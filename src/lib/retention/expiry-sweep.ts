import { logger } from "@/lib/logging";
import {
  abandonedGraceMs,
  planJobExpiry,
  runningSilenceMs,
  type JobExpiryFacts,
  type JobExpiryPlan,
  type JobLifecycleState,
  type QueueEvidence,
} from "./job-expiry";
import { createQueueActivityLookup, resolveEvidence, unknownEvidence, type QueueReadResult } from "./queue-activity";
import { openRetentionRedis, type RetentionRedisHandle } from "./queue-connection";
import { applyExpiryPlan } from "./expiry-write";
import { AI_JOB_QUEUE_NAME, JOB_QUEUE_NAME } from "@/lib/queue";

/**
 * Job-expiry sweep: planning, queue evidence and the guarded apply write.
 *
 * Extracted from `scripts/cleanup-expired-jobs.ts` so the dry-run entrypoint can
 * plan an expiry sweep without importing a script that executes itself. The
 * apply write stays here and is reachable only through `expireStalledJobs()` in
 * `"apply"` mode; `planStalledJobExpiry()` is read-only.
 */

/**
 * Legacy export retained for compatibility.
 *
 * It is no longer the single expiry window. RUNNING work is judged by queue
 * evidence and a 24h-minimum silence window; `abandonedGraceMs()` is the
 * effective bound for QUEUED/RETRYING jobs.
 */
export const EXPIRY_CUTOFF_MS = 24 * 60 * 60 * 1000;

/** Non-terminal states the sweep may consider. Terminal states are never read. */
const CANDIDATE_STATUSES = ["QUEUED", "RETRYING"] as const;

export type CandidateRow = {
  id: string;
  status: JobLifecycleState;
  createdAt: Date;
  startedAt: Date | null;
  updatedAt: Date;
  completedAt: Date | null;
};

/** The queues this deployment actually uses, in read order. */
const QUEUE_NAMES = [JOB_QUEUE_NAME, AI_JOB_QUEUE_NAME] as const;

/**
 * Load the facts the expiry policy needs.
 *
 * QUEUED/RETRYING rows are bounded by the grace window. RUNNING rows are only
 * candidates once they have been silent past the longest plausible attempt, so
 * the query prefilter cannot exclude a job the policy would have expired.
 */
async function loadCandidates(now: Date): Promise<CandidateRow[]> {
  // Lazy import: see `repository.ts`. A dry-run must not construct a client
  // before its configuration has been validated.
  const { db } = await import("@/lib/db");
  const silenceFloor = new Date(now.getTime() - runningSilenceMs());
  const graceFloor = new Date(now.getTime() - abandonedGraceMs());

  const [queueLike, running] = await Promise.all([
    db.job.findMany({
      where: { status: { in: [...CANDIDATE_STATUSES] }, updatedAt: { lt: graceFloor } },
      select: { id: true, status: true, createdAt: true, startedAt: true, updatedAt: true, completedAt: true },
    }),
    db.job.findMany({
      where: {
        status: "RUNNING",
        // `startedAt` is preserved across retries, so this is a coarse prefilter;
        // the policy still requires a long silence before expiry.
        OR: [
          { startedAt: { lt: silenceFloor } },
          { startedAt: null, updatedAt: { lt: silenceFloor } },
        ],
      },
      select: { id: true, status: true, createdAt: true, startedAt: true, updatedAt: true, completedAt: true },
    }),
  ]);

  return [...queueLike, ...running];
}

export type QueueEvidenceProvider = {
  /**
   * Set when the provider cannot read at all (e.g. `REDIS_URL` is not
   * configured). Every job is then `unknown`, never `absent`.
   */
  unavailable?: Extract<QueueEvidence, { state: "unknown" }>["reason"];
  /** Reads every configured queue, returning one result per queue. */
  read(jobIds: readonly string[]): Promise<QueueReadResult[]>;
  /** Releases any connection this provider owns. Must be idempotent. */
  close(): Promise<void>;
  /** Optional aggregate counters, safe to log (no hosts, no credentials). */
  diagnostics?(): { queues_expected: number; queues_read: number; failed_reads: number };
};

/**
 * Provider backed by a bounded, explicitly-configured Redis connection.
 *
 * When `REDIS_URL` is absent the sweep must not invent a localhost endpoint
 * (see `queue-connection.ts`): every job becomes `unknown`, and unknown never
 * permits expiry.
 */
export function redisEvidenceProvider(): QueueEvidenceProvider {
  const handle: RetentionRedisHandle = openRetentionRedis();
  if (!handle.connection) {
    return {
      unavailable: "not_configured",
      async read() {
        return [];
      },
      close: handle.close,
      diagnostics: () => ({ queues_expected: QUEUE_NAMES.length, queues_read: 0, failed_reads: 0 }),
    };
  }
  const connection = handle.connection;
  const nowMs = () => Date.now();
  // Diagnostic only: distinguishes "Redis unreachable" from "every job is
  // genuinely tracked". Logged as a count, never as a connection string.
  let lastReadFailures = 0;
  const lookups = QUEUE_NAMES.map((queueName) => createQueueActivityLookup({ redis: connection, queueName, now: nowMs }));
  return {
    async read(jobIds) {
      // Sequential reads keep load on the worker's Redis predictable.
      const results: QueueReadResult[] = [];
      for (const lookup of lookups) results.push(await lookup.read(jobIds));
      lastReadFailures = results.filter((result) => !result.ok).length;
      return results;
    },
    close: handle.close,
    diagnostics: () => ({ queues_expected: QUEUE_NAMES.length, queues_read: lookups.length, failed_reads: lastReadFailures }),
  };
}

/**
 * Attach queue evidence to every candidate.
 *
 * Presence anywhere wins; otherwise any incomplete read poisons the batch to
 * `unknown`. Only a fully successful, fully empty read set may conclude absence.
 */
async function withQueueEvidence(
  jobs: CandidateRow[],
  provider: QueueEvidenceProvider,
  unavailableReason: Extract<QueueEvidence, { state: "unknown" }>["reason"] | null = null,
): Promise<JobExpiryFacts[]> {
  if (jobs.length === 0) return [];
  if (unavailableReason) return jobs.map((job) => ({ ...job, queue: unknownEvidence(unavailableReason) }));

  let reads: QueueReadResult[];
  try {
    reads = await provider.read(jobs.map((job) => job.id));
  } catch {
    // A provider-level failure is UNKNOWN for the whole batch, never absence.
    return jobs.map((job) => ({ ...job, queue: unknownEvidence("error") }));
  }
  // Absence requires a complete read of EVERY configured queue. A short result
  // set means a queue went unread, and an unread queue might have held the job.
  return jobs.map((job) => ({ ...job, queue: resolveEvidence(job.id, reads, QUEUE_NAMES.length) }));
}

/**
 * Aggregate, content-free queue-evidence diagnostics.
 *
 * `redis_configured` is false only when nothing could be read *because no queue
 * endpoint was supplied*; an unreachable-but-configured Redis reports
 * `redis_configured: true` with `failed_reads > 0`, which is a materially
 * different incident.
 */
export type QueueDiagnostics = {
  redis_configured: boolean;
  unavailable: "not_configured" | "unavailable" | "error" | null;
  queues_expected: number;
  queues_read: number;
  failed_reads: number;
  candidates_scanned: number;
};

export type ExpireStalledJobsOptions = {
  now?: Date;
  /**
   * `"apply"` performs the expiry update; `"plan"` is strictly read-only.
   */
  mode?: "apply" | "plan";
  /** Test seam: replaces the Redis-backed queue evidence provider. */
  evidence?: QueueEvidenceProvider;
  /** Test seam: forces the "queue is unusable" path without touching Redis. */
  queueUnavailable?: Extract<QueueEvidence, { state: "unknown" }>["reason"] | null;
  /**
   * Test seam: replaces the PostgreSQL candidate read. Never used to widen what
   * the policy may expire — the same rows are classified either way.
   */
  loadCandidates?: (now: Date) => Promise<CandidateRow[]>;
};

export type ExpireStalledJobsResult = { expired: number; plan: JobExpiryPlan; queue: QueueDiagnostics };

function expiryLogContext(
  plan: JobExpiryPlan,
  mode: "apply" | "plan",
  diagnostics?: { queues_expected: number; queues_read: number; failed_reads: number },
) {
  return {
    scanned: plan.counts.scanned,
    expired: plan.counts.expired,
    abandoned_running: plan.counts.abandonedRunning,
    stale_queue: plan.counts.staleQueue,
    active_running: plan.counts.runningStillActive,
    within_grace: plan.counts.withinGrace,
    // Visible on every sweep: a Redis outage shows up as a non-zero count here
    // rather than silently suppressing cleanup.
    queue_unknown: plan.counts.queueUnknown,
    abandoned_grace_ms: plan.policy.abandonedGraceMs,
    running_silence_ms: plan.policy.runningSilenceMs,
    // Diagnostics: a queue that could not be read shows up here rather than as
    // a silent "nothing expired". Counts only — never hosts or credentials.
    ...(diagnostics ?? {}),
    mode,
  };
}

/**
 * Plan the expiry sweep without mutating anything.
 *
 * Read-only: it reads PostgreSQL and Redis only, which is what lets a dry-run
 * report job-expiry candidates without terminating live work.
 */
export async function planStalledJobExpiry(options: ExpireStalledJobsOptions = {}): Promise<ExpireStalledJobsResult> {
  const now = options.now ?? new Date();
  const mode = options.mode ?? "plan";
  const ownsProvider = !options.evidence;
  const provider = options.evidence ?? redisEvidenceProvider();
  try {
    const candidates = await (options.loadCandidates ?? loadCandidates)(now);
    const unavailable = options.queueUnavailable ?? provider.unavailable ?? null;
    const facts = await withQueueEvidence(candidates, provider, unavailable);
    const plan = planJobExpiry(facts, now);
    const counts = provider.diagnostics?.() ?? { queues_expected: QUEUE_NAMES.length, queues_read: 0, failed_reads: 0 };
    const queue: QueueDiagnostics = {
      redis_configured: unavailable === null,
      unavailable,
      queues_expected: counts.queues_expected,
      queues_read: counts.queues_read,
      failed_reads: counts.failed_reads,
      candidates_scanned: plan.counts.scanned,
    };
    logger.info("jobs.expiry_planned", expiryLogContext(plan, mode, counts));
    return { expired: 0, plan, queue };
  } finally {
    // Always release the connection: a one-shot scheduler process must not leak
    // a Redis socket when planning throws.
    if (ownsProvider) await provider.close().catch(() => undefined);
  }
}

/**
 * Terminally expire jobs that will never finish.
 *
 * Only apply mode mutates. A dry-run must be strictly read-only and must not
 * turn live work into an EXPIRED row.
 */
export async function expireStalledJobs(options: ExpireStalledJobsOptions = {}): Promise<number> {
  const mode = options.mode ?? "apply";
  const now = options.now ?? new Date();
  // Captured BEFORE planning: the write is only allowed to touch rows that were
  // already quiet when the sweep began. See `expiry-write.ts` for why the plain
  // status guard is not enough.
  const sweepStartedAt = now;
  const { plan } = await planStalledJobExpiry({ ...options, now, mode });
  if (mode !== "apply" || plan.expireIds.length === 0) return 0;

  // Apply only: the client is resolved here, never on the planning path.
  const { db } = await import("@/lib/db");
  const count = await applyExpiryPlan(
    { updateMany: (args) => db.job.updateMany(args as Parameters<typeof db.job.updateMany>[0]) },
    { expireIds: plan.expireIds, sweepStartedAt, completedAt: now },
  );
  logger.info("jobs.expired_cleanup", {
    count,
    planned: plan.expireIds.length,
    // A shortfall means the sweep lost the race to a legitimate state change,
    // which is the desired outcome — surface it rather than hiding it.
    skipped_changed_since_sweep: plan.expireIds.length - count,
    abandoned_running: plan.counts.abandonedRunning,
    stale_queue: plan.counts.staleQueue,
  });
  return count;
}
