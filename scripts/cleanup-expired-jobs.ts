import { db } from "@/lib/db";
import { logger } from "@/lib/logging";
import { runRetentionCleanup } from "@/lib/retention/service";
import { configuredRetentionScope, missingRetentionCredentials, parseRetentionApply } from "@/lib/retention/safety";
import {
  abandonedGraceMs,
  planJobExpiry,
  runningSilenceMs,
  type JobExpiryFacts,
  type JobExpiryPlan,
  type JobLifecycleState,
} from "@/lib/retention/job-expiry";
import { createQueueActivityLookup, emptyQueueActivityLookup, type QueueActivityLookup } from "@/lib/retention/queue-activity";
import { AI_JOB_QUEUE_NAME, getQueueConnection, JOB_QUEUE_NAME } from "@/lib/queue";

/**
 * Legacy export retained for compatibility.
 *
 * It is no longer the single expiry window. RUNNING work is judged by activity
 * and lease, not age; `abandonedGraceMs()` is the effective bound for
 * QUEUED/RETRYING jobs.
 */
export const EXPIRY_CUTOFF_MS = 24 * 60 * 60 * 1000;

/** Non-terminal states the sweep may consider. Terminal states are never read. */
const CANDIDATE_STATUSES = ["QUEUED", "RETRYING"] as const;

type CandidateRow = {
  id: string;
  status: JobLifecycleState;
  createdAt: Date;
  startedAt: Date | null;
  updatedAt: Date;
  completedAt: Date | null;
};

/**
 * Load the facts the expiry policy needs.
 *
 * QUEUED/RETRYING rows are bounded by the grace window. RUNNING rows are only
 * candidates once they have been silent past the longest plausible attempt, so
 * the query prefilter cannot exclude a job the policy would have expired.
 */
async function loadCandidates(now: Date): Promise<CandidateRow[]> {
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

/** Default lookup: real BullMQ keys over the shared Redis connection. */
export function redisQueueActivity(nowMs: () => number): (queueName: string) => QueueActivityLookup {
  try {
    const redis = getQueueConnection();
    return (queueName) => createQueueActivityLookup({ redis, queueName, now: nowMs });
  } catch {
    // Without Redis the sweep still runs, but every job looks queue-unknown, so
    // the database silence window alone has to elapse before expiry.
    return () => emptyQueueActivityLookup;
  }
}

/**
 * Attach queue liveness evidence, trying the document queue then the AI queue.
 * A job known to neither is left with `queue: null`.
 */
async function withQueueActivity(
  jobs: CandidateRow[],
  lookupFor: (queueName: string) => QueueActivityLookup,
): Promise<JobExpiryFacts[]> {
  const ids = jobs.map((job) => job.id);
  const documentQueue = await lookupFor(JOB_QUEUE_NAME).lookup(ids);
  const remaining = ids.filter((id) => !documentQueue.has(id));
  const aiQueue = remaining.length ? await lookupFor(AI_JOB_QUEUE_NAME).lookup(remaining) : new Map();
  return jobs.map((job) => ({ ...job, queue: documentQueue.get(job.id) ?? aiQueue.get(job.id) ?? null }));
}

export type ExpireStalledJobsOptions = {
  now?: Date;
  /**
   * `"apply"` performs the expiry update; `"plan"` is strictly read-only.
   */
  mode?: "apply" | "plan";
  /** Test seam: replaces the Redis-backed queue evidence provider. */
  queueActivity?: (queueName: string) => QueueActivityLookup;
};

export type ExpireStalledJobsResult = { expired: number; plan: JobExpiryPlan };

function expiryLogContext(plan: JobExpiryPlan, mode: "apply" | "plan") {
  return {
    scanned: plan.counts.scanned,
    expired: plan.counts.expired,
    abandoned_running: plan.counts.abandonedRunning,
    stale_queue: plan.counts.staleQueue,
    active_running: plan.counts.runningStillActive,
    within_grace: plan.counts.withinGrace,
    abandoned_grace_ms: plan.policy.abandonedGraceMs,
    running_silence_ms: plan.policy.runningSilenceMs,
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
  const lookupFor = options.queueActivity ?? redisQueueActivity(() => now.getTime());
  const candidates = await loadCandidates(now);
  const plan = planJobExpiry(await withQueueActivity(candidates, lookupFor), now);
  logger.info("jobs.expiry_planned", expiryLogContext(plan, mode));
  return { expired: 0, plan };
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
  const { plan } = await planStalledJobExpiry({ ...options, now, mode });
  if (mode !== "apply" || plan.expireIds.length === 0) return 0;

  // The update repeats the status guard so a job that reached a terminal state
  // between planning and writing is never overwritten.
  const result = await db.job.updateMany({
    where: { id: { in: plan.expireIds }, status: { in: ["QUEUED", "RETRYING", "RUNNING"] } },
    data: { status: "EXPIRED", errorCode: "JOB_EXPIRED", completedAt: now },
  });
  logger.info("jobs.expired_cleanup", {
    count: result.count,
    abandoned_running: plan.counts.abandonedRunning,
    stale_queue: plan.counts.staleQueue,
  });
  return result.count;
}

/**
 * Scheduler entrypoint.
 *
 * - Missing credentials fail closed, before Prisma or the object store is used,
 *   and the message lists variable NAMES only.
 * - RETENTION_APPLY=1 is required for apply; anything else is a read-only
 *   dry-run that reports candidates and writes nothing.
 */
async function main() {
  const missing = missingRetentionCredentials(process.env);
  if (missing.length > 0) throw new Error(`RETENTION_CONFIGURATION_MISSING:${missing.join(",")}`);

  const apply = parseRetentionApply(process.env.RETENTION_APPLY);
  const scope = configuredRetentionScope(process.env);
  const expiredJobs = apply
    ? await expireStalledJobs({ mode: "apply" })
    : (await planStalledJobExpiry({ mode: "plan" })).plan.counts.expired;
  logger.info("retention.mode", { apply, bucket_configured: true });

  const result = await runRetentionCleanup({ dryRun: !apply, scope });
  logger.info("retention.scheduler_result", {
    dry_run: result.dryRun,
    scanned: result.scanned,
    candidate_documents: result.candidateDocuments,
    candidate_files: result.candidateFiles,
    deleted_objects: result.deletedObjects,
    deleted_documents: result.deletedDocuments,
    failures: result.failures,
    blocked_objects: result.blockedObjects,
    expired_jobs: expiredJobs,
  });
}

main().catch((error) => {
  // Classify without ever echoing a credential value.
  const prismaCode = (error as { code?: unknown })?.code;
  const message = error instanceof Error ? error.message : "";
  const configurationMissing = message.startsWith("RETENTION_CONFIGURATION_MISSING");
  const safeCode = configurationMissing
    ? "RETENTION_CONFIGURATION_MISSING"
    : typeof prismaCode === "string" && /^P\d{4}$/.test(prismaCode) ? prismaCode : error instanceof Error ? error.name : "UNKNOWN";
  logger.error("retention.scheduler_failed", { error_code: safeCode });
  const missing = configurationMissing ? message.slice("RETENTION_CONFIGURATION_MISSING:".length).split(",") : undefined;
  if (missing) logger.error("retention.missing_configuration", { missing_variables: missing.join(",") });
  process.exitCode = 1;
}).finally(() => db.$disconnect());
