import { runtimeLimits } from "@/lib/runtime/config";

/**
 * Job-expiry policy for the retention scheduler.
 *
 * The scheduler's job is to terminate work that will *never* finish — not work
 * that is simply slow. The previous rule compared `createdAt` against a fixed
 * 24h window for every non-terminal state, which meant a legitimate long-running
 * RUNNING job could be marked EXPIRED while its worker was still processing.
 *
 * That is unsafe for three independent reasons:
 *
 *   1. Transient silence is not abandonment. `startedAt` is preserved across
 *      retries (`startedAt: job.startedAt ?? new Date()`), so a job that has been
 *      retried for hours can still be making progress on its newest attempt.
 *   2. `updatedAt` may be much older than the current attempt. The pipeline only
 *      touches the row at attempt boundaries (claim and commit), so a long
 *      single attempt legitimately leaves the row quiet for its whole duration.
 *   3. A RUNNING row with a fresh lease is demonstrably alive.
 *
 * The rule below therefore requires BOTH a stale activity timestamp AND an
 * absence of any live lease before a RUNNING job may be expired. It only ever
 * uses timestamps the application already writes, so no schema change and no
 * migration is needed.
 */

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

/**
 * Queue-side evidence that a RUNNING job is alive.
 *
 * BullMQ removes a completed/failed job after `removeOnComplete`/`removeOnFail`
 * (24h), so an attempt still present in the queue is running or retryable. The
 * only field this produces is a Redis-local timestamp, which costs no schema.
 */
export type QueueActivity = {
  /** ms epoch of the newest state change BullMQ reports for the attempt. */
  lastActivityMs: number;
  /** True when BullMQ has a live lock holder for this attempt. */
  leased: boolean;
  /** True when the attempt is in `active` (not wait/delayed/failed). */
  activelyProcessing: boolean;
};

export type JobLifecycleState = "QUEUED" | "RUNNING" | "RETRYING" | "SUCCEEDED" | "FAILED" | "CANCELLED" | "EXPIRED";

export type JobExpiryFacts = {
  id: string;
  status: JobLifecycleState;
  createdAt: Date;
  startedAt: Date | null;
  updatedAt: Date;
  completedAt: Date | null;
  /** Present when the queue still knows this attempt. */
  queue?: QueueActivity | null;
};

export type JobExpiryDecision =
  | { expire: true; reason: "abandoned_running" | "stale_queue" }
  | { expire: false; reason: "terminal" | "queued_within_grace" | "running_still_leased" | "running_recent_activity" | "retrying_within_grace" | "retrying_active_queue" | "queue_present" };

/**
 * How long a QUEUED/RETRYING job may sit before it counts as abandoned.
 *
 * Defaults to the existing 24h grace so queue behaviour is unchanged; the bound
 * mirrors `JOB_TIMEOUT_MS` so a fleet configured for slower processing also gets
 * a proportional grace window.
 */
export function abandonedGraceMs(): number {
  return Math.max(runtimeLimits.jobTimeoutMs * 4, 24 * HOUR);
}

/**
 * How long a RUNNING job must be silent before it may be expired.
 *
 * Deliberately larger than the longest possible single attempt (JOB_TIMEOUT_MS
 * plus storage persist), because the row is legitimately quiet for the whole
 * duration of one attempt.
 */
export function runningSilenceMs(): number {
  return runtimeLimits.jobTimeoutMs + runtimeLimits.storageTimeoutMs + 30 * MINUTE;
}

/** A BullMQ lock is held for at most `lockDuration` (capped at 10 minutes). */
const QUEUE_LEASE_HORIZON_MS = 10 * MINUTE;

function lastActivityAt(job: JobExpiryFacts): number {
  const candidates = [job.updatedAt.getTime()];
  if (job.startedAt) candidates.push(job.startedAt.getTime());
  if (job.queue) candidates.push(job.queue.lastActivityMs);
  return Math.max(...candidates);
}

/**
 * Decide whether one job may be terminally expired.
 *
 * Terminal jobs are never touched. A RUNNING job is only expirable when it has
 * no live queue lease, is not actively processing, and has been silent for
 * longer than the longest plausible attempt.
 */
export function classifyJobExpiry(job: JobExpiryFacts, now: Date): JobExpiryDecision {
  if (job.completedAt || job.status === "SUCCEEDED" || job.status === "FAILED" || job.status === "CANCELLED" || job.status === "EXPIRED") {
    return { expire: false, reason: "terminal" };
  }

  const nowMs = now.getTime();
  const lastActivity = lastActivityAt(job);

  if (job.status === "RUNNING") {
    // A live lease is authoritative: the worker holds a heartbeat and will
    // either commit or throw. Never expire underneath it.
    if (job.queue?.leased && nowMs - job.queue.lastActivityMs <= QUEUE_LEASE_HORIZON_MS) {
      return { expire: false, reason: "running_still_leased" };
    }
    if (job.queue?.activelyProcessing && nowMs - job.queue.lastActivityMs <= QUEUE_LEASE_HORIZON_MS) {
      return { expire: false, reason: "running_still_leased" };
    }
    if (nowMs - lastActivity <= runningSilenceMs()) {
      return { expire: false, reason: "running_recent_activity" };
    }
    return { expire: true, reason: "abandoned_running" };
  }

  // QUEUED / RETRYING: nothing is processing, so age alone is meaningful, but
  // still never before the grace window and never while the queue still tracks
  // the attempt (waiting, delayed for backoff, or actively retrying).
  if (nowMs - lastActivity <= abandonedGraceMs()) {
    return { expire: false, reason: job.status === "RETRYING" ? "retrying_within_grace" : "queued_within_grace" };
  }
  if (job.queue) {
    // The attempt still exists in BullMQ — waiting, delayed for backoff, or
    // actively retrying — so it is not abandoned. A genuinely stuck delayed
    // attempt is repaired by `maxStalledCount`, not by the retention sweep.
    return { expire: false, reason: "retrying_active_queue" };
  }
  // Nothing held this job for more than a full grace window, and BullMQ no
  // longer tracks the attempt: it will never run again.
  return { expire: true, reason: "stale_queue" };
}

export type JobExpiryPlan = {
  /** Ids eligible for expiry. Order is stable for deterministic tests. */
  expireIds: string[];
  /** Aggregate counts only: no tool ids, filenames or tenant identifiers. */
  counts: {
    scanned: number;
    expired: number;
    abandonedRunning: number;
    staleQueue: number;
    runningStillActive: number;
    withinGrace: number;
  };
  /** Bounds actually applied, so a policy drift is visible in logs. */
  policy: { abandonedGraceMs: number; runningSilenceMs: number };
};

/** Classify a batch without touching any dependency. */
export function planJobExpiry(jobs: readonly JobExpiryFacts[], now: Date): JobExpiryPlan {
  const plan: JobExpiryPlan = {
    expireIds: [],
    counts: { scanned: jobs.length, expired: 0, abandonedRunning: 0, staleQueue: 0, runningStillActive: 0, withinGrace: 0 },
    policy: { abandonedGraceMs: abandonedGraceMs(), runningSilenceMs: runningSilenceMs() },
  };

  for (const job of jobs) {
    const decision = classifyJobExpiry(job, now);
    if (!decision.expire) {
      if (decision.reason === "running_still_leased" || decision.reason === "running_recent_activity") plan.counts.runningStillActive += 1;
      else if (decision.reason === "queued_within_grace" || decision.reason === "retrying_within_grace" || decision.reason === "retrying_active_queue") plan.counts.withinGrace += 1;
      continue;
    }
    plan.expireIds.push(job.id);
    plan.counts.expired += 1;
    if (decision.reason === "abandoned_running") plan.counts.abandonedRunning += 1;
    else plan.counts.staleQueue += 1;
  }

  return plan;
}
