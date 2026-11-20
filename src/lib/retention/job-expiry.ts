import { runtimeLimits } from "@/lib/runtime/config";

/**
 * Job-expiry policy for the retention scheduler.
 *
 * The scheduler's job is to terminate work that will *never* finish — not work
 * that is simply slow. The original rule compared `createdAt` against a fixed
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
 * ## The evidence rule
 *
 * Automated expiry requires **CONFIRMED ABSENCE**, never merely "no evidence".
 * Queue liveness is tri-state:
 *
 *   - `present`  — BullMQ still tracks the attempt (lock, or hash entry in any
 *                  state: wait / delayed / active / failed-with-retries).
 *   - `absent`   — Redis was reachable and every configured queue was read
 *                  successfully, and none knows this job.
 *   - `unknown`  — Redis is unconfigured, unreachable, slow, or a read failed
 *                  part-way. **Unknown always prevents expiry.**
 *
 * Collapsing `unknown` into `absent` is what turns a Redis outage into mass
 * termination of live work. That is the failure mode this module exists to
 * make unrepresentable: `JobExpiryFacts.queue` is a required field, and only
 * the explicit `absent` variant is ever actionable.
 *
 * ## Lock authority
 *
 * A BullMQ lock is refreshed by the worker's `lockRenewTime` heartbeat, so lock
 * existence is *current* liveness evidence — not historical. Whether
 * `processedOn` is old is irrelevant: if a lock exists right now, a worker holds
 * the job right now. A lock therefore blocks expiry unconditionally, with no
 * time window applied to it.
 */

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

/**
 * Queue-side liveness evidence for one job.
 *
 * Tri-state by construction: there is no `null` that could be misread as
 * absence, and no optional field that could be forgotten.
 */
export type QueueEvidence =
  | {
      state: "present";
      /** ms epoch of the newest state change BullMQ reports, or `now` if none. */
      lastActivityMs: number;
      /** True when BullMQ holds a live lock: current, authoritative liveness. */
      leased: boolean;
      /** True when an attempt has started and not finished (active, not locked). */
      activelyProcessing: boolean;
    }
  | { state: "absent" }
  | { state: "unknown"; reason: "not_configured" | "unavailable" | "error" };

export type JobLifecycleState = "QUEUED" | "RUNNING" | "RETRYING" | "SUCCEEDED" | "FAILED" | "CANCELLED" | "EXPIRED";

export type JobExpiryFacts = {
  id: string;
  status: JobLifecycleState;
  createdAt: Date;
  startedAt: Date | null;
  updatedAt: Date;
  completedAt: Date | null;
  /**
   * Required: a caller must decide what it knows. Omitting it means "unknown",
   * never "absent" — see {@link evidenceFor}.
   */
  queue: QueueEvidence;
};

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
 * The lower bound is one full attempt (job timeout + storage persist + slack),
 * because a single attempt legitimately leaves the row quiet for its whole
 * duration and would otherwise look abandoned while healthy.
 *
 * The floor is the **previously approved 24h run boundary**: this change must
 * not shorten how long a RUNNING job may live before cleanup is allowed to
 * reclaim it. Widening it further is a policy decision, not a bug fix.
 */
export function runningSilenceMs(): number {
  const oneAttempt = runtimeLimits.jobTimeoutMs + runtimeLimits.storageTimeoutMs + 30 * MINUTE;
  return Math.max(oneAttempt, 24 * HOUR);
}

/** Coerce missing evidence to `unknown`. Absence must be stated explicitly. */
export function evidenceFor(job: Pick<JobExpiryFacts, "queue">): QueueEvidence {
  return job.queue ?? { state: "unknown", reason: "error" };
}

export type JobExpiryReason =
  | "terminal"
  | "running_still_leased"
  | "running_active_attempt"
  | "running_queue_present"
  | "running_recent_activity"
  | "running_queue_unknown"
  | "queued_within_grace"
  | "retrying_within_grace"
  | "retry_queue_present"
  | "retry_queue_unknown";

export type JobExpiryDecision =
  | { expire: true; reason: "abandoned_running" | "stale_queue" }
  | { expire: false; reason: JobExpiryReason };

function lastActivityAt(job: JobExpiryFacts, evidence: QueueEvidence): number {
  const candidates = [job.updatedAt.getTime()];
  if (job.startedAt) candidates.push(job.startedAt.getTime());
  if (evidence.state === "present") candidates.push(evidence.lastActivityMs);
  return Math.max(...candidates);
}

function isTerminal(job: JobExpiryFacts): boolean {
  return Boolean(job.completedAt) || job.status === "SUCCEEDED" || job.status === "FAILED" || job.status === "CANCELLED" || job.status === "EXPIRED";
}

/**
 * Decide whether one job may be terminally expired.
 *
 * Terminal jobs are never touched. Everything else requires confirmed queue
 * absence before the sweep will act.
 */
export function classifyJobExpiry(job: JobExpiryFacts, now: Date): JobExpiryDecision {
  if (isTerminal(job)) return { expire: false, reason: "terminal" };

  const nowMs = now.getTime();
  const evidence = evidenceFor(job);
  const lastActivity = lastActivityAt(job, evidence);

  if (job.status === "RUNNING") {
    if (evidence.state === "present") {
      // A live lock is *current* evidence: it outranks any stale timestamp.
      if (evidence.leased) return { expire: false, reason: "running_still_leased" };
      if (evidence.activelyProcessing) return { expire: false, reason: "running_active_attempt" };
      // Waiting or scheduled for a retry: BullMQ still owns the attempt.
      return { expire: false, reason: "running_queue_present" };
    }
    // Unknown (outage, unconfigured, timeout, partial read): never expire.
    if (evidence.state === "unknown") return { expire: false, reason: "running_queue_unknown" };

    // Confirmed absent from every configured queue.
    if (nowMs - lastActivity <= runningSilenceMs()) return { expire: false, reason: "running_recent_activity" };
    return { expire: true, reason: "abandoned_running" };
  }

  // QUEUED / RETRYING: nothing is processing, so age is meaningful, but still
  // never before the grace window and never without confirmed absence.
  if (nowMs - lastActivity <= abandonedGraceMs()) {
    return { expire: false, reason: job.status === "RETRYING" ? "retrying_within_grace" : "queued_within_grace" };
  }
  if (evidence.state === "unknown") return { expire: false, reason: "retry_queue_unknown" };
  if (evidence.state === "present") {
    // Waiting, or delayed for exponential backoff. A genuinely wedged delayed
    // attempt is repaired by `maxStalledCount`, not by the retention sweep.
    return { expire: false, reason: "retry_queue_present" };
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
    /** Jobs held back solely because queue state could not be established. */
    queueUnknown: number;
  };
  /** Bounds actually applied, so a policy drift is visible in logs. */
  policy: { abandonedGraceMs: number; runningSilenceMs: number };
};

/** Classify a batch without touching any dependency. */
export function planJobExpiry(jobs: readonly JobExpiryFacts[], now: Date): JobExpiryPlan {
  const plan: JobExpiryPlan = {
    expireIds: [],
    counts: { scanned: jobs.length, expired: 0, abandonedRunning: 0, staleQueue: 0, runningStillActive: 0, withinGrace: 0, queueUnknown: 0 },
    policy: { abandonedGraceMs: abandonedGraceMs(), runningSilenceMs: runningSilenceMs() },
  };

  for (const job of jobs) {
    const decision = classifyJobExpiry(job, now);
    if (!decision.expire) {
      switch (decision.reason) {
        case "running_still_leased":
        case "running_active_attempt":
        case "running_queue_present":
        case "running_recent_activity":
          plan.counts.runningStillActive += 1;
          break;
        case "running_queue_unknown":
        case "retry_queue_unknown":
          plan.counts.queueUnknown += 1;
          break;
        case "terminal":
          // Already finished and never actionable; deliberately outside every
          // live bucket so the counts describe only work still in flight.
          break;
        default:
          plan.counts.withinGrace += 1;
      }
      continue;
    }
    plan.expireIds.push(job.id);
    plan.counts.expired += 1;
    if (decision.reason === "abandoned_running") plan.counts.abandonedRunning += 1;
    else plan.counts.staleQueue += 1;
  }

  return plan;
}
