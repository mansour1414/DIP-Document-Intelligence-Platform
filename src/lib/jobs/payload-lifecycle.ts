/**
 * When may a job's encrypted `fill-forms` payload be destroyed?
 *
 * ## The problem this replaces
 *
 * The previous rule was arithmetic: purge when `attemptsMade + 1 >= maxAttempts`.
 * That is wrong in both directions for a real queue:
 *
 *   - **Too late.** BullMQ ends a job on the *first* attempt when the handler
 *     throws an `UnrecoverableError` (`toDocumentQueueError` does exactly that for
 *     an infected output). `attemptsMade` is then 0 while `maxAttempts` is 3, so
 *     the arithmetic says "retryable" and the payload survives a job that will
 *     never run again.
 *   - **Too early.** A retryable failure increments `attemptsMade`, but the retry
 *     has not run yet. If the arithmetic happened to reach the ceiling because a
 *     stalled delivery was counted twice, the payload would be gone when the
 *     remaining attempt started.
 *
 * ## The rule
 *
 * The only thing that actually decides "no further attempt" is the queue itself,
 * and the worker knows it at exactly one point: the `failed` event, where
 * `isUnrecoverableQueueError` plus the attempt counter gives the same verdict
 * BullMQ used to decide whether to retry. So the decision is made *there* — by
 * `classifyAttemptOutcome` — and the pipeline receives it as `terminal`.
 *
 * Every other path is a state transition, and each has its own answer:
 *
 *   | Situation | Payload |
 *   | --- | --- |
 *   | committed SUCCEEDED | purge (after commit) |
 *   | retryable failure | keep |
 *   | unrecoverable failure | purge (first attempt) |
 *   | final attempt exhausted | purge |
 *   | stalled then terminal | purge (worker `failed` path) |
 *   | crash after commit, before purge | purge on the next terminal touch / TTL |
 *   | duplicate delivery of a completed job | purge (idempotent) |
 *   | cancelled or expired | purge |
 *   | enqueue never acknowledged | purge in the creator's catch |
 *
 * ## Why it is a pure function
 *
 * The rules are the kind of thing that must be provable without a queue, a Redis
 * or a database. Everything below is data in, data out.
 */

/** What the worker knows when a queue attempt ends. */
export type AttemptFacts = {
  /** `attemptsMade` as reported by BullMQ for this delivery (attempts started *before* this one). */
  attemptsMade: number;
  /** The job's configured attempt ceiling, as enqueued. */
  maxAttempts: number;
  /** Whether the thrown error is an `UnrecoverableError`. */
  unrecoverable: boolean;
};

export type AttemptOutcome = {
  /** True when the queue will not run this job again. */
  terminal: boolean;
  /** Why — recorded so the decision can be audited rather than inferred. */
  reason: "UNRECOVERABLE" | "ATTEMPTS_EXHAUSTED" | "RETRYABLE";
};

/**
 * Classify one finished attempt exactly as BullMQ does.
 *
 * `attemptsMade` counts attempts already started, so this delivery is number
 * `attemptsMade + 1`; exhaustion is `attemptsMade + 1 >= maxAttempts`.
 */
export function classifyAttemptOutcome(facts: AttemptFacts): AttemptOutcome {
  if (facts.unrecoverable) return { terminal: true, reason: "UNRECOVERABLE" };
  const maxAttempts = Math.max(1, facts.maxAttempts);
  if (facts.attemptsMade + 1 >= maxAttempts) return { terminal: true, reason: "ATTEMPTS_EXHAUSTED" };
  return { terminal: false, reason: "RETRYABLE" };
}

/**
 * Whether a job in this state still needs its payload.
 *
 * A terminal job never will. A live one always might — including `FAILED`, which
 * in this schema means the row was written failed by an attempt while the queue
 * may still hold a retry.
 */
export function payloadRequired(jobStatus: string, queueTerminal: boolean): boolean {
  if (queueTerminal) return false;
  return ["QUEUED", "RUNNING", "RETRYING"].includes(jobStatus);
}

/**
 * The status a job may be moved to when a retry is scheduled.
 *
 * A retry must never revive work that reached a terminal state by another route:
 * a cancellation or expiry that raced the claim wins, and a job that already
 * published output stays published. Returning `undefined` means "leave the row
 * alone", which is what the worker does then.
 */
export function retryTransitionTarget(jobStatus: string): "RETRYING" | undefined {
  return ["QUEUED", "RUNNING", "RETRYING", "FAILED"].includes(jobStatus) ? "RETRYING" : undefined;
}
