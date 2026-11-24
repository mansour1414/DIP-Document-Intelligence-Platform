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

/**
 * What the queue itself tells us about a finished attempt.
 *
 * ## The counter is not the same on both sides of the failure
 *
 * BullMQ 6.3.4 increments `attemptsMade` **inside** `Job.moveToFailed`
 * (`dist/esm/classes/job.js:510`), and the worker emits `failed`
 * (`dist/esm/classes/worker.js:651`) *after* that call returns. The retry decision
 * itself is taken earlier still, in `shouldRetryJob` (`job.js:446`):
 *
 *     shouldRetry = attemptsMade + 1 < opts.attempts && !(err instanceof UnrecoverableError)
 *
 * So the counter means two different things at the two moments this module is
 * consulted:
 *
 *   | moment | `attemptsMade` |
 *   | --- | --- |
 *   | processor entry (`Worker` handler) | attempts *before* this one — 0 on the first delivery |
 *   | `failed` event | attempts *including* this one — 1 after the first failure |
 *
 * An earlier version applied the `+1` form of the predicate in the `failed`
 * handler, i.e. added one to an already-incremented counter. On three configured
 * attempts that mis-classified **attempt 2 as terminal** and purged the payload
 * while a retry was still scheduled. The two entry points are now separate and
 * each takes the counter in the frame it is actually delivered in.
 */
export type AttemptFacts = {
  /** `attemptsMade` exactly as delivered at this call site — never re-adjusted. */
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
 * Classify a failure as the queue decides it, from the **`failed` event**.
 *
 * Here `attemptsMade` has already been incremented, so this attempt is number
 * `attemptsMade` and exhaustion is `attemptsMade >= maxAttempts`. This mirrors
 * `shouldRetryJob`'s negation exactly.
 */
export function classifyFailedEvent(facts: AttemptFacts): AttemptOutcome {
  if (facts.unrecoverable) return { terminal: true, reason: "UNRECOVERABLE" };
  const maxAttempts = Math.max(1, facts.maxAttempts);
  if (facts.attemptsMade >= maxAttempts) return { terminal: true, reason: "ATTEMPTS_EXHAUSTED" };
  return { terminal: false, reason: "RETRYABLE" };
}

/**
 * Classify from the **processor** side, where `attemptsMade` has *not* yet been
 * incremented for the attempt that is about to run.
 *
 * Kept because the pipeline needs the same answer while handling its own failure,
 * before the queue has spoken. It is deliberately named apart from
 * `classifyFailedEvent` so the two frames cannot be confused again.
 */
export function classifyAtProcessorEntry(facts: AttemptFacts): AttemptOutcome {
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
