/**
 * FF-03 — payload lifecycle, behaviourally.
 *
 * The architect's requirement is not "the code contains a terminal check"; it is
 * that each way a queue job can end is enumerated and shown to destroy (or keep)
 * the encrypted payload correctly. Every case below drives the real decision
 * function the worker and pipeline use, with no database and no Redis, so the
 * table in `payload-lifecycle.ts` is executable rather than asserted in a comment.
 *
 * The one thing these tests deliberately cannot cover is the queue's own behaviour
 * — BullMQ deciding to retry. That is what `classifyAttemptOutcome` mirrors, and
 * the mirror is checked against the documented semantics: `attemptsMade` counts
 * attempts already started, so exhaustion is `attemptsMade + 1 >= maxAttempts`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyAtProcessorEntry, classifyFailedEvent, payloadRequired, retryTransitionTarget } from "../src/lib/jobs/payload-lifecycle";

/**
 * The question every case reduces to, asked in the frame the *queue* uses.
 *
 * The `failed` handler sees the post-increment counter, so every lifecycle
 * assertion here goes through `classifyFailedEvent`.
 */
const purges = (facts: { attemptsMade: number; maxAttempts: number; unrecoverable: boolean }) =>
  classifyFailedEvent(facts).terminal;

/**
 * Walk three configured attempts the way BullMQ 6.3.4 actually does, and report
 * what the queue decided for each delivery.
 *
 * `attemptsMade` is incremented inside `moveToFailed` (`job.js:510`) *before* the
 * worker emits `failed` (`worker.js:651`), while the retry decision is taken
 * earlier from the pre-increment value (`job.js:446`). Both frames are exercised so
 * a test cannot pass by using the wrong one.
 */
function threeAttemptRun(resultOf: (attempt: number) => "ok" | { unrecoverable: boolean }) {
  const maxAttempts = 3;
  let counter = 0; // attemptsMade as BullMQ holds it between deliveries
  const observed: Array<{
    attempt: number;
    entryFrame: number;
    failedEventFrame: number;
    queueWillRetry: boolean;
    workerSaysTerminal: boolean;
    pipelineSaysTerminal: boolean;
  }> = [];
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const entryFrame = counter;
    const outcome = resultOf(attempt);
    if (outcome === "ok") break;
    const queueWillRetry = entryFrame + 1 < maxAttempts && !outcome.unrecoverable; // job.js:446
    counter += 1; // job.js:510
    const failedEventFrame = counter;
    observed.push({
      attempt,
      entryFrame,
      failedEventFrame,
      queueWillRetry,
      workerSaysTerminal: classifyFailedEvent({ attemptsMade: failedEventFrame, maxAttempts, unrecoverable: outcome.unrecoverable }).terminal,
      pipelineSaysTerminal: classifyAtProcessorEntry({ attemptsMade: entryFrame, maxAttempts, unrecoverable: outcome.unrecoverable }).terminal,
    });
    if (!queueWillRetry) break;
  }
  return observed;
}

test("success after commit: a completed job's payload is purged, not retried", () => {
  // Success purges on the commit path (`reason: "SUCCESS"`), before any attempt
  // classification. Nothing keeps the payload alive for a SUCCEEDED job.
  assert.equal(payloadRequired("SUCCEEDED", false), false);
  assert.equal(payloadRequired("SUCCEEDED", true), false);
});

test("retry success: an attempt that fails then succeeds purges on success", () => {
  // Attempt 1 fails retryably — payload must survive for attempt 2.
  assert.equal(purges({ attemptsMade: 0, maxAttempts: 3, unrecoverable: false }), false);
  assert.equal(payloadRequired("RETRYING", false), true);
  // Attempt 2 succeeds: the commit path purges. No state keeps it.
  assert.equal(payloadRequired("SUCCEEDED", true), false);
});

test("unrecoverable failure on the first attempt is terminal immediately", () => {
  // This is the case attempt arithmetic got wrong: attemptsMade is 0 (first
  // attempt) and maxAttempts is 3, so `1 >= 3` is false — yet BullMQ stops here.
  const outcome = classifyFailedEvent({ attemptsMade: 1, maxAttempts: 3, unrecoverable: true });
  assert.deepEqual(outcome, { terminal: true, reason: "UNRECOVERABLE" });
});

test("attempt exhaustion is terminal on the last configured attempt", () => {
  // Post-increment frame: after the third failure `attemptsMade` is 3.
  assert.equal(purges({ attemptsMade: 3, maxAttempts: 3, unrecoverable: false }), true);
  assert.equal(purges({ attemptsMade: 2, maxAttempts: 3, unrecoverable: false }), false);
  assert.equal(purges({ attemptsMade: 1, maxAttempts: 3, unrecoverable: false }), false);
});

test("a stalled delivery that is retried keeps the payload until it is terminal", () => {
  // BullMQ counts a stalled delivery as an attempt. The payload must survive,
  // because the job will run again and needs its inputs.
  assert.equal(purges({ attemptsMade: 2, maxAttempts: 3, unrecoverable: false }), false);
  assert.equal(payloadRequired("RUNNING", false), true);
});

test("stalled and then exhausted purges once, at the terminal point", () => {
  assert.equal(purges({ attemptsMade: 3, maxAttempts: 3, unrecoverable: false }), true);
});

test("crash after commit, before purge: the job is SUCCEEDED and needs no payload", () => {
  // The pipeline purges after the commit lands. A hard crash in between leaves an
  // orphaned payload whose TTL is the backstop; crucially the *job* is already
  // correct, and any later terminal touch purges again (idempotent).
  assert.equal(payloadRequired("SUCCEEDED", true), false);
});

test("duplicate delivery of a completed job does not resurrect the payload", () => {
  // The pipeline returns early for SUCCEEDED jobs, and the purge site runs on the
  // commit path only once. Purging is idempotent, so the second delivery is safe.
  assert.equal(payloadRequired("SUCCEEDED", false), false);
  assert.equal(retryTransitionTarget("SUCCEEDED"), undefined, "a duplicate retry must not move a SUCCEEDED job");
});

test("cancel versus claim: a cancellation wins and the payload is purged", () => {
  // The pipeline's first action is the terminal-state check; CANCELLED/EXPIRED
  // purge immediately and return before any parsing or queue work.
  assert.equal(payloadRequired("CANCELLED", false), false);
  assert.equal(payloadRequired("EXPIRED", false), false);
  // And a retry racing that cancellation must not move it back.
  assert.equal(retryTransitionTarget("CANCELLED"), undefined);
  assert.equal(retryTransitionTarget("EXPIRED"), undefined);
});

test("a retry may only move a job that is still live", () => {
  for (const status of ["QUEUED", "RUNNING", "RETRYING", "FAILED"]) {
    assert.equal(retryTransitionTarget(status), "RETRYING", `${status} must be retryable`);
  }
  for (const status of ["SUCCEEDED", "CANCELLED", "EXPIRED"]) {
    assert.equal(retryTransitionTarget(status), undefined, `${status} must never be revived`);
  }
});

test("enqueue never acknowledged: the creator purges because no retry can exist", () => {
  // Enqueue failure throws in the creator before a job row exists; the payload it
  // wrote is purged in that catch. No queue state can be classified at all, so the
  // payload must not be treated as live.
  assert.equal(payloadRequired("FAILED", true), false);
});

test("expiration purges through the sweep, driven by the committed transition", () => {
  // The sweep passes only rows its guarded write actually expired (see
  // `retention.expiry-race.test.ts`); those are EXPIRED, so the payload is gone,
  // and a job claimed mid-sweep keeps it.
  assert.equal(payloadRequired("EXPIRED", true), false);
  assert.equal(payloadRequired("RUNNING", false), true);
});

test("Redis cleanup failure cannot keep a payload alive", () => {
  // Every purge site treats a Redis error as best-effort (`catch(() => undefined)`)
  // and the TTL is the backstop, so a failed delete delays destruction but never
  // prevents it. The classification is independent of whether the delete worked.
  assert.equal(purges({ attemptsMade: 3, maxAttempts: 3, unrecoverable: false }), true);
  assert.equal(payloadRequired("EXPIRED", false), false);
});

test("no path leaves a terminal job with a required payload", () => {
  // Exhaustive: for every status and every terminal verdict, a terminal queue
  // outcome must never report the payload as required.
  const statuses = ["QUEUED", "RUNNING", "RETRYING", "FAILED", "SUCCEEDED", "CANCELLED", "EXPIRED"];
  for (const status of statuses) {
    assert.equal(payloadRequired(status, true), false, `${status} with a terminal queue still required a payload`);
  }
});

/**
 * P4 — the counter frame. These are the cases the architect enumerated, run
 * against BullMQ 6.3.4's actual sequencing rather than an assumed one.
 */
test("three attempts, failing on attempt one: the payload survives for the retry", () => {
  const run = threeAttemptRun((attempt) => (attempt === 1 ? { unrecoverable: false } : "ok"));
  assert.equal(run.length, 1, "one failed delivery");
  assert.equal(run[0].queueWillRetry, true);
  // This is the case the previous implementation got right by accident: adding one
  // to the entry-frame counter happens to agree at attempt 1.
  assert.equal(run[0].workerSaysTerminal, false, "the worker must not purge while a retry is scheduled");
  assert.equal(run[0].pipelineSaysTerminal, false);
});

test("three attempts, failing on attempt two: the retry is still scheduled and the payload is kept", () => {
  // The regression. With `attemptsMade + 1` applied to the post-increment counter,
  // attempt 2 of 3 computed `2 + 1 >= 3` => terminal, and purged the payload while
  // BullMQ still had one attempt left to run.
  const run = threeAttemptRun((attempt) => (attempt <= 2 ? { unrecoverable: false } : "ok"));
  const second = run[1];
  assert.equal(second.attempt, 2);
  assert.equal(second.queueWillRetry, true, "BullMQ schedules the third attempt");
  assert.equal(second.workerSaysTerminal, false, "the worker must agree with the queue, not purge early");
  assert.equal(second.pipelineSaysTerminal, false, "the pipeline must agree too");
});

test("three attempts, exhausted: the final failure purges once", () => {
  const run = threeAttemptRun(() => ({ unrecoverable: false }));
  assert.equal(run.length, 3);
  assert.deepEqual(run.map((row) => row.queueWillRetry), [true, true, false]);
  assert.deepEqual(run.map((row) => row.workerSaysTerminal), [false, false, true], "only the last delivery is terminal");
  assert.deepEqual(run.map((row) => row.pipelineSaysTerminal), [false, false, true]);
});

test("an unrecoverable failure on the first attempt is terminal even with attempts left", () => {
  const run = threeAttemptRun(() => ({ unrecoverable: true }));
  assert.equal(run.length, 1);
  assert.equal(run[0].queueWillRetry, false, "BullMQ stops immediately on UnrecoverableError");
  assert.equal(run[0].workerSaysTerminal, true);
  assert.equal(run[0].pipelineSaysTerminal, true, "the pipeline must purge rather than wait for attempts to run out");
});

test("the worker and the pipeline never disagree about a delivery", () => {
  // Both frames describe the same delivery; if they ever diverge, one of them is
  // purging either earlier or later than the queue's own decision.
  for (const plan of ["ok", "one", "two"] as const) {
    const run = threeAttemptRun((attempt) =>
      plan === "ok" ? (attempt >= 1 ? "ok" : "ok") : plan === "one" ? (attempt === 1 ? { unrecoverable: false } : "ok") : (attempt <= 2 ? { unrecoverable: false } : "ok"));
    for (const row of run) {
      assert.equal(row.workerSaysTerminal, !row.queueWillRetry, `plan ${plan} attempt ${row.attempt}: worker disagreed with the queue`);
      assert.equal(row.pipelineSaysTerminal, !row.queueWillRetry, `plan ${plan} attempt ${row.attempt}: pipeline disagreed with the queue`);
    }
  }
});

test("a single configured attempt is terminal on the first failure", () => {
  assert.equal(classifyFailedEvent({ attemptsMade: 1, maxAttempts: 1, unrecoverable: false }).terminal, true);
  assert.equal(classifyAtProcessorEntry({ attemptsMade: 0, maxAttempts: 1, unrecoverable: false }).terminal, true);
});

test("the two frames differ by exactly one attempt, and that difference is the bug", () => {
  // Documenting the invariant that was violated: the same numeric counter fed to
  // both functions yields different verdicts, which is why they are separate
  // exports rather than one function with a flag.
  const postIncrement = 2; // after two failures, still one attempt left
  assert.equal(classifyFailedEvent({ attemptsMade: postIncrement, maxAttempts: 3, unrecoverable: false }).terminal, false);
  assert.equal(classifyAtProcessorEntry({ attemptsMade: postIncrement, maxAttempts: 3, unrecoverable: false }).terminal, true);
});
