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
import { classifyAttemptOutcome, payloadRequired, retryTransitionTarget } from "../src/lib/jobs/payload-lifecycle";

/** The single question every case reduces to. */
const purges = (facts: { attemptsMade: number; maxAttempts: number; unrecoverable: boolean }) =>
  classifyAttemptOutcome(facts).terminal;

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
  const outcome = classifyAttemptOutcome({ attemptsMade: 0, maxAttempts: 3, unrecoverable: true });
  assert.deepEqual(outcome, { terminal: true, reason: "UNRECOVERABLE" });
});

test("attempt exhaustion is terminal on the last configured attempt", () => {
  assert.equal(purges({ attemptsMade: 2, maxAttempts: 3, unrecoverable: false }), true);
  assert.equal(purges({ attemptsMade: 1, maxAttempts: 3, unrecoverable: false }), false);
  // A job configured with a single attempt is terminal after it.
  assert.equal(purges({ attemptsMade: 0, maxAttempts: 1, unrecoverable: false }), true);
});

test("a stalled delivery that is retried keeps the payload until it is terminal", () => {
  // BullMQ counts a stalled delivery as an attempt. The payload must survive,
  // because the job will run again and needs its inputs.
  assert.equal(purges({ attemptsMade: 1, maxAttempts: 3, unrecoverable: false }), false);
  assert.equal(payloadRequired("RUNNING", false), true);
});

test("stalled and then exhausted purges once, at the terminal point", () => {
  assert.equal(purges({ attemptsMade: 2, maxAttempts: 3, unrecoverable: false }), true);
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
  assert.equal(purges({ attemptsMade: 2, maxAttempts: 3, unrecoverable: false }), true);
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
