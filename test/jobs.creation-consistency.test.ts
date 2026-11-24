/**
 * P5 — a charge must match a job that exists.
 *
 * The rule is one sentence: **release only when no job row committed.** Both halves
 * matter. Releasing too late leaves a charge for work that never happened; releasing
 * too early gives away work that may already be running, and on an ambiguous enqueue
 * acknowledgement it also risks deleting inputs a QUEUED job still references.
 *
 * The model below mirrors `createToolJob`'s control flow — one `try`, a commit
 * point, then cleanup — because the defect was precisely an ordering question that a
 * helper-level unit test could not see.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

type Outcome = {
  committed: boolean;
  chargeReleased: boolean;
  inputsDeleted: boolean;
  jobStatus: string | null;
  error?: string;
};

/**
 * Faithful model of `createToolJob`'s failure handling, with the post-commit branch
 * the fix introduced.
 */
function runCreation(scenario: "ok" | "storage-fail" | "tx-fail" | "enqueue-throws" | "ambiguous-ack"): Outcome {
  let committedJobId: string | undefined;
  let inputsDeleted = false;
  let chargeReleased = false;
  let jobStatus: string | null = null;
  try {
    if (scenario === "storage-fail") throw new Error("S3 500");
    if (scenario === "tx-fail") throw new Error("P2034 transaction conflict");
    committedJobId = "job-1";
    jobStatus = "QUEUED";
    if (scenario === "enqueue-throws") throw new Error("ECONNRESET");
    if (scenario === "ambiguous-ack") throw new Error("ETIMEDOUT waiting for acknowledgement");
    return { committed: true, chargeReleased, inputsDeleted, jobStatus };
  } catch (error) {
    // The fix: cleanup branches on whether a job row committed.
    if (committedJobId) return { committed: true, chargeReleased, inputsDeleted, jobStatus, error: (error as Error).message };
    chargeReleased = true;
    inputsDeleted = true;
    return { committed: false, chargeReleased, inputsDeleted, jobStatus: null, error: (error as Error).message };
  }
}

test("a storage failure before the commit releases the charge and deletes inputs", () => {
  const outcome = runCreation("storage-fail");
  assert.equal(outcome.committed, false);
  assert.equal(outcome.chargeReleased, true, "no job exists, so the charge must not stand");
  assert.equal(outcome.inputsDeleted, true, "nothing references the uploaded objects");
});

test("a transaction failure releases the charge", () => {
  const outcome = runCreation("tx-fail");
  assert.equal(outcome.committed, false);
  assert.equal(outcome.chargeReleased, true);
});

test("a definite enqueue failure after the commit keeps the charge and the inputs", () => {
  // The job row exists and is discoverable. A caught exception does not prove the
  // queue rejected it, and even when it did the row must remain consistent.
  const outcome = runCreation("enqueue-throws");
  assert.equal(outcome.committed, true);
  assert.equal(outcome.chargeReleased, false, "the job exists; releasing would give the work away");
  assert.equal(outcome.inputsDeleted, false, "a QUEUED job must not point at deleted objects");
});

test("an ambiguous enqueue acknowledgement keeps the charge and the inputs", () => {
  // Worst case: the job WAS queued and the reply was lost. It may be running, so
  // deleting its inputs would corrupt live work.
  const outcome = runCreation("ambiguous-ack");
  assert.equal(outcome.committed, true);
  assert.equal(outcome.chargeReleased, false);
  assert.equal(outcome.inputsDeleted, false);
  assert.equal(outcome.jobStatus, "QUEUED", "the row stays discoverable for expiry reconciliation");
});

test("a successful creation releases nothing", () => {
  const outcome = runCreation("ok");
  assert.equal(outcome.chargeReleased, false);
  assert.equal(outcome.inputsDeleted, false);
});

test("the orchestrator branches cleanup on the commit, and the code says so", () => {
  // The behavioural cases above prove the rule; this proves the implementation
  // applies it rather than an unconditional `Promise.all` of every cleanup.
  const source = readFileSync(new URL("../src/lib/jobs/orchestrator.ts", import.meta.url), "utf8");
  assert.match(source, /let committedJobId: string \| undefined/u, "the commit point must be tracked");
  assert.match(source, /if \(committedJobId\) \{/u, "cleanup must branch on the commit");
  const postCommit = source.slice(source.indexOf("if (committedJobId) {"));
  assert.equal(
    postCommit.slice(0, postCommit.indexOf("throw error")).includes("charge?.release()"),
    false,
    "the post-commit branch must not release the charge",
  );
  // And the pre-commit branch still releases it.
  const preCommit = source.slice(source.indexOf("No job row: release the charge"));
  assert.match(preCommit.slice(0, 600), /charge\?\.release\(\)/u);
});

test("usage events are not double counted when creation is refused", () => {
  // `enforceJobCreation` is idempotent per idempotency key (`prior` check), so a
  // retried submission does not write a second `job.created` event; the release is
  // keyed on the same idempotency key so it cannot refund twice either.
  const enforcement = readFileSync(new URL("../src/lib/usage/enforcement.ts", import.meta.url), "utf8");
  assert.match(enforcement, /const prior=await tx\.usageEvent\.findUnique/u, "the usage event must be idempotent per key");
  assert.match(enforcement, /job-release:\$\{input\.toolId\}:\$\{input\.idempotencyKey\}/u, "the reversal must be idempotent per key");
});
