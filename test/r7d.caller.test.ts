/**
 * The trusted caller library (R7D.1 §9).
 *
 * ## What is real here
 *
 * The verification path: the caller computes its own digest, verifies an HMAC over the complete
 * transcript, compares every binding field, and only then releases bytes. Every refusal below is
 * produced by the production code with a commit the test forged, not by a stub.
 *
 * **Mocked:** the supervisor channel. The commit is generated with the same signing function the
 * supervisor uses, so the cryptography is real; what is not tested is any actual transport.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { randomBytes, createHash } from "node:crypto";
import { executeRequest, CallerError, digestOf, newRequestId, type SupervisorChannel, type RequestSpec } from "../src/lib/execution/caller";
import { signTerminalCommit } from "../src/lib/execution/terminal-commit";
import { sha256Hex, type VerifiedTerminalCommit } from "../src/lib/execution/provisional-stream";
import type { TerminalCommitMessage } from "../src/lib/execution/terminal-auth";

const CALLER_SECRET = randomBytes(32);
const EXECUTION = "a".repeat(32);
const REQUEST = "b".repeat(16);
const BOOT = "boot-0123456789";
const SUPERVISOR_INSTANCE = "sv-0123456789ab";
const WATCHDOG_INSTANCE = "wd-0123456789ab";

/** A result frame the caller will hold. Its digest is what the commit must bind. */
const FRAME = Buffer.concat([
  Buffer.from([0, 0, 0, 2]),
  Buffer.from("{}", "utf8"),
  Buffer.from("output", "utf8"),
]);

/** Build a commit message signed with the caller's key, as the supervisor would. */
function commitFor(
  frame: Buffer,
  overrides: Partial<VerifiedTerminalCommit> = {},
  expectation: { executionId?: string; requestId?: string; bootId?: string; supervisorInstance?: string } = {},
): TerminalCommitMessage {
  const commit: VerifiedTerminalCommit = {
    executionId: EXECUTION,
    requestId: REQUEST,
    operation: "fill",
    resultDigest: sha256Hex(frame),
    resultBytes: frame.byteLength,
    // The sealed metadata length is the declared block length in the frame's own prefix, not the
    // whole frame — a real supervisor seals what it actually validated.
    metaBytes: frame.readUInt32BE(0),
    outcome: "committed",
    containerRemoved: true,
    watchdogInstance: WATCHDOG_INSTANCE,
    verifiedAtMonotonicMs: 1_000,
    ...overrides,
  };
  return signTerminalCommit(CALLER_SECRET, commit, {
    executionId: expectation.executionId ?? commit.executionId,
    requestId: expectation.requestId ?? commit.requestId,
    operation: "fill",
    resultDigest: commit.resultDigest,
    resultBytes: commit.resultBytes,
    metaBytes: commit.metaBytes,
    containerId: "c".repeat(64),
    containerName: `dip-exec-${EXECUTION}`,
    bootId: expectation.bootId ?? BOOT,
    supervisorInstance: expectation.supervisorInstance ?? SUPERVISOR_INSTANCE,
    watchdogInstance: WATCHDOG_INSTANCE,
  }, "0123456789abcdef", 1_100);
}

/** A channel that performs no I/O and holds whatever the test gives it. */
function channel(options: {
  ready?: Promise<void>;
  frame?: Buffer;
  message?: TerminalCommitMessage | null;
  onWrite?: (chunk: Buffer) => void;
}): SupervisorChannel {
  const frame = options.frame ?? FRAME;
  return {
    ready: options.ready ?? Promise.resolve(),
    write: async (chunk) => { options.onWrite?.(chunk); },
    endInput: () => undefined,
    result: Readable.from([frame]),
    commitMessage: async () => (options.message === undefined ? commitFor(frame) : options.message),
    cancel: () => undefined,
    nonce: "0123456789abcdef",
  };
}

function spec(body: Buffer, overrides: Partial<RequestSpec> = {}): RequestSpec {
  return {
    requestId: REQUEST,
    operation: "fill",
    role: "worker",
    bodyBytes: body.byteLength,
    bodyDigest: digestOf(body),
    metaBytes: FRAME.byteLength,
    executionId: EXECUTION,
    bootId: BOOT,
    supervisorInstance: SUPERVISOR_INSTANCE,
    ...overrides,
  };
}

test("R7D.1-CL-1: a verified commit releases exactly the bytes it describes", async () => {
  // The caller's own digest and byte count are checked against the commit. The bytes are returned
  // only after the transcript verified and every field matched.
  const body = Buffer.from("form payload");
  const result = await executeRequest(channel({}), spec(body), Readable.from([body]), CALLER_SECRET);
  assert.equal(result.bytes.equals(FRAME), true);
  assert.equal(result.digest, sha256Hex(FRAME));
  assert.equal(result.commit.watchdogInstance, WATCHDOG_INSTANCE);
});

test("R7D.1-CL-2: no commit means no result, even when the frame is well formed", async () => {
  // A successful result frame alone never authorizes release. This is the core correction.
  const body = Buffer.from("payload");
  await assert.rejects(
    executeRequest(channel({ message: null }), spec(body), Readable.from([body]), CALLER_SECRET),
    (error: unknown) => error instanceof CallerError && error.code === "COMMIT_MISSING",
  );
});

test("R7D.1-CL-3: a commit signed with another key is refused", async () => {
  const body = Buffer.from("payload");
  const foreign = signTerminalCommit(randomBytes(32), {
    executionId: EXECUTION, requestId: REQUEST, operation: "fill",
    resultDigest: sha256Hex(FRAME), resultBytes: FRAME.byteLength, metaBytes: FRAME.byteLength,
    outcome: "committed", containerRemoved: true, watchdogInstance: WATCHDOG_INSTANCE,
    verifiedAtMonotonicMs: 1_000,
  }, {
    executionId: EXECUTION, requestId: REQUEST, operation: "fill", resultDigest: sha256Hex(FRAME),
    resultBytes: FRAME.byteLength, metaBytes: FRAME.byteLength, containerId: "c".repeat(64),
    containerName: `dip-exec-${EXECUTION}`, bootId: BOOT, supervisorInstance: SUPERVISOR_INSTANCE,
    watchdogInstance: WATCHDOG_INSTANCE,
  }, "0123456789abcdef", 1_100);

  await assert.rejects(
    executeRequest(channel({ message: foreign }), spec(body), Readable.from([body]), CALLER_SECRET),
    (error: unknown) => error instanceof CallerError && error.code === "RESULT_UNVERIFIED",
  );
});

test("R7D.1-CL-4: a commit that describes different bytes is refused", async () => {
  // A valid signature over a commit for a different result is exactly what a replay looks like.
  const body = Buffer.from("payload");
  const otherFrame = Buffer.from("a different result");
  await assert.rejects(
    executeRequest(channel({ message: commitFor(otherFrame) }), spec(body), Readable.from([body]), CALLER_SECRET),
    (error: unknown) => error instanceof CallerError && error.code === "RESULT_UNVERIFIED",
  );
});

test("R7D.1-CL-5: a non-committed outcome never releases output", async () => {
  const body = Buffer.from("payload");
  for (const outcome of ["refused", "timeout", "cancelled", "failed"] as const) {
    await assert.rejects(
      executeRequest(channel({ message: commitFor(FRAME, { outcome }) }), spec(body), Readable.from([body]), CALLER_SECRET),
      (error: unknown) => error instanceof CallerError && error.code === "RESULT_UNVERIFIED",
      outcome,
    );
  }
});

test("R7D.1-CL-6: a commit without confirmed removal never releases output", async () => {
  const body = Buffer.from("payload");
  await assert.rejects(
    executeRequest(channel({ message: commitFor(FRAME, { containerRemoved: false }) }), spec(body), Readable.from([body]), CALLER_SECRET),
    (error: unknown) => error instanceof CallerError,
  );
});

test("R7D.1-CL-7: the caller does not send a byte before it is invited", async () => {
  const body = Buffer.from("payload");
  const sent: Buffer[] = [];
  // A `ready` that never resolves. The caller must refuse rather than optimistically write, so
  // that no document byte is ever in flight against a container that failed preflight.
  await assert.rejects(
    executeRequest(
      channel({ ready: new Promise<void>(() => undefined), onWrite: (chunk) => sent.push(chunk) }),
      spec(body),
      Readable.from([body]),
      CALLER_SECRET,
      { limits: { readyTimeoutMs: 20 } },
    ),
    (error: unknown) => error instanceof CallerError && error.code === "NOT_READY",
  );
  assert.deepEqual(sent, [], "no body byte may be written before the invitation");
});

test("R7D.1-CL-8: the caller refuses a body larger than its own bound", async () => {
  const body = Buffer.alloc(2_048, 1);
  await assert.rejects(
    executeRequest(channel({}), spec(body), Readable.from([body]), CALLER_SECRET, { limits: { maxInputBytes: 1_024 } }),
    (error: unknown) => error instanceof CallerError && error.code === "INPUT_TOO_LARGE",
  );
});

test("R7D.1-CL-9: a body that does not match its declaration is refused", async () => {
  const body = Buffer.from("payload");
  // The caller declared one digest and streamed another. The supervisor would reject it too, but
  // the caller must not proceed to collect in that state.
  await assert.rejects(
    executeRequest(channel({}), spec(body, { bodyDigest: "0".repeat(64) }), Readable.from([body]), CALLER_SECRET),
    (error: unknown) => error instanceof CallerError && error.code === "INPUT_MISMATCH",
  );
});

test("R7D.1-CL-10: the caller refuses a result larger than its own bound", async () => {
  const body = Buffer.from("payload");
  await assert.rejects(
    executeRequest(channel({}), spec(body), Readable.from([body]), CALLER_SECRET, { limits: { maxOutputBytes: 4 } }),
    (error: unknown) => error instanceof CallerError && error.code === "RESULT_TOO_LARGE",
  );
});

test("R7D.1-CL-11: the caller's digest is of the complete frame, not of the body alone", async () => {
  // The chain binds the whole frame. A caller that hashed only the output section would accept a
  // commit that described a different metadata block, which is a different operation result.
  const body = Buffer.from("payload");
  const frameDigest = sha256Hex(FRAME);
  const bodyDigest = createHash("sha256").update(Buffer.from("output")).digest("hex");
  assert.notEqual(frameDigest, bodyDigest, "the frame and its body must not share a digest here");
  const result = await executeRequest(channel({}), spec(body), Readable.from([body]), CALLER_SECRET);
  assert.equal(result.digest, frameDigest);
});

test("R7D.1-CL-12: request ids are unpredictable and never repeat", () => {
  const ids = new Set<string>();
  for (let index = 0; index < 64; index += 1) ids.add(newRequestId());
  assert.equal(ids.size, 64);
  for (const id of ids) assert.match(id, /^[a-f0-9]{32}$/u);
});

test("R7D.1-CL-13: a commit for another execution is refused by the caller", async () => {
  const body = Buffer.from("payload");
  const foreignExecution = "f".repeat(32);
  const message = commitFor(FRAME, { executionId: foreignExecution }, { executionId: foreignExecution });
  await assert.rejects(
    executeRequest(channel({ message }), spec(body), Readable.from([body]), CALLER_SECRET),
    (error: unknown) => error instanceof CallerError && error.code === "RESULT_UNVERIFIED",
  );
});
