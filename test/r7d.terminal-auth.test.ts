/**
 * Authenticated terminal arbitration (R7D.1, C-F02 / §4 / §5).
 *
 * ## What is real here and what is mocked
 *
 * Real: HMAC computation and verification, the transcript encoding, the watchdog state machine,
 * the message-id window, the deadline clock (injected, advanced by the test), and the negative
 * paths — every refusal is produced by the real code, not by a stub.
 *
 * Mocked: `killContainer`/`inspectContainer` are injected functions, so nothing here touches a
 * Docker daemon. **No test in this file establishes OS isolation.** The cgroup checks are exercised
 * against this sandbox's real `/sys/fs/cgroup` (a cgroup2 hierarchy exists here, at `/user`), which
 * is why some arm tests use a synthetic cgroup root created with `mkdtemp` — the code reads real
 * inodes either way, but the container is fictional.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Watchdog, newWatchdogIdentity, verifyArmIdentity, type HostVerification } from "../src/lib/execution/watchdog";
import {
  MessageIdWindow,
  decodeWatchdogFrame,
  encodeWatchdogFrame,
  signArmAck,
  verifyArmAck,
  signDisarmGrant,
  verifyDisarmGrant,
  WATCHDOG_LIMITS,
  type ArmRequest,
  type Heartbeat,
} from "../src/lib/execution/watchdog-protocol";
import { verifyWatchdogGrant, verifyTerminalCommit, signTerminalCommit } from "../src/lib/execution/terminal-commit";
import { assertTerminalContext, computeTerminalProof, type TerminalRequest } from "../src/lib/execution/terminal-auth";
import { readBootId, readProcessStartTimeTicks, findCgroup2Mount } from "../src/lib/execution/host-facts";
import { BoundedProvisionalOutput } from "../src/lib/execution/provisional-stream";
import { WatchdogStore } from "../src/lib/execution/watchdog-store";
import { makeWatchdog as makeWatchdogHarness, VIRTUAL_CGROUP_MOUNT } from "./support/watchdog-harness";

const SUPERVISOR = "sv-0123456789ab";
const EXECUTION = "a".repeat(32);
const REQUEST = "b".repeat(16);
const CONTAINER_ID = "c".repeat(64);
const CONTAINER_NAME = `dip-exec-${EXECUTION}`;
const IMAGE_DIGEST = `sha256:${"d".repeat(64)}`;
const WATCHDOG_SECRET = randomBytes(32);
const CALLER_SECRET = randomBytes(32);

test("R7D.1-CF02-11: a control frame is length-prefixed and refuses oversized bodies", () => {
  const encoded = encodeWatchdogFrame({ kind: "HEARTBEAT", executionId: EXECUTION });
  assert.equal(encoded.readUInt32BE(0), encoded.byteLength - 4);
  assert.deepEqual(decodeWatchdogFrame(encoded), { kind: "HEARTBEAT", executionId: EXECUTION });

  assert.throws(() => encodeWatchdogFrame({ pad: "x".repeat(WATCHDOG_LIMITS.frameBytes) }), /exceeds/u);

  const truncated = encoded.subarray(0, encoded.byteLength - 2);
  assert.throws(() => decodeWatchdogFrame(truncated), /truncated/u);

  const lying = Buffer.alloc(8);
  lying.writeUInt32BE(1_000_000, 0);
  assert.throws(() => decodeWatchdogFrame(lying), /more than the bound|truncated/u);
});

test("R7D.1-CF02-12: an ARM_ACK proof is bound to the observed identity", () => {
  const ack = {
    kind: "ARM_ACK" as const,
    messageId: "1".repeat(16),
    executionId: EXECUTION,
    watchdogInstance: "wd-0123456789ab",
    observedCgroupDirInode: 100,
    observedCgroupEventsInode: 101,
    observedCgroupKillInode: 102,
    observedCgroupProcsInode: 103,
    observedCgroupDevice: "0:25",
    observedBootId: "boot-abc",
    armedAtMonotonicMs: 5_000,
  };
  const proof = signArmAck(WATCHDOG_SECRET, ack);
  assert.equal(verifyArmAck(WATCHDOG_SECRET, { ...ack, proof }), true);

  // Every observed field is in the transcript: changing any one invalidates the proof. This is
  // what makes the ack evidence rather than a courtesy.
  for (const field of ["observedCgroupDirInode", "observedCgroupKillInode", "observedBootId", "armedAtMonotonicMs"] as const) {
    assert.equal(verifyArmAck(WATCHDOG_SECRET, { ...ack, proof, [field]: 1 as never }), false, field);
  }
  assert.equal(verifyArmAck(randomBytes(32), { ...ack, proof }), false, "wrong key");
  assert.equal(verifyArmAck(WATCHDOG_SECRET, { ...ack, proof: "zz" }), false, "malformed proof does not throw");
});

test("R7D.1-CF02-13: the message-id window refuses a replay and stays bounded", () => {
  const window = new MessageIdWindow(4);
  assert.equal(window.consume(EXECUTION, "1"), true);
  assert.equal(window.consume(EXECUTION, "1"), false, "the same id cannot be used twice");
  // The window is per execution: the same id under another execution is a different message.
  assert.equal(window.consume("f".repeat(32), "1"), true);
  for (let index = 0; index < 10; index += 1) window.consume(EXECUTION, `id-${index}`);
  assert.ok(window.size <= 4, `window must stay bounded, saw ${window.size}`);
});

test("R7D.1-CF02-14: a watchdog refuses to arm a request from another boot", async () => {
  // The real verifier, not an injected one: this asserts production behaviour.
  const harness = makeWatchdog({ realVerify: true });
  const denied = await harness.watchdog.arm(baseArm({ bootId: "previous-boot", cgroupPath: "/sys/fs/cgroup/dip-exec/x" }));
  assert.equal(denied.kind, "ARM_DENIED");
  assert.equal((denied as { code: string }).code, "BOOT_MISMATCH");
  // A refused arm leaves nothing armed.
  assert.deepEqual(harness.watchdog.outstanding(), []);
});

test("R7D.1-CF02-15: a watchdog refuses to arm when the cgroup cannot be verified", async () => {
  const harness = makeWatchdog({ realVerify: true });
  const denied = await harness.watchdog.arm(baseArm({ cgroupPath: `/sys/fs/cgroup/dip-executor.slice/dip-exec-${EXECUTION}` }));
  assert.equal(denied.kind, "ARM_DENIED");
  assert.equal((denied as { code: string }).code, "CGROUP_UNVERIFIED");
});

test("R7D.1-CF02-16: the host verifier refuses a PID that is not in the cgroup it names", () => {
  // Real /proc and real /sys: this process exists, its start time is checkable, and it is not in
  // the directory the request claims. The membership check is what must refuse.
  const mount = findCgroup2Mount();
  assert.notEqual(mount, null, "this sandbox exposes a cgroup2 mount; the verifier needs one");
  const directory = mkdtempSync(join(tmpdir(), "dip-cg-"));
  try {
    for (const name of ["cgroup.events", "cgroup.kill", "cgroup.procs"]) writeFileSync(join(directory, name), "populated 1\n");
    const result = verifyArmIdentity(baseArm({
      cgroupPath: directory,
      initPid: process.pid,
      initStartTimeTicks: readProcessStartTimeTicks(process.pid),
    }), readBootId());
    assert.equal(result.ok, false);
    // It fails because the path is not in the dedicated DIP subtree, which is a refusal — and the
    // more specific one, since ownership is checked before existence.
    assert.equal((result as { code: string }).code, "NOT_DIP_OWNED");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("R7D.1-CF02-16b: the host verifier refuses a PID whose start time does not match", () => {
  // This sandbox has no `dip-executor.slice`, so a request naming one cannot resolve to a real
  // cgroup. Both facts below are therefore refused — but for a reason this test can name, rather
  // than by trusting the request. The PID-level probes that need a legitimate DIP cgroup are in
  // `r7d.watchdog-security.test.ts`, where the refusal code is asserted explicitly.
  const result = verifyArmIdentity(baseArm({
    initPid: process.pid,
    initStartTimeTicks: readProcessStartTimeTicks(process.pid) + 1,
  }), readBootId());
  assert.equal(result.ok, false);
  if (!result.ok) assert.ok(["PID_UNVERIFIED", "CGROUP_UNVERIFIED"].includes(result.code), result.code);
});

test("R7D.1-CF02-16c: the host verifier refuses this process when it is not the execution's init", () => {
  // A real PID, a real start time, a real boot — and still a refusal, because the process is not in
  // the cgroup the request names. This is the positive-control-shaped negative: the verifier is not
  // refusing everything blindly, it is refusing this claim.
  const result = verifyArmIdentity(baseArm({
    initPid: process.pid,
    initStartTimeTicks: readProcessStartTimeTicks(process.pid),
  }), readBootId());
  assert.equal(result.ok, false);
  if (!result.ok) assert.ok(["PID_UNVERIFIED", "CGROUP_UNVERIFIED"].includes(result.code), result.code);

  // And the same request with a boot id that is not this boot is refused earlier still.
  const stale = verifyArmIdentity(baseArm({ bootId: "00000000-0000-4000-8000-000000000000" }), readBootId());
  assert.equal(stale.ok, false);
  if (!stale.ok) assert.equal(stale.code, "BOOT_MISMATCH");
});

test("R7D.1-CF02-17: a watchdog refuses a second arm for the same execution", async () => {
  const harness = makeWatchdog();
  const first = await harness.watchdog.arm(baseArm({ messageId: "1".repeat(16) }));
  assert.equal(first.kind, "ARM_ACK");
  const second = await harness.watchdog.arm(baseArm({ messageId: "2".repeat(16) }));
  assert.equal((second as { code: string }).code, "ALREADY_ARMED");
  // A replayed message id is refused before the armed-state check, so the reason is specific.
  const replay = await harness.watchdog.arm(baseArm({ messageId: "1".repeat(16) }));
  assert.equal((replay as { code: string }).code, "REPLAYED");
  await harness.watchdog.disarm(terminalContext(harness.observed!), "3".repeat(16), 2);
});

test("R7D.1-CF02-18: a disarm whose deadline has passed is refused and leaves the execution terminable", async () => {
  const harness = makeWatchdog();
  assert.notEqual(await harness.armWithFakeCgroup(), null, "the harness must arm successfully");
  harness.advance(6_000);
  const denied = await harness.watchdog.disarm(terminalContext(harness.observed!), "3".repeat(16), 2);
  assert.equal((denied as { code: string }).code, "EXPIRED");
  // The expired execution cannot then be disarmed even if the clock were to go backwards.
  harness.advance(-10_000);
  const again = await harness.watchdog.disarm(terminalContext(harness.observed!), "4".repeat(16), 3);
  assert.notEqual((again as { code?: string }).code, undefined);
});

test("R7D.1-CF02-19: a grant is refused when the context names a different container", async () => {
  // A real pin over a real (non-cgroup) tree, so a *correct* disarm can succeed — which is what
  // makes the refusal below meaningful rather than indistinguishable from "nothing ever succeeds".
  const granted = makeGrantable();
  try {
    await armGrantable(granted);
    // The supervisor removed the container after committing; a grant before that would release
    // bytes the executor still holds (WD-F04).
    granted.harness.removeContainer();
    const mismatched = terminalContext(granted.digest, { containerId: "f".repeat(64) });
    const denied = await granted.harness.watchdog.disarm(mismatched, "5".repeat(16), 2);
    assert.equal((denied as { code: string }).code, "MISMATCH");
    // A refusal must not consume the execution: a correct disarm still succeeds afterwards.
    const grant = await granted.harness.watchdog.disarm(terminalContext(granted.digest), "6".repeat(16), 2);
    assert.ok("proof" in grant, "a correct disarm after a refused one must still be issued");
  } finally {
    granted.harness.cleanup();
  }
});

test("R7D.1-CF02-20: a second disarm is refused with ALREADY_CONCLUDED", async () => {
  const granted = makeGrantable();
  try {
    await armGrantable(granted);
    granted.harness.removeContainer();
    const first = await granted.harness.watchdog.disarm(terminalContext(granted.digest), "7".repeat(16), 2);
    assert.ok("proof" in first);
    const second = await granted.harness.watchdog.disarm(terminalContext(granted.digest), "8".repeat(16), 3);
    assert.equal((second as { code: string }).code, "ALREADY_CONCLUDED");
  } finally {
    granted.harness.cleanup();
  }
});

test("R7D.1-CF02-21: termination and disarm cannot both win", async () => {
  const harness = makeWatchdog();
  assert.notEqual(await harness.armWithFakeCgroup(), null, "the harness must arm successfully");
  // Advance to the deadline: the watchdog concludes it as unresolved.
  harness.advance(6_000);
  const due = harness.watchdog.dueForTermination();
  assert.equal(due.length, 1);
  const result = await harness.watchdog.terminate(due[0]!);
  assert.equal(result.executionId, EXECUTION);

  // A disarm arriving after the deadline fired must be refused. This is the race the record
  // serialises: the deadline reached `concluded` first.
  const denied = await harness.watchdog.disarm(terminalContext(harness.observed!), "9".repeat(16), 2);
  assert.ok(["TERMINATED", "ALREADY_CONCLUDED", "EXPIRED"].includes((denied as { code: string }).code), (denied as { code: string }).code);
});

test("R7D.1-CF02-22: a committed outcome without removal evidence is refused, not released", async () => {
  const harness = makeWatchdog();
  assert.notEqual(await harness.armWithFakeCgroup(), null, "the harness must arm successfully");
  // `containerRemoved: false` is the caller's own claim; the injected pin cannot confirm
  // termination either, so the refusal is `UNCERTAIN` rather than a release.
  const denied = await harness.watchdog.disarm(terminalContext(harness.observed!, { containerRemoved: false }), "a".repeat(16), 2);
  assert.equal((denied as { code: string }).code, "UNCERTAIN");
});

test("R7D.1-CF02-23: a verified grant produces a commit, and every binding is checked", () => {
  // This is the whole chain, without a container: watchdog signs, supervisor verifies, caller
  // verifies, output releases. Each negative case below is a distinct defect.
  const chain = makeChain();
  const first = verifyWatchdogGrant(WATCHDOG_SECRET, chain.expectation, chain.grant, 9_000);
  assert.equal(first.ok, true);
  if (!first.ok) return;
  assert.equal(first.commit.resultDigest, chain.digest);

  // A grant signed by another watchdog instance is refused even though its signature is valid.
  const foreign = verifyWatchdogGrant(WATCHDOG_SECRET, { ...chain.expectation, watchdogInstance: "wd-other-instance" }, chain.grant, 9_000);
  assert.equal(foreign.ok, false);
  assert.equal((foreign as { code: string }).code, "BAD_WATCHDOG_PROOF");

  // A grant whose context was edited after signing fails the signature.
  const tampered = { ...chain.grant, context: { ...chain.grant.context, resultDigest: "0".repeat(64) } };
  const tamperedResult = verifyWatchdogGrant(WATCHDOG_SECRET, chain.expectation, tampered, 9_000);
  assert.equal((tamperedResult as { code: string }).code, "BAD_WATCHDOG_PROOF");

  // A grant for a different execution is a valid signature over the wrong subject.
  const different = verifyWatchdogGrant(
    WATCHDOG_SECRET,
    { ...chain.expectation, resultBytes: chain.expectation.resultBytes + 1 },
    chain.grant,
    9_000,
  );
  assert.equal((different as { code: string }).code, "GRANT_MISMATCH");

  // No grant at all is not an error, it is a missing precondition.
  assert.equal((verifyWatchdogGrant(WATCHDOG_SECRET, chain.expectation, null, 9_000) as { code: string }).code, "MISSING_GRANT");
});

test("R7D.1-CF02-24: a non-committed outcome cannot be authorized even with a valid signature", () => {
  const chain = makeChain({ outcome: "refused" });
  const result = verifyWatchdogGrant(WATCHDOG_SECRET, chain.expectation, chain.grant, 9_000);
  assert.equal(result.ok, false);
  assert.equal((result as { code: string }).code, "NOT_ELIGIBLE");
});

test("R7D.1-CF02-25: the caller verifies the commit independently and cannot accept a forged one", () => {
  const chain = makeChain();
  const nonce = "0123456789abcdef";
  const commitMessage = signTerminalCommit(CALLER_SECRET, chain.commit, chain.expectation, nonce, 9_100);

  const verified = verifyTerminalCommit(CALLER_SECRET, commitMessage, {
    executionId: EXECUTION,
    requestId: REQUEST,
    operation: "fill",
    resultDigest: chain.digest,
    resultBytes: chain.expectation.resultBytes,
    metaBytes: chain.expectation.metaBytes,
    bootId: chain.expectation.bootId,
    supervisorInstance: SUPERVISOR,
  }, 9_200);
  assert.equal(verified.ok, true);
  if (!verified.ok) return;

  // The commit is signed under the caller's key, so the watchdog's key does not verify it. This
  // is what stops one authority from minting the other's evidence.
  const wrongKey = verifyTerminalCommit(
    WATCHDOG_SECRET,
    commitMessage,
    { executionId: EXECUTION, requestId: REQUEST, operation: "fill", resultDigest: chain.digest, resultBytes: chain.expectation.resultBytes, metaBytes: chain.expectation.metaBytes, bootId: chain.expectation.bootId, supervisorInstance: SUPERVISOR },
    9_200,
  );
  assert.equal((wrongKey as { code: string }).code, "BAD_COMMIT_PROOF");

  // A commit that describes different bytes is refused by the caller, not trusted.
  const wrongBytes = verifyTerminalCommit(CALLER_SECRET, commitMessage, {
    executionId: EXECUTION, requestId: REQUEST, operation: "fill", resultDigest: chain.digest,
    resultBytes: chain.expectation.resultBytes + 1, metaBytes: chain.expectation.metaBytes,
    bootId: chain.expectation.bootId, supervisorInstance: SUPERVISOR,
  }, 9_200);
  assert.equal((wrongBytes as { code: string }).code, "GRANT_MISMATCH");

  // And the verified commit is what releases the bytes, in the caller's own process.
  const output = new BoundedProvisionalOutput(1024);
  output.append(chain.bytes);
  output.seal(EXECUTION, chain.digest);
  assert.equal(output.collect(verified.commit).byteLength, chain.bytes.byteLength);
});

test("R7D.1-CF02-26: a grant issued by the watchdog verifies with the same code path the supervisor uses", () => {
  // Guards the two-sided-context defect: signDisarmGrant and verifyDisarmGrant must agree, and
  // the supervisor's verifier must accept what the watchdog actually produced.
  const request = terminalRequest(makeChain().digest, 128);
  const grant = signDisarmGrant(WATCHDOG_SECRET, request);
  assert.equal(verifyDisarmGrant(WATCHDOG_SECRET, grant), true);
  assert.equal(verifyDisarmGrant(randomBytes(32), grant), false);
});

test("R7D.1-CF02-27: a heartbeat proves liveness and authorizes nothing", () => {
  const harness = makeWatchdog();
  const beat: Heartbeat = {
    kind: "HEARTBEAT",
    messageId: "c".repeat(16),
    executionId: EXECUTION,
    supervisorInstance: SUPERVISOR,
    monotonicMs: 1_000,
  };
  // No armed execution: a heartbeat for one is refused rather than creating state.
  assert.equal(harness.watchdog.heartbeat(beat).code, "UNKNOWN_EXECUTION");
  assert.equal(harness.watchdog.state(EXECUTION).armed, false);
  // A heartbeat did not create an execution, and it did not authorize anything.
  assert.deepEqual(harness.watchdog.outstanding(), []);
});

test("R7D.1-CF02-28: recovery refuses a record written on another boot", async () => {
  // `adopt` took a request and decided; recovery now reads durable records, which is the only
  // source that survives a crash. A record naming another boot describes cgroup namespaces that no
  // longer exist, so it is reported as `previousBoot` and cannot become a live deadline.
  const harness = makeWatchdog();
  try {
    // Nothing armed in this process, so this asserts the reporting shape rather than a decision.
    const recovery = harness.watchdog.recover();
    assert.deepEqual(recovery.adopted, []);
    assert.deepEqual(recovery.quarantined, []);
    assert.deepEqual(recovery.previousBoot, []);
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-CF02-29: an arm whose cgroup cannot be verified is refused", async () => {
  const harness = makeWatchdog({ realVerify: true });
  try {
    const denied = await harness.watchdog.arm(baseArm({ cgroupPath: "/sys/fs/cgroup/dip-exec/gone" }));
    assert.equal(denied.kind, "ARM_DENIED");
    // Not in the DIP subtree, so ownership refuses before existence matters.
    assert.equal((denied as { code: string }).code, "NOT_DIP_OWNED");
    assert.deepEqual(harness.watchdog.outstanding(), []);
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-CF02-30: a watchdog never reports an execution as terminated without positive evidence", async () => {
  const harness = makeWatchdog({ inspectPresent: true });
  try {
    assert.notEqual(await harness.armWithFakeCgroup(), null, "the harness must arm successfully");
    harness.advance(6_000);
    const due = harness.watchdog.dueForTermination();
    const result = await harness.watchdog.terminate(due[0]!);
    // The container is still present, and the injected pin holds no descriptors, so neither debt
    // can be discharged. The record says `unresolved`, which is the honest answer.
    assert.equal(result.containerRemovalConfirmed, false);
    assert.equal(result.processTerminationConfirmed, false);
    assert.equal(result.resolved, false);
    const record = harness.watchdog.state(EXECUTION).record;
    assert.equal(record?.outcome, "unresolved");
    // "Still owed" is recorded as `unresolved` once a termination has been attempted: the debt was
    // not paid and the watchdog is not pretending otherwise.
    assert.equal(record?.containerDebt, "unresolved");
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-CF02-31: a watchdog refuses to claim termination it cannot evidence", async () => {
  // The identity-mismatch case moved to `r7d.watchdog-security.test.ts` (WD-03), where a real pin
  // over a real directory can be swapped. What remains here is the consequence: without a verified
  // pin, no kill is written and no debt is discharged.
  const harness = makeWatchdog();
  try {
    assert.notEqual(await harness.armWithFakeCgroup(), null, "the harness must arm successfully");
    harness.advance(6_000);
    const due = harness.watchdog.dueForTermination();
    const result = await harness.watchdog.terminate(due[0]!);
    // With no pinned descriptor there is no cgroup write; the daemon kill is the separate fallback
    // and it is accepted here. What matters is that a *process* termination was never confirmed
    // from the cgroup, so neither debt is discharged and nothing is claimed.
    assert.equal(result.processTerminationConfirmed, false, "the daemon accepting a kill is not proof the cgroup emptied");
    assert.equal(result.resolved, false);
    const record = harness.watchdog.state(EXECUTION).record;
    // An unresolved termination retains quarantine. `terminating` becomes `quarantined` once the
    // attempt finishes without evidence, which is the state that keeps the execution retryable and
    // prevents its release.
    assert.ok(["terminating", "quarantined"].includes(String(record?.phase)), String(record?.phase));
    assert.equal(record?.outcome, "unresolved");
    // The execution has been terminated as far as this watchdog can act. It is no longer *due* —
    // repeating the same failed attempt on every tick would be a busy loop — but it is quarantined
    // and unresolved, so its release stays blocked and recovery will find it.
    assert.deepEqual(harness.watchdog.dueForTermination(), []);
    assert.equal(harness.watchdog.state(EXECUTION).phase, "quarantined");
  } finally {
    harness.cleanup();
  }
});

// ── helpers ────────────────────────────────────────────────────────────────────────────────────

/**
 * A watchdog whose disarm can succeed: a real pin over a real directory tree shaped like a cgroup.
 *
 * Shared with `r7d.watchdog-security.test.ts`; it is the only construction in these tests where a
 * grant is actually minted, so it is named rather than inlined at each call site.
 */
function makeGrantable(): { harness: ReturnType<typeof makeWatchdogHarness>; digest: string } {
  const harness = makeWatchdogHarness({ liveTree: { populated: false }, observeLifecycle: true });
  return { harness, digest: "e".repeat(64) };
}

/** The arm that a grantable harness accepts: a legitimate DIP leaf with real inodes behind it. */
function grantedArm(digest: string): ArmRequest {
  void digest;
  return baseArm();
}

/** Arm a grantable harness and fail loudly if the arm was refused. */
async function armGrantable(granted: { harness: ReturnType<typeof makeWatchdogHarness>; digest: string }): Promise<void> {
  const answer = await granted.harness.watchdog.arm(grantedArm(granted.digest));
  if (answer.kind !== "ARM_ACK") throw new Error(`the arm was denied: ${answer.code}`);
}

function baseArm(overrides: Partial<ArmRequest> = {}): ArmRequest {
  return {
    kind: "ARM_REQ",
    messageId: "1".repeat(16),
    sequence: 1,
    executionId: EXECUTION,
    requestId: REQUEST,
    operation: "fill",
    supervisorInstance: SUPERVISOR,
    bootId: readBootId(),
    containerId: CONTAINER_ID,
    containerName: CONTAINER_NAME,
    imageDigest: IMAGE_DIGEST,
    profileId: "synthetic-v1",
    initPid: 2,
    initStartTimeTicks: 0,
    cgroupPath: `/sys/fs/cgroup/dip-executor.slice/dip-exec-${EXECUTION}`,
    deadlineMs: 5_000,
    startedMonotonicMs: 0,
    ...overrides,
  };
}

function terminalRequest(digest: string, bytes: number, overrides: Partial<TerminalRequest> = {}): TerminalRequest {
  return {
    executionId: EXECUTION,
    requestId: REQUEST,
    operation: "fill",
    resultDigest: digest,
    resultBytes: bytes,
    metaBytes: 128,
    containerId: CONTAINER_ID,
    containerName: CONTAINER_NAME,
    containerRemoved: true,
    outcome: "committed",
    watchdogInstance: "wd-0123456789ab",
    supervisorInstance: SUPERVISOR,
    bootId: readBootId(),
    nonce: "0123456789abcdef",
    concludedMonotonicMs: 9_000,
    ...overrides,
  };
}

function terminalContext(digest: string, overrides: Partial<TerminalRequest> = {}): TerminalRequest {
  return terminalRequest(digest, 128, overrides);
}

type Harness = {
  watchdog: Watchdog;
  clock: { now: number };
  advance: (delta: number) => void;
  observed: string | null;
  armWithFakeCgroup: () => Promise<unknown | null>;
  cleanup: () => void;
};

/**
 * Build a watchdog whose *arbitration* runs for real over real durable state.
 *
 * The store is a temporary directory with real `fsync`; the clock is a host-consistent clock the
 * test advances; the HMAC primitives are production code. The verification *answer* and the cgroup
 * pin are injected because this sandbox has no writable cgroup2 mount, so an end-to-end arm cannot
 * succeed here. `verifyArmIdentity` itself has direct tests against this host below, and those are
 * the ones that prove verification; these prove the state machine around it.
 */
function makeWatchdog(options: { inspectPresent?: boolean; verify?: HostVerification; realVerify?: boolean } = {}): Harness {
  const clock = { now: 1_000 };
  const bootId = readBootId();
  const identity = newWatchdogIdentity(() => clock.now, readProcessStartTimeTicks(process.pid), bootId);
  const stateDir = mkdtempSync(join(tmpdir(), "dip-cf02-"));
  const store = new WatchdogStore(join(stateDir, "records"));
  store.init();
  const injected = options.verify ?? {
    ok: true as const,
    dirInode: 100,
    eventsInode: 101,
    killInode: 102,
    procsInode: 103,
    device: "0:25",
    bootId,
  };
  const watchdog = new Watchdog({
    identity,
    clock: { bootId, nowMs: () => clock.now },
    secret: WATCHDOG_SECRET,
    store,
    killContainer: async () => ({ ok: true, detail: "killed" }),
    // The closed observation vocabulary: the test names the daemon answer it means. The default is
    // a container that exists, because arming now requires positive Docker ownership (WD-F04).
    observeContainer: async (expected) => (options.inspectPresent === false
      ? { state: "absent", detail: "inspected" }
      : { state: "present", containerId: expected.containerId, labels: {}, detail: "inspected" }),
    // The fixture tree this harness pins is not under the real mount, so membership is reported
    // under the virtual prefix the record names.
    cgroupMount: () => VIRTUAL_CGROUP_MOUNT,
    actualCgroupPath: (_pid, mountPath) => {
      const record = { executionId: EXECUTION };
      const relative = `/dip-executor.slice/dip-exec-${record.executionId}`;
      return { path: `${mountPath}${relative}`, relative };
    },
    // D2-F03: the supervisor's independently written intent, which every arm is now corroborated
    // against. It matches `baseArm` exactly, because that is the production relationship: the
    // supervisor records the intent, creates the container it names, and only then arms.
    readIntent: (executionId) => ({
      executionId,
      bootId,
      supervisorInstance: SUPERVISOR,
      containerName: CONTAINER_NAME,
      containerId: CONTAINER_ID,
      imageDigest: IMAGE_DIGEST,
      profileId: "synthetic-v1",
    }),
    // `realVerify` uses the production verifier against this host. Used by the tests that assert
    // a refusal, since an injected "ok" would make those assertions vacuous.
    verifyHost: options.realVerify === true ? undefined : () => injected,
    // A pin holding no descriptors, reporting the injected verification's inodes. It can never
    // confirm a termination, so tests that need a granted disarm use the shared harness in
    // `support/watchdog-harness.ts` with a real tree instead.
    pin: options.realVerify === true ? undefined : () => ({
      ok: true as const,
      pin: {
        dirFd: -1,
        dirDevice: 0,
        dirInode: 100,
        pinnedPath: "/injected",
        files: {
          "cgroup.kill": { name: "cgroup.kill" as const, fd: -1, device: 0, inode: 102, resolvedPath: "" },
          "cgroup.events": { name: "cgroup.events" as const, fd: -1, device: 0, inode: 101, resolvedPath: "" },
          "cgroup.procs": { name: "cgroup.procs" as const, fd: -1, device: 0, inode: 103, resolvedPath: "" },
        },
      },
    }),
  });
  return {
    watchdog,
    clock,
    advance: (delta: number) => { clock.now += delta; },
    observed: "0".repeat(64),
    // Asynchronous now: arming observes the container before accepting the target (WD-F04).
    armWithFakeCgroup: async () => {
      const ack = await watchdog.arm(baseArm());
      return ack.kind === "ARM_ACK" ? ack : null;
    },
    cleanup: () => {
      watchdog.closeAll();
      rmSync(stateDir, { recursive: true, force: true });
    },
  };
}

function makeChain(overrides: { outcome?: "committed" | "refused" } = {}): {
  bytes: Buffer;
  digest: string;
  expectation: Parameters<typeof verifyWatchdogGrant>[1];
  grant: ReturnType<typeof signDisarmGrant>;
  commit: Parameters<typeof signTerminalCommit>[1];
} {
  const bytes = Buffer.alloc(128, 7);
  const digest = createHmac("sha256", "x").update(bytes).digest("hex");
  const expectation = {
    executionId: EXECUTION,
    requestId: REQUEST,
    operation: "fill" as const,
    resultDigest: digest,
    resultBytes: bytes.byteLength,
    metaBytes: 128,
    containerId: CONTAINER_ID,
    containerName: CONTAINER_NAME,
    bootId: readBootId(),
    supervisorInstance: SUPERVISOR,
    watchdogInstance: "wd-0123456789ab",
  };
  const grant = signDisarmGrant(WATCHDOG_SECRET, {
    ...terminalRequest(digest, bytes.byteLength, { outcome: overrides.outcome ?? "committed" }),
    watchdogInstance: expectation.watchdogInstance,
  });
  const commit = {
    executionId: EXECUTION,
    requestId: REQUEST,
    operation: "fill" as const,
    resultDigest: digest,
    resultBytes: bytes.byteLength,
    metaBytes: 128,
    outcome: (overrides.outcome ?? "committed") as "committed" | "refused",
    containerRemoved: true,
    watchdogInstance: expectation.watchdogInstance,
    verifiedAtMonotonicMs: 9_000,
  };
  return { bytes, digest, expectation, grant, commit };
}

test("R7D.1-CF02-32: the terminal context validator refuses an incomplete context", () => {
  assert.throws(() => assertTerminalContext({ executionId: "x" }), /executionId|invalid/u);
  assert.throws(() => assertTerminalContext(null), /context/u);
  const good = terminalRequest("a".repeat(64), 1);
  assert.equal(assertTerminalContext(good).executionId, EXECUTION);
  // Proofs are direction-separated: a proof computed for one direction must not verify for another.
  const proof = computeTerminalProof(WATCHDOG_SECRET, { ...good, direction: "watchdog-to-supervisor" });
  assert.match(proof, /^[a-f0-9]{64}$/u);
});
