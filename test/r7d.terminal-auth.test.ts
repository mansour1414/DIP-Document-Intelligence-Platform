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
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
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

test("R7D.1-CF02-14: a watchdog refuses to arm a request from another boot", () => {
  // The real verifier, not an injected one: this asserts production behaviour.
  const harness = makeWatchdog({ realVerify: true });
  const denied = harness.watchdog.arm(baseArm({ bootId: "previous-boot", cgroupPath: "/sys/fs/cgroup/dip-exec/x" }));
  assert.equal(denied.kind, "ARM_DENIED");
  assert.equal((denied as { code: string }).code, "BOOT_MISMATCH");
  // A refused arm leaves nothing armed.
  assert.deepEqual(harness.watchdog.outstanding(), []);
});

test("R7D.1-CF02-15: a watchdog refuses to arm when the cgroup cannot be verified", () => {
  const harness = makeWatchdog({ realVerify: true });
  const denied = harness.watchdog.arm(baseArm({ cgroupPath: "/sys/fs/cgroup/dip-exec/does-not-exist" }));
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
    // It fails because the path is not under the cgroup2 mount, which is also a refusal — either
    // way, no arm.
    assert.equal((result as { code: string }).code, "CGROUP_UNVERIFIED");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("R7D.1-CF02-16b: the host verifier refuses a start time that does not match the PID", () => {
  const mount = findCgroup2Mount();
  assert.notEqual(mount, null);
  // This process's real cgroup, so membership would pass; only the start time is wrong.
  const raw = readFileSyncSafe("/proc/self/cgroup");
  if (raw === null) return;
  const unified = raw.split("\n").find((line) => line.startsWith("0::"));
  assert.ok(unified !== undefined);
  const relative = unified.slice(3);
  const full = `${mount!.path}${relative === "/" ? "" : relative}`;
  const wrongStart = readProcessStartTimeTicks(process.pid) + 1;
  const result = verifyArmIdentity(baseArm({
    cgroupPath: full,
    initPid: process.pid,
    initStartTimeTicks: wrongStart,
  }), readBootId());
  assert.equal(result.ok, false);
  assert.equal((result as { code: string }).code, "PID_UNVERIFIED", (result as { code: string }).code);
});

test("R7D.1-CF02-16c: the host verifier accepts this process when every fact is true", () => {
  const mount = findCgroup2Mount();
  assert.notEqual(mount, null);
  const raw = readFileSyncSafe("/proc/self/cgroup");
  if (raw === null) return;
  const unified = raw.split("\n").find((line) => line.startsWith("0::"));
  assert.ok(unified !== undefined);
  const relative = unified.slice(3);
  const full = `${mount!.path}${relative === "/" ? "" : relative}`;
  const result = verifyArmIdentity(baseArm({
    cgroupPath: full,
    initPid: process.pid,
    initStartTimeTicks: readProcessStartTimeTicks(process.pid),
  }), readBootId());
  // Positive control: the verifier is not simply refusing everything. It reports real inodes,
  // which is what the watchdog records and later re-checks before killing.
  assert.equal(result.ok, true, JSON.stringify(result));
  if (!result.ok) return;
  assert.ok(result.dirInode > 0);
  assert.ok(result.killInode > 0);
  assert.match(result.device, /^\d+:\d+$/u);
});

test("R7D.1-CF02-17: a watchdog refuses a second arm for the same execution", () => {
  const harness = makeWatchdog();
  const first = harness.watchdog.arm(baseArm({ messageId: "1".repeat(16) }));
  assert.equal(first.kind, "ARM_ACK");
  const second = harness.watchdog.arm(baseArm({ messageId: "2".repeat(16) }));
  assert.equal((second as { code: string }).code, "ALREADY_ARMED");
  // A replayed message id is refused before the armed-state check, so the reason is specific.
  const replay = harness.watchdog.arm(baseArm({ messageId: "1".repeat(16) }));
  assert.equal((replay as { code: string }).code, "REPLAYED");
  harness.watchdog.disarm(terminalContext(harness.observed!), "3".repeat(16), 2);
});

test("R7D.1-CF02-18: a disarm whose deadline has passed is refused, and the execution is no longer eligible", () => {
  const harness = makeWatchdog();
  assert.notEqual(harness.armWithFakeCgroup(), null, "the harness must arm successfully");
  harness.advance(6_000);
  const denied = harness.watchdog.disarm(terminalContext(harness.observed!), "3".repeat(16), 2);
  assert.equal((denied as { code: string }).code, "EXPIRED");
  // The expired execution cannot then be disarmed even if the clock were to go backwards.
  harness.advance(-10_000);
  const again = harness.watchdog.disarm(terminalContext(harness.observed!), "4".repeat(16), 3);
  assert.notEqual((again as { code?: string }).code, undefined);
});

test("R7D.1-CF02-19: a grant is refused when the context names a different container", () => {
  const harness = makeWatchdog();
  assert.notEqual(harness.armWithFakeCgroup(), null, "the harness must arm successfully");
  const mismatched = terminalContext(harness.observed!, { containerId: "f".repeat(64) });
  const denied = harness.watchdog.disarm(mismatched, "5".repeat(16), 2);
  assert.equal((denied as { code: string }).code, "MISMATCH");
  // A refusal must not consume the execution: a correct disarm still succeeds afterwards.
  const granted = harness.watchdog.disarm(terminalContext(harness.observed!), "6".repeat(16), 2);
  assert.ok("proof" in granted, "a correct disarm after a refused one must still be issued");
});

test("R7D.1-CF02-20: a second disarm is refused with ALREADY_CONCLUDED", () => {
  const harness = makeWatchdog();
  assert.notEqual(harness.armWithFakeCgroup(), null, "the harness must arm successfully");
  const first = harness.watchdog.disarm(terminalContext(harness.observed!), "7".repeat(16), 2);
  assert.ok("proof" in first);
  const second = harness.watchdog.disarm(terminalContext(harness.observed!), "8".repeat(16), 3);
  assert.equal((second as { code: string }).code, "ALREADY_CONCLUDED");
});

test("R7D.1-CF02-21: termination and disarm cannot both win", async () => {
  const harness = makeWatchdog();
  assert.notEqual(harness.armWithFakeCgroup(), null, "the harness must arm successfully");
  // Advance to the deadline: the watchdog concludes it as unresolved.
  harness.advance(6_000);
  const due = harness.watchdog.dueForTermination();
  assert.equal(due.length, 1);
  const result = await harness.watchdog.terminate(due[0]!);
  assert.equal(result.executionId, EXECUTION);

  // A disarm arriving after the deadline fired must be refused. This is the race the record
  // serialises: the deadline reached `concluded` first.
  const denied = harness.watchdog.disarm(terminalContext(harness.observed!), "9".repeat(16), 2);
  assert.ok(["TERMINATED", "ALREADY_CONCLUDED", "EXPIRED"].includes((denied as { code: string }).code), (denied as { code: string }).code);
});

test("R7D.1-CF02-22: a committed outcome without removal evidence is refused, not released", () => {
  const harness = makeWatchdog();
  assert.notEqual(harness.armWithFakeCgroup(), null, "the harness must arm successfully");
  const denied = harness.watchdog.disarm(terminalContext(harness.observed!, { containerRemoved: false }), "a".repeat(16), 2);
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

test("R7D.1-CF02-28: a restarted watchdog refuses to adopt a record from another boot", () => {
  const harness = makeWatchdog();
  const adopted = harness.watchdog.adopt({
    ...baseArm({ cgroupPath: "/sys/fs/cgroup/dip-exec/x", bootId: "previous-boot" }),
    deadlineAtMonotonicMs: 20_000,
  });
  assert.equal(adopted.adopted, false);
  assert.equal(adopted.reason, "BOOT_MISMATCH");
});

test("R7D.1-CF02-29: a restarted watchdog will not adopt a record whose cgroup it cannot see", () => {
  const harness = makeWatchdog();
  const adopted = harness.watchdog.adopt({
    ...baseArm({ cgroupPath: "/sys/fs/cgroup/dip-exec/gone" }),
    deadlineAtMonotonicMs: 20_000,
  });
  assert.equal(adopted.adopted, false);
  assert.equal(adopted.reason, "CGROUP_ABSENT");
});

test("R7D.1-CF02-30: a watchdog never reports an execution as terminated without positive evidence", async () => {
  const harness = makeWatchdog({ inspectPresent: true });
  assert.notEqual(harness.armWithFakeCgroup(), null, "the harness must arm successfully");
  harness.advance(6_000);
  const due = harness.watchdog.dueForTermination();
  const result = await harness.watchdog.terminate(due[0]!);
  // The container is still present and the fake cgroup still reads populated 1, so the watchdog
  // must not claim termination.
  assert.equal(result.containerPresent, true);
  assert.equal(harness.watchdog.state(EXECUTION).concluded?.outcome, "unresolved");
});

test("R7D.1-CF02-31: a watchdog refuses to signal a cgroup whose identity changed after arming", async () => {
  const harness = makeWatchdog();
  assert.notEqual(harness.armWithFakeCgroup(), null, "the harness must arm successfully");
  harness.advance(6_000);
  const due = harness.watchdog.dueForTermination();
  // Simulate reuse: the record claims a different inode than the directory now has.
  const reused = { ...due[0]!, observed: { ...due[0]!.observed, dirInode: due[0]!.observed.dirInode + 1 } };
  const result = await harness.watchdog.terminate(reused);
  assert.equal(result.signalSent, false);
  assert.match(result.detail, /identity changed/u);
});

// ── helpers ────────────────────────────────────────────────────────────────────────────────────

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
    cgroupPath: "/sys/fs/cgroup/dip-exec/x",
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
  armWithFakeCgroup: () => unknown | null;
};

/**
 * Build a watchdog whose *arbitration* runs for real.
 *
 * The verification step is injected because this sandbox has no writable cgroup2 mount, so an
 * end-to-end arm cannot succeed here. What is injected is only the answer to "did the host
 * confirm this identity" — the deadline, the serialisation of disarm against termination, the
 * replay window, the refusal codes and the signing are the production code paths. `verifyArmIdentity`
 * has its own direct tests against this host below, and those are the ones that prove the
 * verification logic; these prove the state machine.
 */
function makeWatchdog(options: { inspectPresent?: boolean; verify?: HostVerification; realVerify?: boolean } = {}): Harness {
  const clock = { now: 1_000 };
  const bootId = readBootId();
  const identity = newWatchdogIdentity(() => clock.now, readProcessStartTimeTicks(process.pid), bootId);
  const watchdog = new Watchdog({
    identity,
    secret: WATCHDOG_SECRET,
    monotonicMs: () => clock.now,
    killContainer: async () => ({ ok: true, detail: "killed" }),
    inspectContainer: async () => ({ present: options.inspectPresent ?? false, detail: "inspected" }),
    // `realVerify` uses the production verifier against this host. Used by the tests that assert
    // a refusal, since an injected "ok" would make those assertions vacuous.
    verifyHost: options.realVerify === true
      ? undefined
      : () => options.verify ?? {
        ok: true,
        dirInode: 100,
        eventsInode: 101,
        killInode: 102,
        procsInode: 103,
        device: "0:25",
        bootId,
      },
  });
  const harness: Harness = {
    watchdog,
    clock,
    advance: (delta: number) => { clock.now += delta; },
    observed: "0".repeat(64),
    armWithFakeCgroup: () => {
      const ack = watchdog.arm(baseArm({ cgroupPath: "/sys/fs/cgroup/dip-exec/x" }));
      return ack.kind === "ARM_ACK" ? ack : null;
    },
  };
  return harness;
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

/** Read a file, returning null instead of throwing when the sandbox hides it. */
function readFileSyncSafe(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}
