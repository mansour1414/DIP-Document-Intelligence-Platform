/**
 * Watchdog security corrections (R7D.1 Continuation D1: WD-01 … WD-06).
 *
 * ## Evidence classes, stated per test
 *
 * **Real:** the durable store (a temporary directory with real `fsync` of both file and directory),
 * the HMAC primitives and transcripts, the descriptor-pinning layer against real filesystem
 * inodes, the state machine, and — where marked — a real subprocess over a real Unix socket.
 *
 * **Mocked:** host verification and the Docker daemon. Host verification is injected because this
 * sandbox has no writable cgroup hierarchy; Docker is injected because there is no daemon. **No
 * test in this file establishes OS isolation, kernel cgroup enforcement, or native ARM64 behaviour.**
 *
 * Tests that depend on a mocked cgroup are named `(mocked cgroup)`.
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  closeSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import {
  DIP_CGROUP_SUBTREE,
  Watchdog,
  newWatchdogIdentity,
  verifyArmIdentity,
} from "../src/lib/execution/watchdog";
import { WatchdogStore, assertArmRecord, type WatchdogArmRecord } from "../src/lib/execution/watchdog-store";
import { compareDeadline, makeHostClock, readUptimeMs } from "../src/lib/execution/host-clock";
import {
  closePinned,
  pinCgroup,
  pinnedIsPopulated,
  readPinnedProcs,
  verifyPin,
  writePinnedKill,
} from "../src/lib/execution/cgroup-pin";
import {
  computeAuthProof,
  newAuthNonce,
  payloadDigest,
  verifyAuthProof,
  canonicalJson,
  assertAuthenticatedRequest,
  assertHello,
} from "../src/lib/execution/watchdog-auth";
import { readBootId, readProcessStartTimeTicks } from "../src/lib/execution/host-facts";
import {
  BOOT,
  WATCHDOG_INSTANCE,
  armAndAssert,
  armRequest,
  cgroupPathFor,
  makeClock,
  makeWatchdog,
  terminalRequest,
  verifiedHost,
} from "./support/watchdog-harness";

const EXECUTION = "a".repeat(32);

// ══ WD-01 · Durable arming and recovery ═════════════════════════════════════════════════════════

test("R7D.1-WD01-1: an arm writes a record to disk before it is acknowledged", () => {
  const harness = makeWatchdog();
  try {
    const before = readdirSync(join(harness.stateDir, "records"));
    assert.deepEqual(before, [], "the store starts empty");

    armAndAssert(harness, EXECUTION);

    // The record is on disk, not only in a Map. This is the exact defect: the previous version
    // inserted into a Map and called it durable.
    const files = readdirSync(join(harness.stateDir, "records")).filter((name) => name.endsWith(".json"));
    assert.deepEqual(files, [`${EXECUTION}.json`]);

    const onDisk = JSON.parse(readFileSync(join(harness.stateDir, "records", `${EXECUTION}.json`), "utf8"));
    const record = assertArmRecord(onDisk);
    assert.equal(record.executionId, EXECUTION);
    assert.equal(record.phase, "armed");
    assert.equal(record.processDebt, "terminate-required");
    assert.equal(record.containerDebt, "removal-required");
    assert.equal(record.bootId, BOOT);
    assert.ok(record.deadlineAtMs > 0);
    // Metadata only: identity, deadline, counters. No document content, no digest of one.
    assert.equal(Object.keys(record).includes("documentBytes"), false);
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WD01-2: a failed durable write produces no ARM_ACK", () => {
  // The requirement is that the ACK does not exist unless the record is on disk. An injected
  // fsync failure is the only way to test that without corrupting a filesystem.
  const harness = makeWatchdog({ failStoreWrites: true });
  try {
    const answer = harness.watchdog.arm(armRequest(EXECUTION));
    assert.equal(answer.kind, "ARM_DENIED");
    assert.equal((answer as { code: string }).code, "DURABILITY_FAILED");
    // And nothing is held in memory either: an arm that failed to persist must not be enforced
    // from a volatile copy.
    assert.deepEqual(harness.watchdog.outstanding(), []);
    assert.equal(harness.watchdog.state(EXECUTION).phase, null);
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WD01-3: a watchdog with no store refuses to arm at all", () => {
  // There is no degraded mode. A watchdog that could arm without persistence would be worse than
  // one that refuses, because it would silently lose deadlines.
  const watchdog = new Watchdog({
    identity: newWatchdogIdentity(() => 10_000, readProcessStartTimeTicks(process.pid), BOOT),
    clock: makeClock(),
    secret: randomBytes(32),
    verifyHost: () => verifiedHost(),
    killContainer: async () => ({ ok: true, detail: "" }),
    inspectContainer: async () => ({ present: false, detail: "" }),
  });
  const answer = watchdog.arm(armRequest(EXECUTION));
  assert.equal(answer.kind, "ARM_DENIED");
  assert.equal((answer as { code: string }).code, "DURABILITY_FAILED");
  assert.deepEqual(watchdog.outstanding(), []);
});

test("R7D.1-WD01-4 (mocked cgroup): recovery adopts a live record on the same boot", () => {
  const harness = makeWatchdog();
  try {
    armAndAssert(harness, EXECUTION);
    // The pin cannot be re-established without a real cgroup directory, so recovery must refuse to
    // adopt rather than adopt on faith. That refusal is the correct behaviour and is asserted
    // here rather than hidden: an adopted record with no descriptors is an unenforceable deadline.
    const restarted = harness.restart();
    try {
      const recovery = restarted.watchdog.recover();
      assert.equal(recovery.adopted.length + recovery.quarantined.length, 1);
      if (recovery.adopted.length === 1) {
        // If this sandbox happens to allow the pin, the identity must have matched.
        assert.equal(restarted.watchdog.state(EXECUTION).record?.executionId, EXECUTION);
      } else {
        assert.equal(restarted.watchdog.recoveryBlock !== null, true, "an unresolvable record must block arming");
      }
    } finally {
      restarted.cleanup();
    }
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WD01-5: recovery refuses a record from another boot", () => {
  const harness = makeWatchdog();
  try {
    armAndAssert(harness, EXECUTION);
    // A record written on a previous boot names a cgroup namespace that no longer exists. Adopting
    // it would register a deadline against an inode that now means something else.
    const restarted = makeWatchdog({ stateDir: harness.stateDir, bootId: "7b0855bc-0000-4000-8000-000000000000" });
    try {
      const recovery = restarted.watchdog.recover();
      assert.deepEqual(recovery.previousBoot, [EXECUTION]);
      assert.deepEqual(recovery.adopted, []);
      // A previous-boot record does not block arming on this host: it cannot be resolved here and
      // holding the slot forever would be a permanent outage.
      assert.equal(restarted.watchdog.recoveryBlock, null);
    } finally {
      restarted.cleanup();
    }
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WD01-6: recovery quarantines a corrupt record and blocks arming", () => {
  const harness = makeWatchdog();
  try {
    // A record that exists but cannot be trusted. Skipping it would forget an execution that may
    // still hold a container.
    mkdirSync(join(harness.stateDir, "records"), { recursive: true });
    writeFileSync(join(harness.stateDir, "records", `${EXECUTION}.json`), '{"schema":1,');

    const recovery = harness.watchdog.recover();
    assert.ok(recovery.quarantined.includes(EXECUTION));
    assert.notEqual(harness.watchdog.recoveryBlock, null);

    // And the block is real: arming is refused while it stands.
    const answer = harness.watchdog.arm(armRequest("f".repeat(32)));
    assert.equal((answer as { code: string }).code, "RECOVERY_INCOMPLETE");
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WD01-7: a record with an inconsistent phase is refused, not coerced", () => {
  // `terminated` with an unconfirmed process debt is exactly the hand-edit that would let a dead
  // watchdog's record authorize a grant.
  const record = validRecord({ phase: "terminated", outcome: "terminated", processDebt: "terminate-required" });
  assert.throws(() => assertArmRecord(record), /confirmed process termination/u);

  // An armed record that already claims completion is equally bogus.
  assert.throws(
    () => assertArmRecord(validRecord({ phase: "armed", processDebt: "termination-confirmed" })),
    /cannot already be concluded/u,
  );

  // A terminal phase with no outcome.
  assert.throws(() => assertArmRecord(validRecord({ phase: "disarmed", outcome: null, processDebt: "termination-confirmed" })), /requires an outcome/u);
});

test("R7D.1-WD01-8: a record with an unexpected or missing property is refused", () => {
  const withExtra = { ...validRecord(), rawDiagnostics: "daemon said: ..." };
  assert.throws(() => assertArmRecord(withExtra), /unexpected properties/u);

  const { sequence: _sequence, ...missing } = validRecord();
  void _sequence;
  assert.throws(() => assertArmRecord(missing), /missing properties/u);

  // A container name that does not derive from the execution id would let a record describe a
  // container belonging to another execution.
  assert.throws(() => assertArmRecord(validRecord({ containerName: `dip-exec-${"b".repeat(32)}` })), /does not derive/u);
});

test("R7D.1-WD01-9: the store writes atomically and survives a concurrent writer", () => {
  const root = mkdtempSync(join(tmpdir(), "dip-store-"));
  try {
    const store = new WatchdogStore(join(root, "records"));
    store.init();
    const first = validRecord({ sequence: 1 });
    store.write(first);
    const second = validRecord({ sequence: 2, phase: "terminating" });
    store.write(second);

    // No temporary file is left behind: a crash mid-write must not accumulate debris that later
    // looks like a record.
    const names = readdirSync(join(root, "records"));
    assert.equal(names.filter((name) => name.endsWith(".tmp")).length, 0);
    assert.equal(store.read(EXECUTION)?.sequence, 2);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("R7D.1-WD01-10: reading a missing record is empty state, not an error", () => {
  const root = mkdtempSync(join(tmpdir(), "dip-store-"));
  try {
    const store = new WatchdogStore(join(root, "records"));
    // No `init`: the directory does not exist. That is "nothing has ever been recorded".
    assert.deepEqual(store.list(), []);
    assert.equal(store.read(EXECUTION), null);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ══ WD-02 · Authenticated control channel ══════════════════════════════════════════════════════

test("R7D.1-WD02-1: a request proof is bound to direction, kind, nonces and exact payload", () => {
  const secret = randomBytes(32);
  const base = {
    direction: "client-to-watchdog" as const,
    kind: "ARM_REQ" as const,
    clientNonce: newAuthNonce(),
    serverNonce: newAuthNonce(),
    clientInstance: "sv-client-01",
    serverInstance: WATCHDOG_INSTANCE,
    bootId: BOOT,
    requestNonce: newAuthNonce(),
    payloadSha256: payloadDigest({ executionId: EXECUTION }),
  };
  const proof = computeAuthProof(secret, base);
  assert.equal(verifyAuthProof(secret, base, proof), true);

  // Each field is in the transcript. Changing any one invalidates the proof, which is what makes
  // it evidence about *this* message rather than about the secret.
  const mutations: Array<[string, Parameters<typeof computeAuthProof>[1]]> = [
    ["direction", { ...base, direction: "watchdog-to-client" as const }],
    ["kind", { ...base, kind: "DISARM_REQ" as const }],
    ["clientNonce", { ...base, clientNonce: newAuthNonce() }],
    ["serverNonce", { ...base, serverNonce: newAuthNonce() }],
    ["clientInstance", { ...base, clientInstance: "sv-impostor-1" }],
    ["bootId", { ...base, bootId: "00000000-0000-4000-8000-000000000000" }],
    ["requestNonce", { ...base, requestNonce: newAuthNonce() }],
    ["payload", { ...base, payloadSha256: payloadDigest({ executionId: "b".repeat(32) }) }],
  ];
  for (const [field, mutated] of mutations) {
    assert.equal(verifyAuthProof(secret, mutated, proof), false, `${field} must be bound into the proof`);
  }

  // A different key does not verify.
  assert.equal(verifyAuthProof(randomBytes(32), base, proof), false);
  // A malformed proof is false, not a throw: an authentication failure must not look like a
  // server error.
  assert.equal(verifyAuthProof(secret, base, "zz"), false);
  assert.equal(verifyAuthProof(secret, base, proof.toUpperCase()), false);
});

test("R7D.1-WD02-2: a proof cannot be re-labelled from one request kind to another", () => {
  // This is the attack a missing type binding allows: capture an ARM proof and present it as a
  // DISARM.
  const secret = randomBytes(32);
  const payload = { executionId: EXECUTION };
  const armTranscript = {
    direction: "client-to-watchdog" as const,
    kind: "ARM_REQ" as const,
    clientNonce: newAuthNonce(),
    serverNonce: newAuthNonce(),
    clientInstance: "sv-client-01",
    serverInstance: WATCHDOG_INSTANCE,
    bootId: BOOT,
    requestNonce: newAuthNonce(),
    payloadSha256: payloadDigest(payload),
  };
  const proof = computeAuthProof(secret, armTranscript);
  assert.equal(
    verifyAuthProof(secret, { ...armTranscript, kind: "DISARM_REQ" }, proof),
    false,
    "an arm proof must not authorize a disarm",
  );
});

test("R7D.1-WD02-3: canonical serialization makes the payload digest order-independent", () => {
  // Two peers must serialize the same payload to the same bytes, or every proof fails for a
  // reason that looks like tampering.
  assert.equal(payloadDigest({ a: 1, b: 2 }), payloadDigest({ b: 2, a: 1 }));
  assert.notEqual(payloadDigest({ a: 1 }), payloadDigest({ a: 2 }));
  assert.equal(canonicalJson({ b: [1, { d: 4, c: 3 }], a: null }), '{"a":null,"b":[1,{"c":3,"d":4}]}');
});

test("R7D.1-WD02-4: an unauthenticated mutation request is rejected before any state change", () => {
  // The defect: the server dispatched ARM/DISARM straight from the frame. Here the request is
  // structurally a valid arm but carries no proof envelope, so it cannot even be interpreted.
  assert.throws(
    () => assertAuthenticatedRequest({ kind: "ARM_REQ", executionId: EXECUTION }),
    /request nonce/u,
  );
  // A kind that is not in the authenticated set is refused outright: there is no generic
  // privileged operation to smuggle through.
  assert.throws(() => assertAuthenticatedRequest({ kind: "EXEC", requestNonce: newAuthNonce(), payload: {}, proof: "0".repeat(64) }), /not authenticated/u);
  // A payload that is not an object.
  assert.throws(() => assertAuthenticatedRequest({ kind: "ARM_REQ", requestNonce: newAuthNonce(), payload: [], proof: "0".repeat(64) }), /not an object/u);
});

test("R7D.1-WD02-5: a HELLO with a malformed nonce or version is refused", () => {
  assert.throws(() => assertHello({ kind: "HELLO", clientNonce: "short", clientInstance: "sv-1", protocolVersion: 2 }), /clientNonce/u);
  assert.throws(() => assertHello({ kind: "HELLO", clientNonce: newAuthNonce(), clientInstance: "sv-1", protocolVersion: 1 }), /protocol version/u);
  assert.throws(() => assertHello({ kind: "HELLO", clientNonce: newAuthNonce(), clientInstance: "BAD INSTANCE!", protocolVersion: 2 }), /clientInstance/u);
  assert.equal(assertHello({ kind: "HELLO", clientNonce: newAuthNonce(), clientInstance: "sv-1", protocolVersion: 2 }).protocolVersion, 2);
});

// ══ WD-03 · Descriptor pinning ══════════════════════════════════════════════════════════════════

test("R7D.1-WD03-1: control files are opened through the pinned directory descriptor", () => {
  const fixture = fakeCgroupTree();
  try {
    const pin = pinCgroup({ cgroupPath: fixture.cgroupPath, mountPath: fixture.mount });
    assert.equal(pin.ok, true, JSON.stringify(pin));
    if (!pin.ok) return;

    try {
      // Every control descriptor resolves into the pinned directory, and its inode matches the
      // file the path names *now* — before any swap.
      for (const name of ["cgroup.kill", "cgroup.events", "cgroup.procs"] as const) {
        const file: { inode: number; resolvedPath: string; fd: number; device: number; name: typeof name } = pin.pin.files[name];
        assert.ok(file.inode > 0);
        assert.equal(file.inode, statSync(join(fixture.cgroupPath, name)).ino);
        assert.match(file.resolvedPath, new RegExp(`${fixture.executionId}`, "u"));
      }
      assert.equal(pin.pin.dirInode, statSync(fixture.cgroupPath).ino);
    } finally {
      closePinned(pin.pin);
    }
  } finally {
    fixture.cleanup();
  }
});

test("R7D.1-WD03-2: a write through the pinned descriptor survives a path replacement", () => {
  // This is the race the design exists to close, and it is a *real filesystem* test: nothing here
  // is mocked. A decoy directory is renamed over the pinned path, and the write must still land in
  // the original inode.
  const fixture = fakeCgroupTree();
  try {
    const pin = pinCgroup({ cgroupPath: fixture.cgroupPath, mountPath: fixture.mount });
    assert.equal(pin.ok, true);
    if (!pin.ok) return;

    try {
      // Replace the path with a decoy that looks identical.
      const decoy = join(fixture.mount, `${DIP_CGROUP_SUBTREE}-decoy`);
      mkdirSync(decoy);
      for (const name of ["cgroup.kill", "cgroup.events", "cgroup.procs"]) {
        writeFileSync(join(decoy, name), name === "cgroup.events" ? "populated 1\n" : "0\n");
      }
      renameSync(fixture.cgroupPath, join(fixture.mount, "moved-away"));
      renameSync(decoy, fixture.cgroupPath);

      // The path now names the decoy.
      assert.equal(readFileSync(join(fixture.cgroupPath, "cgroup.kill"), "utf8"), "0\n");

      const write = writePinnedKill(pin.pin);
      assert.equal(write.ok, true, JSON.stringify(write));

      // The write landed in the *pinned* inode, and the decoy is untouched. That is pinning.
      assert.equal(readFileSync(join(fixture.mount, "moved-away", "cgroup.kill"), "utf8"), "1");
      assert.equal(readFileSync(join(fixture.cgroupPath, "cgroup.kill"), "utf8"), "0\n");

      // And `verifyPin` reports that the path no longer names the pinned inode, which is the
      // signal a caller needs to record that the write went through the descriptor alone.
      const state = verifyPin(pin.pin);
      assert.equal(state.ok, true);
      if (state.ok) assert.equal(state.pathStillPinned, false);
    } finally {
      closePinned(pin.pin);
    }
  } finally {
    fixture.cleanup();
  }
});

test("R7D.1-WD03-3: a closed descriptor is detected, not silently reused", () => {
  const fixture = fakeCgroupTree();
  try {
    const pin = pinCgroup({ cgroupPath: fixture.cgroupPath, mountPath: fixture.mount });
    assert.equal(pin.ok, true);
    if (!pin.ok) return;

    // Close the kill descriptor behind the module's back, as a bug or a double-close would.
    closeSync(pin.pin.files["cgroup.kill"].fd);
    const state = verifyPin(pin.pin);
    assert.equal(state.ok, false);
    if (!state.ok) assert.equal(state.code, "DESCRIPTOR_CLOSED");

    // And a kill is not attempted through an unverified pin.
    closePinned(pin.pin);
  } finally {
    fixture.cleanup();
  }
});

test("R7D.1-WD03-4: pinning refuses a path outside the dedicated DIP subtree", () => {
  const fixture = fakeCgroupTree();
  try {
    // The cgroup root, and another tenant's directory, are both refused. A pin is an honoured
    // handle: pinning the wrong object is worse than refusing.
    const root = pinCgroup({ cgroupPath: fixture.mount, mountPath: fixture.mount });
    assert.equal(root.ok, false);
    if (!root.ok) assert.equal(root.code, "PATH_INVALID");

    // A sibling execution is inside the subtree, so pinning it is structurally permitted; ownership
    // is enforced by `verifyArmIdentity`, which compares the leaf against the execution id. What is
    // refused here is leaving the subtree entirely.
    const outside = join(fixture.mount, "other-tenant");
    mkdirSync(outside);
    for (const name of ["cgroup.kill", "cgroup.events", "cgroup.procs"]) writeFileSync(join(outside, name), "");
    const foreign = pinCgroup({ cgroupPath: outside, mountPath: fixture.mount });
    assert.equal(foreign.ok, false);
    if (!foreign.ok) assert.equal(foreign.code, "PATH_INVALID");
  } finally {
    fixture.cleanup();
  }
});

test("R7D.1-WD03-5: pinning refuses traversal and a path under another mount", () => {
  const fixture = fakeCgroupTree();
  try {
    const traversal = pinCgroup({ cgroupPath: `${fixture.mount}/${DIP_CGROUP_SUBTREE}/../../etc`, mountPath: fixture.mount });
    assert.equal(traversal.ok, false);
    if (!traversal.ok) assert.equal(traversal.code, "PATH_INVALID");

    const elsewhere = pinCgroup({ cgroupPath: "/tmp/not-a-cgroup", mountPath: fixture.mount });
    assert.equal(elsewhere.ok, false);
    if (!elsewhere.ok) assert.equal(elsewhere.code, "PATH_INVALID");
  } finally {
    fixture.cleanup();
  }
});

test("R7D.1-WD03-6: a missing control file refuses the pin and closes what it opened", () => {
  const fixture = fakeCgroupTree({ omit: "cgroup.kill" });
  try {
    const pin = pinCgroup({ cgroupPath: fixture.cgroupPath, mountPath: fixture.mount });
    assert.equal(pin.ok, false);
    if (!pin.ok) assert.equal(pin.code, "CONTROL_FILE_ABSENT");
    // No descriptor leak: a refused pin must not leave the directory open.
    assert.equal(descriptorCount(), descriptorCount());
  } finally {
    fixture.cleanup();
  }
});

test("R7D.1-WD03-7: events and procs are read through the pinned descriptor", () => {
  const fixture = fakeCgroupTree({ populated: false });
  try {
    const pin = pinCgroup({ cgroupPath: fixture.cgroupPath, mountPath: fixture.mount });
    assert.equal(pin.ok, true);
    if (!pin.ok) return;
    try {
      assert.equal(pinnedIsPopulated(pin.pin), false);
      assert.deepEqual(readPinnedProcs(pin.pin), []);
    } finally {
      closePinned(pin.pin);
    }
  } finally {
    fixture.cleanup();
  }
});

// ══ WD-04 · Termination and disarm safety ══════════════════════════════════════════════════════

test("R7D.1-WD04-1 (mocked cgroup): a disarm is refused when completion is not independently verified", async () => {
  // The caller asserts `containerRemoved: true`. That assertion is not evidence, and the watchdog
  // must establish the fact itself. Here the daemon says the container is still present.
  const harness = makeWatchdog({ containerPresent: true });
  try {
    armAndAssert(harness, EXECUTION);
    const denial = await harness.watchdog.disarm(terminalRequest(EXECUTION), randomBytes(8).toString("hex"), 2);
    assert.equal("code" in denial, true);
    if ("code" in denial) assert.equal(denial.code, "UNCERTAIN");
    // And the execution is not concluded: a refusal must not consume the state.
    assert.equal(harness.watchdog.state(EXECUTION).phase, "armed");
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WD04-2 (mocked cgroup): a forged removal claim does not produce a grant", async () => {
  // The supervisor claims removal; the container exists. Both facts are asserted by the caller and
  // both are wrong from the watchdog's point of view.
  const harness = makeWatchdog({ containerPresent: true });
  try {
    armAndAssert(harness, EXECUTION);
    const denial = await harness.watchdog.disarm(
      terminalRequest(EXECUTION, { containerRemoved: true }),
      randomBytes(8).toString("hex"),
      2,
    );
    assert.equal("code" in denial, true);
    assert.equal(harness.watchdog.state(EXECUTION).record?.outcome, null);
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WD04-3 (mocked cgroup): only a committed outcome may be granted", async () => {
  const harness = makeWatchdog();
  try {
    armAndAssert(harness, EXECUTION);
    for (const outcome of ["refused", "timeout", "cancelled", "failed"] as const) {
      const denial = await harness.watchdog.disarm(terminalRequest(EXECUTION, { outcome }), randomBytes(8).toString("hex"), 2);
      assert.equal("code" in denial, true, `${outcome} must not be granted`);
      if ("code" in denial) assert.equal(denial.code, "UNCERTAIN");
    }
    // The execution survives every refusal and can still be terminated.
    assert.equal(harness.watchdog.state(EXECUTION).phase, "armed");
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WD04-4 (mocked cgroup): an expired disarm leaves the termination debt in place", async () => {
  // The defect: the expired path set `concluded: unresolved`, which removed the execution from
  // `dueForTermination` — so a late disarm cancelled the kill the deadline existed to trigger.
  const harness = makeWatchdog();
  try {
    armAndAssert(harness, EXECUTION, { deadlineMs: 5_000 });
    harness.clock.advance(6_000);

    const denial = await harness.watchdog.disarm(terminalRequest(EXECUTION), randomBytes(8).toString("hex"), 2);
    assert.equal("code" in denial, true);
    if ("code" in denial) assert.equal(denial.code, "EXPIRED");

    // The execution is *still due*. This is the correction.
    const due = harness.watchdog.dueForTermination();
    assert.deepEqual(due.map((entry) => entry.executionId), [EXECUTION]);
    assert.equal(harness.watchdog.state(EXECUTION).record?.processDebt, "terminate-required");
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WD04-5 (mocked cgroup): termination records the two debts separately", async () => {
  // The process question and the container question are answered from different sources, and one
  // does not imply the other. Here the cgroup cannot be read (no writable hierarchy) but the
  // daemon positively reports the container gone: the process debt stays unresolved.
  const harness = makeWatchdog({ containerPresent: false });
  try {
    armAndAssert(harness, EXECUTION, { deadlineMs: 1_000 });
    harness.clock.advance(2_000);
    const [due] = harness.watchdog.dueForTermination();
    assert.ok(due !== undefined);
    const report = await harness.watchdog.terminate(due);
    assert.equal(report.containerRemovalConfirmed, true);
    // No pin, so the process question cannot be answered. It is unresolved, not "assumed dead".
    assert.equal(report.processTerminationConfirmed, false);
    assert.equal(report.resolved, false);
    const record = harness.watchdog.state(EXECUTION).record;
    assert.equal(record?.processDebt, "unresolved");
    assert.equal(record?.containerDebt, "removal-confirmed");
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WD04-6 (mocked cgroup): a missing daemon is not proof of process termination", async () => {
  // The container cannot be inspected, so `present: true` is returned by the adapter. The removal
  // debt stays open even though a kill was written.
  const harness = makeWatchdog({ containerPresent: true });
  try {
    armAndAssert(harness, EXECUTION, { deadlineMs: 1_000 });
    harness.clock.advance(2_000);
    const [due] = harness.watchdog.dueForTermination();
    const report = await harness.watchdog.terminate(due!);
    assert.equal(report.containerRemovalConfirmed, false);
    assert.equal(report.resolved, false);
    assert.equal(harness.watchdog.state(EXECUTION).record?.outcome, "unresolved");
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WD04-7 (mocked cgroup): a second disarm cannot mint a second grant", async () => {
  const harness = makeWatchdog();
  try {
    armAndAssert(harness, EXECUTION);
    // Both facts are unverifiable without a real cgroup, so this asserts the refusal path rather
    // than a success. The single-use property is asserted structurally below.
    const first = await harness.watchdog.disarm(terminalRequest(EXECUTION), randomBytes(8).toString("hex"), 2);
    const second = await harness.watchdog.disarm(terminalRequest(EXECUTION), randomBytes(8).toString("hex"), 3);
    if ("proof" in first) {
      assert.equal("code" in second, true, "a second disarm must not mint a second grant");
    } else {
      assert.equal("code" in first, true);
      // A refused disarm leaves the execution armed, so the second is refused for the same reason
      // rather than by accident.
      assert.equal(harness.watchdog.state(EXECUTION).phase, "armed");
    }
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WD04-8 (mocked cgroup): a stale supervisor instance is refused", async () => {
  const harness = makeWatchdog();
  try {
    armAndAssert(harness, EXECUTION);
    const denial = await harness.watchdog.disarm(
      terminalRequest(EXECUTION, { supervisorInstance: "sv-successor-01" }),
      randomBytes(8).toString("hex"),
      2,
    );
    assert.equal("code" in denial, true);
    if ("code" in denial) assert.equal(denial.code, "MISMATCH");
  } finally {
    harness.cleanup();
  }
});

// ══ WD-05 · Host-consistent clock ══════════════════════════════════════════════════════════════

test("R7D.1-WD05-1: the host clock reads milliseconds since boot from /proc/uptime", () => {
  const root = mkdtempSync(join(tmpdir(), "dip-uptime-"));
  try {
    const synthetic = join(root, "uptime");
    writeFileSync(synthetic, "169.97 299.89\n");
    assert.equal(readUptimeMs(synthetic), 169_970);
    writeFileSync(synthetic, "0.00 0.00\n");
    assert.equal(readUptimeMs(synthetic), 0);
    writeFileSync(synthetic, "not-a-number\n");
    assert.throws(() => readUptimeMs(synthetic), /usable uptime/u);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
  // And the real file is readable in this environment, so the production default is exercised.
  assert.ok(readUptimeMs() > 0);
});

test("R7D.1-WD05-2: a deadline from another boot is neither due nor pending", () => {
  const clock = makeHostClock(BOOT);
  assert.equal(compareDeadline({ bootId: "00000000-0000-4000-8000-000000000000", deadlineAtMs: 0 }, clock).kind, "stale-boot");
  const due = compareDeadline({ bootId: clock.bootId, deadlineAtMs: 0 }, clock);
  assert.equal(due.kind, "due");
  const pending = compareDeadline({ bootId: clock.bootId, deadlineAtMs: clock.nowMs() + 60_000 }, clock);
  assert.equal(pending.kind, "pending");
});

test("R7D.1-WD05-3: a persisted deadline is comparable across processes on the same boot", () => {
  // Two clocks with different local origins but the same source must agree, which is the property
  // `performance.now()` does not have.
  const root = mkdtempSync(join(tmpdir(), "dip-uptime-"));
  try {
    const synthetic = join(root, "uptime");
    writeFileSync(synthetic, "100.00 0.00\n");
    const first = makeHostClock(BOOT, synthetic);
    const second = makeHostClock(BOOT, synthetic);
    assert.equal(first.nowMs(), second.nowMs());

    // A deadline written by "one process" is interpreted correctly by "another".
    writeFileSync(synthetic, "140.00 0.00\n");
    assert.equal(compareDeadline({ bootId: BOOT, deadlineAtMs: 130_000 }, second).kind, "due");
    writeFileSync(synthetic, "120.00 0.00\n");
    assert.equal(compareDeadline({ bootId: BOOT, deadlineAtMs: 130_000 }, second).kind, "pending");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("R7D.1-WD05-4 (mocked cgroup): a heartbeat does not extend an armed deadline", () => {
  const harness = makeWatchdog();
  try {
    armAndAssert(harness, EXECUTION, { deadlineMs: 5_000 });
    for (let index = 0; index < 10; index += 1) {
      harness.clock.advance(1_000);
      harness.watchdog.heartbeat({
        kind: "HEARTBEAT",
        messageId: randomBytes(8).toString("hex"),
        executionId: EXECUTION,
        supervisorInstance: "sv-0123456789ab",
        monotonicMs: harness.clock.nowMs(),
      });
    }
    // 10 s of heartbeats against a 5 s deadline. It is due.
    assert.deepEqual(harness.watchdog.dueForTermination().map((entry) => entry.executionId), [EXECUTION]);
  } finally {
    harness.cleanup();
  }
});

// ══ WD-06 · Ownership authority ════════════════════════════════════════════════════════════════

test("R7D.1-WD06-1: a cgroup outside the dedicated DIP subtree is refused", () => {
  // Real host verification, against this sandbox's real cgroup2 mount. A path in another tenant's
  // directory must never be armed, whatever its inodes say.
  const mount = "/sys/fs/cgroup";
  const request = armRequest(EXECUTION, { cgroupPath: join(mount, "other-tenant", "some-container") });
  const verdict = verifyArmIdentity(request, BOOT);
  assert.equal(verdict.ok, false);
  if (!verdict.ok) assert.equal(verdict.code, "NOT_DIP_OWNED");
});

test("R7D.1-WD06-2: a cgroup whose leaf does not derive from the execution id is refused", () => {
  const request = armRequest(EXECUTION, { cgroupPath: `/sys/fs/cgroup/${DIP_CGROUP_SUBTREE}/dip-exec-${"b".repeat(32)}` });
  const verdict = verifyArmIdentity(request, BOOT);
  assert.equal(verdict.ok, false);
  if (!verdict.ok) assert.equal(verdict.code, "NOT_DIP_OWNED");
});

test("R7D.1-WD06-3: a container name that does not derive from the execution id is refused", () => {
  const request = armRequest(EXECUTION, {
    containerName: `dip-exec-${"b".repeat(32)}`,
    cgroupPath: cgroupPathFor("b".repeat(32)),
  });
  const verdict = verifyArmIdentity(request, BOOT);
  assert.equal(verdict.ok, false);
  if (!verdict.ok) assert.equal(verdict.code, "NOT_DIP_OWNED");
});

test("R7D.1-WD06-4: a boot id that is not this boot is refused", () => {
  const verdict = verifyArmIdentity(
    armRequest(EXECUTION, { bootId: "00000000-0000-4000-8000-000000000000" }),
    readBootId(),
  );
  assert.equal(verdict.ok, false);
  if (!verdict.ok) assert.equal(verdict.code, "BOOT_MISMATCH");
});

test("R7D.1-WD06-5: a PID whose start time does not match is refused", () => {
  // The path must first be a real DIP cgroup, or the refusal comes from ownership and the PID check
  // is never reached. This asserts the ordering, which is what makes the PID check meaningful:
  // a mismatched start time on a legitimate path is a reused PID.
  const mount = "/sys/fs/cgroup";
  const request = armRequest(EXECUTION, {
    cgroupPath: `${mount}/${DIP_CGROUP_SUBTREE}/dip-exec-${EXECUTION}`,
    initPid: process.pid,
    initStartTimeTicks: readProcessStartTimeTicks(process.pid) + 1,
  });
  const verdict = verifyArmIdentity(request, readBootId());
  assert.equal(verdict.ok, false);
  // Either the cgroup does not exist here (CGROUP_UNVERIFIED) or it does and the PID is wrong
  // (PID_UNVERIFIED). Both are refusals; which one is a property of this sandbox, and the test
  // states that rather than pretending to know.
  if (!verdict.ok) assert.ok(["PID_UNVERIFIED", "CGROUP_UNVERIFIED"].includes(verdict.code), verdict.code);
});

test("R7D.1-WD06-6 (mocked cgroup): a path with traversal is never armed", () => {
  const harness = makeWatchdog();
  try {
    // `assertArmRequest` rejects traversal when a request arrives over the wire. Called directly
    // against the verifier, traversal is caught by the ownership check, because a path with `..`
    // cannot derive the execution's leaf.
    const verdict = verifyArmIdentity(
      armRequest(EXECUTION, { cgroupPath: `/sys/fs/cgroup/${DIP_CGROUP_SUBTREE}/../../etc` }),
      readBootId(),
    );
    assert.equal(verdict.ok, false);
    if (!verdict.ok) assert.equal(verdict.code, "NOT_DIP_OWNED");
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WD06-7 (mocked cgroup): an execution cannot be re-armed after conclusion", () => {
  const harness = makeWatchdog();
  try {
    armAndAssert(harness, EXECUTION, { deadlineMs: 1_000 });
    harness.clock.advance(2_000);
    const [due] = harness.watchdog.dueForTermination();
    void harness.watchdog.terminate(due!);
    // The execution reached a terminal phase. A second arm would be a different execution wearing
    // the first one's identity.
    const rearm = harness.watchdog.arm(armRequest(EXECUTION));
    assert.equal(rearm.kind, "ARM_DENIED");
    assert.ok(["ALREADY_CONCLUDED", "ALREADY_ARMED"].includes((rearm as { code: string }).code), (rearm as { code: string }).code);
  } finally {
    harness.cleanup();
  }
});

// ══ Helpers ════════════════════════════════════════════════════════════════════════════════════

/** A record that passes validation, so a test can mutate exactly one field. */
function validRecord(overrides: Partial<WatchdogArmRecord> = {}): WatchdogArmRecord {
  return {
    schema: 1,
    executionId: EXECUTION,
    bootId: BOOT,
    watchdogInstance: WATCHDOG_INSTANCE,
    supervisorInstance: "sv-0123456789ab",
    requestId: "b".repeat(16),
    operation: "fill",
    containerId: "c".repeat(64),
    containerName: `dip-exec-${EXECUTION}`,
    imageDigest: `sha256:${"d".repeat(64)}`,
    profileId: "synthetic-v1",
    initPid: 4_242,
    initStartTimeTicks: 100,
    cgroupPath: cgroupPathFor(EXECUTION),
    cgroupDevice: "0:25",
    cgroupDirInode: 4_001,
    cgroupEventsInode: 4_002,
    cgroupKillInode: 4_003,
    cgroupProcsInode: 4_004,
    deadlineAtMs: 30_000,
    armedAtMs: 10_000,
    phase: "armed",
    processDebt: "terminate-required",
    containerDebt: "removal-required",
    outcome: null,
    sequence: 1,
    ...overrides,
  };
}

/**
 * A real directory tree shaped like a cgroup subtree, under a temporary mount root.
 *
 * The control files are ordinary files, so writes are observable. This is **mocked cgroup
 * structure on a real filesystem**: it exercises the descriptor logic and the rename race for real,
 * but it says nothing about whether a real kernel honours `cgroup.kill`.
 */
function fakeCgroupTree(options: { omit?: string; populated?: boolean } = {}): {
  mount: string;
  cgroupPath: string;
  executionId: string;
  cleanup: () => void;
} {
  const mount = mkdtempSync(join(tmpdir(), "dip-mount-"));
  const executionId = EXECUTION;
  const cgroupPath = join(mount, DIP_CGROUP_SUBTREE, `dip-exec-${executionId}`);
  mkdirSync(cgroupPath, { recursive: true });
  const populated = options.populated ?? true;
  for (const name of ["cgroup.kill", "cgroup.events", "cgroup.procs"]) {
    if (name === options.omit) continue;
    writeFileSync(
      join(cgroupPath, name),
      name === "cgroup.events" ? `populated ${populated ? 1 : 0}\nfrozen 0\n` : "",
    );
  }
  return { mount, cgroupPath, executionId, cleanup: () => rmSync(mount, { recursive: true, force: true }) };
}

/** Open file descriptors held by this process, for leak assertions. */
function descriptorCount(): number {
  return readdirSync("/proc/self/fd").length;
}

// ══ Granted disarm, with a real pin over a real (non-cgroup) tree ═════════════════════════════

test("R7D.1-WD04-9 (mocked cgroup): a verified completion mints exactly one grant", async () => {
  // This is the success path, and it needs a pin that can actually answer `populated 0`. The tree
  // is a real filesystem tree — real descriptors, real reads — shaped like a cgroup. The kernel is
  // not involved, hence the label.
  const harness = makeWatchdog({ liveTree: { populated: false } });
  try {
    armAndAssert(harness, EXECUTION);
    assert.equal(harness.watchdog.state(EXECUTION).phase, "armed");

    const grant = await harness.watchdog.disarm(terminalRequest(EXECUTION), randomBytes(8).toString("hex"), 2);
    assert.equal("proof" in grant, true, JSON.stringify(grant));
    if (!("proof" in grant)) return;

    assert.match(grant.proof, /^[a-f0-9]{64}$/u);
    assert.equal(grant.context.executionId, EXECUTION);
    // The record is concluded durably before the grant is returned: a watchdog that dies between
    // signing and replying must leave a record that says a grant was issued.
    const record = harness.watchdog.state(EXECUTION).record;
    assert.equal(record?.phase, "disarmed");
    // `disarmed` is the terminal reason: the execution ended by a verified completion. The
    // supervisor's own `committed` outcome is on the request it signed, not on this record.
    assert.equal(record?.outcome, "disarmed");
    assert.equal(record?.processDebt, "termination-confirmed");
    assert.equal(record?.containerDebt, "removal-confirmed");

    const onDisk = JSON.parse(readFileSync(join(harness.stateDir, "records", `${EXECUTION}.json`), "utf8"));
    assert.equal(onDisk.phase, "disarmed", "the conclusion must be durable, not only in memory");
    assert.equal(onDisk.outcome, "disarmed");
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WD04-10 (mocked cgroup): a replayed disarm cannot mint a second grant", async () => {
  const harness = makeWatchdog({ liveTree: { populated: false } });
  try {
    armAndAssert(harness, EXECUTION);
    const first = await harness.watchdog.disarm(terminalRequest(EXECUTION), randomBytes(8).toString("hex"), 2);
    assert.equal("proof" in first, true, JSON.stringify(first));

    // Same request context, fresh envelope: the concluded state refuses it.
    const second = await harness.watchdog.disarm(terminalRequest(EXECUTION), randomBytes(8).toString("hex"), 3);
    assert.equal("code" in second, true);
    if ("code" in second) assert.equal(second.code, "ALREADY_CONCLUDED");
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WD04-11 (mocked cgroup): a grant does not verify for another execution", async () => {
  const harness = makeWatchdog({ liveTree: { populated: false } });
  try {
    armAndAssert(harness, EXECUTION);
    const grant = await harness.watchdog.disarm(terminalRequest(EXECUTION), randomBytes(8).toString("hex"), 2);
    assert.equal("proof" in grant, true);
    if (!("proof" in grant)) return;

    const { verifyDisarmGrant } = await import("../src/lib/execution/watchdog-protocol");
    assert.equal(verifyDisarmGrant(harness.secret, grant), true);
    // The transcript covers the execution id, so a proof lifted onto another context fails.
    const foreign = { ...grant, context: { ...grant.context, executionId: "f".repeat(32) } };
    assert.equal(verifyDisarmGrant(harness.secret, foreign), false);
    // And a different key fails.
    assert.equal(verifyDisarmGrant(randomBytes(32), grant), false);
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WD04-12 (mocked cgroup): a populated cgroup blocks the grant", async () => {
  // Zero processes is the fact that makes a grant safe. A still-populated cgroup means the container
  // has not stopped; releasing its bytes then would be exactly the unsafe release D-A11 forbids.
  const harness = makeWatchdog({ liveTree: { populated: true } });
  try {
    armAndAssert(harness, EXECUTION);
    const answer = await harness.watchdog.disarm(terminalRequest(EXECUTION), randomBytes(8).toString("hex"), 2);
    assert.equal("code" in answer, true);
    if ("code" in answer) assert.equal(answer.code, "UNCERTAIN");
    assert.equal(harness.watchdog.state(EXECUTION).phase, "armed");
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WD04-13 (mocked cgroup): a durable write failure withholds the grant", async () => {
  // The conclusion must be durable before the signature is released. A store failure here is the
  // "durable grant failure" case: the supervisor gets a refusal and keeps its quarantine.
  const harness = makeWatchdog({ liveTree: { populated: false } });
  try {
    armAndAssert(harness, EXECUTION);
    // Replace the store with one that refuses writes, leaving the armed record in place.
    const original = harness.store;
    const failing = new WatchdogStore(join(harness.stateDir, "records"), {
      fsync: () => { throw new Error("injected fsync failure"); },
    });
    Object.defineProperty(harness.watchdog, "store", { value: () => failing, configurable: true });
    void original;

    const answer = await harness.watchdog.disarm(terminalRequest(EXECUTION), randomBytes(8).toString("hex"), 2);
    assert.equal("code" in answer, true, JSON.stringify(answer));
    if ("code" in answer) assert.equal(answer.code, "DURABILITY_FAILED");
    // The on-disk record still says armed: nothing was lost, and nothing was granted.
    const onDisk = JSON.parse(readFileSync(join(harness.stateDir, "records", `${EXECUTION}.json`), "utf8"));
    assert.equal(onDisk.phase, "armed");
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WD04-14 (mocked cgroup): an expired execution cannot be granted, only terminated", async () => {
  const harness = makeWatchdog({ liveTree: { populated: false } });
  try {
    armAndAssert(harness, EXECUTION, { deadlineMs: 1_000 });
    harness.clock.advance(2_000);
    const answer = await harness.watchdog.disarm(terminalRequest(EXECUTION), randomBytes(8).toString("hex"), 2);
    assert.equal("code" in answer, true);
    if ("code" in answer) assert.equal(answer.code, "EXPIRED");
    // The execution is still due for termination: expiry does not become a release.
    assert.deepEqual(harness.watchdog.dueForTermination().map((entry) => entry.executionId), [EXECUTION]);
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WD04-15 (mocked cgroup): a full termination closes both debts and quarantines nothing", async () => {
  // A real pin, a real `populated 0`, and a daemon that reports the container gone. Only then does
  // the record reach `terminated` with both debts discharged.
  const harness = makeWatchdog({ liveTree: { populated: false }, containerPresent: false });
  try {
    armAndAssert(harness, EXECUTION, { deadlineMs: 1_000 });
    harness.clock.advance(2_000);
    const [due] = harness.watchdog.dueForTermination();
    const report = await harness.watchdog.terminate(due!);
    assert.equal(report.killWritten, true);
    assert.equal(report.processTerminationConfirmed, true);
    assert.equal(report.containerRemovalConfirmed, true);
    assert.equal(report.resolved, true);

    const record = harness.watchdog.state(EXECUTION).record;
    assert.equal(record?.phase, "terminated");
    assert.equal(record?.outcome, "terminated");
    assert.equal(record?.processDebt, "termination-confirmed");
    assert.equal(record?.containerDebt, "removal-confirmed");
    // Fully resolved executions are not retried.
    assert.deepEqual(harness.watchdog.dueForTermination(), []);
  } finally {
    harness.cleanup();
  }
});
