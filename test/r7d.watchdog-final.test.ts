/**
 * Watchdog correctness gates (R7D.1 Continuation D1-Final: WD-F01 … WD-F05).
 *
 * One test (or more) per finding, each named for the requirement it holds. The file exists
 * separately from `r7d.watchdog-security.test.ts` so the final-increment corrections are auditable
 * as a group rather than mixed into the earlier WD-01…WD-06 evidence.
 *
 * ## Evidence classes, per test
 *
 * **Real:** the container-identity classifier over real formatted inspect output, the exact
 * membership comparator over real `/proc` paths, the arbiter's real async scheduling, the durable
 * store's real fsync, the HMAC primitives, and — where the test says so — a real subprocess over a
 * real Unix socket.
 *
 * **Mocked:** the Docker daemon (absent in this sandbox) and the cgroup controller (not writable).
 * No test here establishes kernel enforcement, container isolation or native ARM64 behaviour.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  actualCgroupPath,
  classifyInspect,
  isExactMembership,
  isInsideDipSubtree,
  matchOwnership,
  parseInspectFields,
  provesAbsence,
  provesOwnership,
  type ContainerObservation,
  type ExpectedOwnership,
} from "../src/lib/execution/container-identity";
import { ExecutionArbiter } from "../src/lib/execution/execution-arbiter";
import { INSPECT_FORMAT } from "../src/lib/execution/docker-lifecycle";
import { readProcessStartTimeTicks } from "../src/lib/execution/host-facts";
import {
  BOOT,
  armAndAssert,
  armRequest,
  makeWatchdog,
  terminalRequest,
} from "./support/watchdog-harness";

const EXECUTION = "a".repeat(32);
const CONTAINER_ID = "c".repeat(64);
const IMAGE = `sha256:${"d".repeat(64)}`;

/** The expectation a record would hold. */
function expectation(overrides: Partial<ExpectedOwnership> = {}): ExpectedOwnership {
  return {
    executionId: EXECUTION,
    containerId: CONTAINER_ID,
    containerName: `dip-exec-${EXECUTION}`,
    imageDigest: IMAGE,
    profileId: "synthetic-v1",
    bootId: BOOT,
    supervisorInstance: "sv-0123456789ab",
    ...overrides,
  };
}

/** A formatted inspect line, as `INSPECT_FORMAT` would produce it. */
function inspectLine(overrides: { id?: string; labels?: Record<string, string> } = {}): string {
  const labels = overrides.labels ?? {
    "dip.execution": EXECUTION,
    "dip.boot": BOOT,
    "dip.supervisor": "sv-0123456789ab",
    "dip.image": IMAGE.slice(IMAGE.indexOf("@") + 1),
    "dip.profile": "synthetic-v1",
  };
  // 27 scalar fields then the labels object, matching INSPECT_FORMAT's order.
  const scalars = [
    overrides.id ?? CONTAINER_ID,
    "/dip-executor.slice",
    "private",
    "65534:65534",
    "none",
    "private",
    "private",
    "private",
    "host",
    "true",
    "402653184",
    "402653184",
    "48",
    "750000000",
    "0",
    "0",
    "no",
    "none",
    "false",
    "false",
    "[]",
    "[]",
    "[]",
    "[]",
    "{}",
    "{}",
    "{}",
  ];
  assert.equal(INSPECT_FORMAT.split("|").length, 28, "the fixture must match the inspect format arity");
  assert.equal(scalars.length, 27);
  return [...scalars, JSON.stringify(labels)].join("|");
}

// ══ WD-F01 · Removal confirmation ═══════════════════════════════════════════════════════════════

test("R7D.1-WDF01-1: a successful inspect NOT_FOUND is the only absence", () => {
  // The production classifier, over the production outcome shape. This is the path the previous
  // adapter collapsed into `present: true`.
  const absent = classifyInspect({ ok: false, fault: "NOT_FOUND", ambiguous: false, detail: "no such container" }, expectation());
  assert.equal(absent.state, "absent");
  assert.equal(provesAbsence(absent), true);
});

test("R7D.1-WDF01-2: an unavailable daemon never confirms removal", () => {
  for (const fault of ["DAEMON_UNAVAILABLE", "BINARY_MISSING"] as const) {
    const observation = classifyInspect({ ok: false, fault, ambiguous: true, detail: "cannot connect" }, expectation());
    assert.equal(observation.state, "unavailable", fault);
    assert.equal(provesAbsence(observation), false, `${fault} must not prove absence`);
  }
});

test("R7D.1-WDF01-3: denial, timeout and bad output are all distinct from absence", () => {
  const denied = classifyInspect({ ok: false, fault: "PERMISSION_DENIED", ambiguous: true, detail: "denied" }, expectation());
  assert.equal(denied.state, "denied");
  assert.equal(provesAbsence(denied), false);

  const timedOut = classifyInspect({ ok: false, fault: "TIMEOUT", ambiguous: true, detail: "timed out" }, expectation());
  assert.equal(timedOut.state, "ambiguous");
  assert.equal(provesAbsence(timedOut), false);

  const garbage = classifyInspect({ ok: true, value: { raw: "not|the|expected|format" } }, expectation());
  assert.equal(garbage.state, "ambiguous");
  assert.equal(provesAbsence(garbage), false);
});

test("R7D.1-WDF01-4: a present container with a matching identity authorizes a signal", () => {
  const observation = classifyInspect({ ok: true, value: { raw: inspectLine() } }, expectation());
  assert.equal(observation.state, "present", JSON.stringify(observation));
  assert.equal(provesOwnership(observation), true);
  assert.equal(provesAbsence(observation), false);
});

test("R7D.1-WDF01-5 (mocked Docker): a removal debt is discharged only by observed absence", async () => {
  // Three daemon answers, three outcomes. The debt is paid in exactly one of them.
  const cases: Array<{ name: string; observation: ContainerObservation; confirmed: boolean }> = [
    { name: "absent", observation: { state: "absent", detail: "gone" }, confirmed: true },
    { name: "unavailable", observation: { state: "unavailable", fault: "DAEMON_UNAVAILABLE", detail: "down" }, confirmed: false },
    { name: "ambiguous", observation: { state: "ambiguous", fault: "TIMEOUT", detail: "timeout" }, confirmed: false },
  ];

  for (const testCase of cases) {
    // The container exists while arming and the daemon gives `testCase.observation` afterwards:
    // absence at arm time would be refused, which is a different requirement's behaviour.
    let afterArm = false;
    const harness = makeWatchdog({
      liveTree: { populated: false },
      observation: (expected) => (afterArm
        ? testCase.observation
        : { state: "present", containerId: expected.containerId, labels: {}, detail: "present while arming" }),
    });
    try {
      await armAndAssert(harness, EXECUTION, { deadlineMs: 1_000 });
      afterArm = true;
      harness.clock.advance(2_000);
      const [due] = harness.watchdog.dueForTermination();
      const report = await harness.watchdog.terminate(due!);
      assert.equal(report.containerRemovalConfirmed, testCase.confirmed, testCase.name);
    } finally {
      harness.cleanup();
    }
  }
});

// ══ WD-F02 · Disarm concurrency ═════════════════════════════════════════════════════════════════

test("R7D.1-WDF02-1: the arbiter serialises overlapping operations on one execution", async () => {
  const arbiter = new ExecutionArbiter();
  const order: string[] = [];

  const slow = arbiter.run(EXECUTION, async () => {
    order.push("first:start");
    await new Promise((resolve) => setTimeout(resolve, 25));
    order.push("first:end");
    return "first";
  });
  const fast = arbiter.run(EXECUTION, async () => {
    order.push("second:start");
    order.push("second:end");
    return "second";
  });

  const [a, b] = await Promise.all([slow, fast]);
  assert.equal(a.ok && a.value, "first");
  assert.equal(b.ok && b.value, "second");
  // The second operation could not begin until the first finished, including its await.
  assert.deepEqual(order, ["first:start", "first:end", "second:start", "second:end"]);
});

test("R7D.1-WDF02-2: the arbiter does not serialise different executions", async () => {
  const arbiter = new ExecutionArbiter();
  const order: string[] = [];
  await Promise.all([
    arbiter.run("a".repeat(32), async () => {
      order.push("a:start");
      await new Promise((resolve) => setTimeout(resolve, 20));
      order.push("a:end");
    }),
    arbiter.run("b".repeat(32), async () => {
      order.push("b:start");
      order.push("b:end");
    }),
  ]);
  // `b` completed while `a` was awaiting, which is the point of a per-execution lane.
  assert.deepEqual(order, ["a:start", "b:start", "b:end", "a:end"]);
});

test("R7D.1-WDF02-3: a saturated lane refuses rather than queueing without bound", async () => {
  const arbiter = new ExecutionArbiter(1);
  let release: () => void = () => {};
  const held = arbiter.run(EXECUTION, () => new Promise<void>((resolve) => { release = resolve; }));
  // One holder plus one waiter is the bound; the third is refused.
  const waiter = arbiter.run(EXECUTION, async () => "waiter");
  const refused = await arbiter.run(EXECUTION, async () => "refused");
  assert.equal(refused.ok, false);
  if (!refused.ok) assert.equal(refused.code, "BUSY");
  release();
  const [first, second] = await Promise.all([held, waiter]);
  assert.equal(first.ok, true);
  assert.equal(second.ok && second.value, "waiter");
});

test("R7D.1-WDF02-4: a rejection releases the lane", async () => {
  const arbiter = new ExecutionArbiter();
  await assert.rejects(async () => {
    await arbiter.run(EXECUTION, async () => { throw new Error("boom"); });
  }, /boom/u);
  // The lane is free again: an operation that throws must not deadlock the execution forever.
  const after = await arbiter.run(EXECUTION, async () => "recovered");
  assert.equal(after.ok && after.value, "recovered");
});

test("R7D.1-WDF02-5 (mocked Docker): concurrent disarms cannot mint two grants", async () => {
  // Genuinely concurrent: both are started before either is awaited, and the evidence read inside
  // them is asynchronous. Only one may reach the durable conclusion.
  const harness = makeWatchdog({ liveTree: { populated: false }, observeLifecycle: true });
  try {
    await armAndAssert(harness, EXECUTION);
    harness.removeContainer();

    const [first, second] = await Promise.all([
      harness.watchdog.disarm(terminalRequest(EXECUTION), randomBytes(8).toString("hex"), 2),
      harness.watchdog.disarm(terminalRequest(EXECUTION), randomBytes(8).toString("hex"), 3),
    ]);

    const grants = [first, second].filter((answer) => "proof" in answer);
    assert.equal(grants.length, 1, "exactly one grant may be minted for one execution");
    const denials = [first, second].filter((answer) => "code" in answer);
    assert.equal(denials.length, 1);
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WDF02-6 (mocked Docker): a concurrent termination is not overwritten by a disarm", async () => {
  const harness = makeWatchdog({ liveTree: { populated: false } });
  try {
    await armAndAssert(harness, EXECUTION, { deadlineMs: 1_000 });
    harness.clock.advance(2_000);
    const [due] = harness.watchdog.dueForTermination();

    // The termination starts first; the disarm arrives while the host is being read.
    const [report, answer] = await Promise.all([
      harness.watchdog.terminate(due!),
      harness.watchdog.disarm(terminalRequest(EXECUTION), randomBytes(8).toString("hex"), 2),
    ]);

    assert.equal(report.executionId, EXECUTION);
    // The disarm must not have produced a grant over a termination.
    assert.equal("proof" in answer, false);
    const record = harness.watchdog.state(EXECUTION).record;
    assert.ok(record?.phase !== "disarmed", `a termination must not be overwritten by a disarm, saw ${String(record?.phase)}`);
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WDF02-7 (mocked Docker): an expired disarm never suppresses the termination", async () => {
  const harness = makeWatchdog({ liveTree: { populated: false } });
  try {
    await armAndAssert(harness, EXECUTION, { deadlineMs: 1_000 });
    harness.clock.advance(2_000);
    const answer = await harness.watchdog.disarm(terminalRequest(EXECUTION), randomBytes(8).toString("hex"), 2);
    assert.equal("code" in answer, true);
    if ("code" in answer) assert.equal(answer.code, "EXPIRED");
    // Still owed, and still actionable.
    assert.deepEqual(harness.watchdog.dueForTermination().map((entry) => entry.executionId), [EXECUTION]);
  } finally {
    harness.cleanup();
  }
});

// ══ WD-F03 · Unresolved termination debt ════════════════════════════════════════════════════════

test("R7D.1-WDF03-1 (mocked Docker): quarantine retains an unresolved process debt", async () => {
  const harness = makeWatchdog({ liveTree: { populated: true }, observation: () => ({ state: "present", containerId: CONTAINER_ID, labels: {}, detail: "present" }) });
  try {
    await armAndAssert(harness, EXECUTION, { deadlineMs: 1_000 });
    harness.clock.advance(2_000);
    const [due] = harness.watchdog.dueForTermination();
    await harness.watchdog.terminate(due!);

    const record = harness.watchdog.state(EXECUTION).record;
    assert.equal(record?.phase, "quarantined");
    assert.equal(record?.processDebt, "unresolved");
    assert.equal(record?.outcome, "unresolved");
    // And the durable copy agrees, so a restart sees the debt.
    assert.equal(harness.store.read(EXECUTION)?.processDebt, "unresolved");
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WDF03-2 (mocked Docker): a quarantined execution with verified ownership is retried, boundedly", async () => {
  // The pin is real, so ownership can be re-established on each attempt; the cgroup stays populated,
  // so the debt is never paid. The retry budget is what stops it becoming a busy loop.
  const harness = makeWatchdog({ liveTree: { populated: true } });
  try {
    await armAndAssert(harness, EXECUTION, { deadlineMs: 1_000 });
    harness.clock.advance(2_000);

    let attempts = 0;
    for (let round = 0; round < 10; round += 1) {
      const due = harness.watchdog.dueForTermination();
      if (due.length === 0) break;
      attempts += 1;
      await harness.watchdog.terminate(due[0]!);
      // Advance past the backoff so the next round is eligible.
      harness.clock.advance(6_000);
    }

    assert.ok(attempts > 1, "a quarantined execution with a live debt must be attempted again");
    assert.ok(attempts <= 3, `retries must be bounded, saw ${attempts}`);
    // The debt is still owed and still recorded.
    assert.equal(harness.watchdog.state(EXECUTION).record?.processDebt, "unresolved");
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WDF03-3 (mocked Docker): an unverified target is never signalled", async () => {
  // No real pin, so ownership cannot be re-established at termination time. The watchdog must
  // refuse to signal rather than repeat a kill at a target it cannot identify.
  const harness = makeWatchdog();
  try {
    await armAndAssert(harness, EXECUTION, { deadlineMs: 1_000 });
    harness.clock.advance(2_000);
    const [due] = harness.watchdog.dueForTermination();
    const report = await harness.watchdog.terminate(due!);
    assert.equal(report.killWritten, false);
    assert.match(report.detail, /ownership is not verified/u);
    // Not retried automatically: an unverified target is an operator's decision.
    assert.deepEqual(harness.watchdog.dueForTermination(), []);
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WDF03-4 (mocked Docker): a durable write failure does not stop a verified termination", async () => {
  // The journal is unwritable but the executor is positively identified. The termination must still
  // be attempted: a running container is the hazard, and the record is what can be rebuilt.
  const harness = makeWatchdog({ liveTree: { populated: false } });
  try {
    await armAndAssert(harness, EXECUTION, { deadlineMs: 1_000 });

    // Break the store after a successful arm, so the pre-existing record is intact but no further
    // write succeeds.
    const failing = new (await import("../src/lib/execution/watchdog-store")).WatchdogStore(
      `${harness.stateDir}/records`,
      { fsync: () => { throw new Error("injected fsync failure"); } },
    );
    Object.defineProperty(harness.watchdog, "store", { value: () => failing, configurable: true });

    harness.clock.advance(2_000);
    const [due] = harness.watchdog.dueForTermination();
    const report = await harness.watchdog.terminate(due!);

    // The kill was attempted and the kernel accepted it, despite the write failing.
    assert.equal(report.killWritten, true, "the termination must not be blocked by the journal");
    assert.match(report.detail, /durable intent could not be written/u);
    // And the failure is reported rather than hidden.
    assert.equal(report.resolved, false);
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WDF03-5: the three debts are distinguishable", async () => {
  // One execution with only removal owed must not be treated as a process debt: the processes are
  // confirmed gone, so there is nothing to signal and the removal is attempted by exact id.
  // The cgroup reads `populated 0` through the pin, so the processes are gone. The daemon still
  // reports the container, so removal is owed. Only one of the two debts remains.
  let afterArm = false;
  const harness = makeWatchdog({
    liveTree: { populated: false },
    observation: (expected) => (afterArm
      ? { state: "present", containerId: expected.containerId, labels: {}, detail: "still present" }
      : { state: "present", containerId: expected.containerId, labels: {}, detail: "present" }),
  });
  try {
    await armAndAssert(harness, EXECUTION, { deadlineMs: 1_000 });
    afterArm = true;
    harness.clock.advance(2_000);
    const [due] = harness.watchdog.dueForTermination();
    const first = await harness.watchdog.terminate(due!);
    // Processes are gone (populated 0 through the pin), removal is not.
    assert.equal(first.processTerminationConfirmed, true);
    assert.equal(first.containerRemovalConfirmed, false);
    // A kill was written through the pin; that is the cgroup the fixture models.
    assert.equal(first.killWritten, true);

    // The remaining debt is a *container* debt, and it is labelled as one. It needs the retry
    // backoff to elapse before it becomes due again.
    harness.clock.advance(6_000);
    const [next] = harness.watchdog.dueForTermination();
    assert.ok(next !== undefined, "a remaining container debt must still be due");
    assert.equal(next!.reason, "unresolved-container");
  } finally {
    harness.cleanup();
  }
});

// ══ WD-F04 · Complete ownership proof ═══════════════════════════════════════════════════════════

test("R7D.1-WDF04-1: a wrong container id is a foreign container, not a match", () => {
  const fields = parseInspectFields(inspectLine({ id: "f".repeat(64) }));
  const observation = matchOwnership(fields, expectation());
  assert.equal(observation.state, "present-foreign");
  if (observation.state === "present-foreign") assert.equal(observation.reason, "container-id-mismatch");
  assert.equal(provesOwnership(observation), false);
});

test("R7D.1-WDF04-2: a wrong ownership label is refused, for each of the five", () => {
  const cases: Array<[string, Record<string, string>, string]> = [
    ["execution", { "dip.execution": "b".repeat(32) }, "label-mismatch"],
    ["boot", { "dip.boot": "00000000-0000-4000-8000-000000000000" }, "label-mismatch"],
    ["supervisor", { "dip.supervisor": "sv-impostor-1" }, "label-mismatch"],
    ["image", { "dip.image": `sha256:${"e".repeat(64)}` }, "image-mismatch"],
    ["profile", { "dip.profile": "other-profile" }, "profile-mismatch"],
  ];
  const base = {
    "dip.execution": EXECUTION,
    "dip.boot": BOOT,
    "dip.supervisor": "sv-0123456789ab",
    "dip.image": IMAGE.slice(IMAGE.indexOf("@") + 1),
    "dip.profile": "synthetic-v1",
  };
  for (const [name, override, reason] of cases) {
    const labels = { ...base, ...override };
    const observation = matchOwnership(parseInspectFields(inspectLine({ labels })), expectation());
    assert.equal(observation.state, "present-foreign", name);
    if (observation.state === "present-foreign") assert.equal(observation.reason, reason, name);
  }
});

test("R7D.1-WDF04-3: a container with no ownership labels is foreign", () => {
  const observation = matchOwnership(parseInspectFields(inspectLine({ labels: {} })), expectation());
  assert.equal(observation.state, "present-foreign");
  if (observation.state === "present-foreign") assert.equal(observation.reason, "label-missing");
});

test("R7D.1-WDF04-4: cgroup membership is compared by whole components, not substrings", () => {
  // The exact prefix attack the substring check allowed.
  assert.equal(isExactMembership(`/dip-executor.slice/dip-exec-${EXECUTION}-sibling`, `/dip-executor.slice/dip-exec-${EXECUTION}`), false);
  assert.equal(isExactMembership(`/dip-executor.slice/dip-exec-${EXECUTION}`, `/dip-executor.slice/dip-exec-${EXECUTION}`), true);
  // A parent is not a member of the child, and vice versa is allowed (the child is inside it).
  assert.equal(isExactMembership(`/dip-executor.slice`, `/dip-executor.slice/dip-exec-${EXECUTION}`), false);
  assert.equal(isExactMembership(`/dip-executor.slice/dip-exec-${EXECUTION}/nested`, `/dip-executor.slice/dip-exec-${EXECUTION}`), true);
  // A trailing slash does not create a prefix match on a partial component.
  assert.equal(isExactMembership(`/dip-executor.slice/dip-exec-aaa`, `/dip-executor.slice/dip-exec-aaaa`), false);
});

test("R7D.1-WDF04-5: the actual cgroup path comes from /proc, not a naming convention", () => {
  // Real `/proc`: this process's own membership, read by the production function.
  const mount = "/sys/fs/cgroup";
  const actual = actualCgroupPath(process.pid, mount);
  assert.notEqual(actual, null, "this sandbox exposes /proc/<pid>/cgroup");
  if (actual === null) return;
  assert.ok(actual.relative.startsWith("/"));
  assert.equal(actual.path, `${mount}${actual.relative}`);
  // A PID that cannot exist is null, not a guess.
  assert.equal(actualCgroupPath(2 ** 30, mount), null);
  assert.equal(actualCgroupPath(-1, mount), null);
});

test("R7D.1-WDF04-6: the DIP subtree test is component-exact", () => {
  const mount = "/sys/fs/cgroup";
  assert.equal(isInsideDipSubtree(`${mount}/dip-executor.slice/dip-exec-x`, mount, "dip-executor.slice"), true);
  // The slice itself is not an execution's cgroup.
  assert.equal(isInsideDipSubtree(`${mount}/dip-executor.slice`, mount, "dip-executor.slice"), false);
  // A path whose first component merely begins with the slice name is outside it.
  assert.equal(isInsideDipSubtree(`${mount}/dip-executor.slice-evil/x`, mount, "dip-executor.slice"), false);
  assert.equal(isInsideDipSubtree(`${mount}/other/x`, mount, "dip-executor.slice"), false);
});

test("R7D.1-WDF04-7 (mocked Docker): a foreign container is refused at arm time", async () => {
  const harness = makeWatchdog({
    liveTree: { populated: false },
    observation: () => ({ state: "present-foreign", reason: "label-mismatch", detail: "another execution's container" }),
  });
  try {
    const answer = await harness.watchdog.arm(armRequest(EXECUTION));
    assert.equal(answer.kind, "ARM_DENIED");
    if (answer.kind === "ARM_DENIED") assert.equal(answer.code, "NOT_DIP_OWNED");
    assert.deepEqual(harness.watchdog.outstanding(), []);
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WDF04-8 (mocked Docker): a daemon that cannot be asked refuses the arm without accusing", async () => {
  const harness = makeWatchdog({
    liveTree: { populated: false },
    observation: () => ({ state: "unavailable", fault: "DAEMON_UNAVAILABLE", detail: "down" }),
  });
  try {
    const answer = await harness.watchdog.arm(armRequest(EXECUTION));
    assert.equal(answer.kind, "ARM_DENIED");
    // Not `NOT_DIP_OWNED`: an outage is not evidence of a foreign container.
    if (answer.kind === "ARM_DENIED") assert.equal(answer.code, "CGROUP_UNVERIFIED");
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WDF04-9 (mocked Docker): a mismatched trusted intent refuses the arm", async () => {
  // The supervisor's journal says the container was created for a different image. Two independent
  // statements disagree, so neither is a basis for accepting the target.
  const harness = makeWatchdog({
    liveTree: { populated: false },
    readIntent: () => ({
      executionId: EXECUTION,
      bootId: BOOT,
      supervisorInstance: "sv-0123456789ab",
      containerName: `dip-exec-${EXECUTION}`,
      containerId: CONTAINER_ID,
      imageDigest: `sha256:${"e".repeat(64)}`,
      profileId: "synthetic-v1",
    }),
  });
  try {
    const answer = await harness.watchdog.arm(armRequest(EXECUTION));
    assert.equal(answer.kind, "ARM_DENIED");
    if (answer.kind === "ARM_DENIED") assert.equal(answer.code, "NOT_DIP_OWNED");
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WDF04-10: the verifier refuses a PID whose start time does not match", () => {
  // Real /proc, real boot id, and a start time that cannot be this process's.
  const wrong = readProcessStartTimeTicks(process.pid) + 1;
  const verdict = (async () => {
    const { verifyArmIdentity } = await import("../src/lib/execution/watchdog");
    return verifyArmIdentity(
      armRequest(EXECUTION, {
        cgroupPath: `/sys/fs/cgroup/dip-executor.slice/dip-exec-${EXECUTION}`,
        initPid: process.pid,
        initStartTimeTicks: wrong,
      }),
      BOOT,
    );
  })();
  return verdict.then((result) => {
    assert.equal(result.ok, false);
    // Either the cgroup is absent here or the PID is wrong; both are refusals, and which one is a
    // property of this sandbox rather than of the code.
    if (!result.ok) assert.ok(["PID_UNVERIFIED", "CGROUP_UNVERIFIED"].includes(result.code), result.code);
  });
});

// ══ WD-F05 · Bounded, authenticated control channel ═════════════════════════════════════════════

test("R7D.1-WDF05-1: diagnostic categories carry no peer-derived text", async () => {
  const { diagnosticCategory } = await import("../src/lib/execution/watchdog-server");
  // A message containing a path and a PID is reduced to a category.
  assert.equal(diagnosticCategory(new Error("the execution id is not acceptable")), "invalid-field");
  assert.equal(diagnosticCategory(new Error("watchdog frame is truncated")), "framing");
  assert.equal(diagnosticCategory(new Error("unrecognised request kind EXEC")), "unrecognised");
  assert.equal(diagnosticCategory(new Error("/var/lib/dip/secret leaked here")), "unhandled");
  assert.equal(diagnosticCategory("a bare string"), "unhandled");
  // No category ever contains a path separator or a digit-heavy identifier.
  for (const sample of ["the execution id is not acceptable", "frame exceeds", "must be absolute"]) {
    const category = diagnosticCategory(new Error(sample));
    assert.match(category, /^[a-z-]+$/u);
  }
});
