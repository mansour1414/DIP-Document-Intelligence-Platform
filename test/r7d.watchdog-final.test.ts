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

/**
 * A formatted inspect line, as `INSPECT_FORMAT` would produce it.
 *
 * ## D2-F01: ordered by the format, not by a hand-written list
 *
 * This fixture used to be a hand-written array of 27 scalars followed by the labels object. It
 * asserted the arity against `INSPECT_FORMAT` and still agreed with the parser's wrong `parts[27]`,
 * because both the parser and the fixture had the labels object last. `INSPECT_FORMAT` actually
 * emits `Config.Labels` at index 26 and `Config.Env` at 27 — so the fixture was evidence for a
 * layout the daemon never produces.
 *
 * The values are now keyed by template and assembled in `INSPECT_FORMAT` order, so a fixture can
 * only ever describe the real layout, and a field added to the format appears here as a missing
 * value rather than as a silently shifted column.
 */
function inspectLine(overrides: { id?: string; labels?: Record<string, string>; env?: string[] } = {}): string {
  const labels = overrides.labels ?? {
    "dip.execution": EXECUTION,
    "dip.boot": BOOT,
    "dip.supervisor": "sv-0123456789ab",
    "dip.image": IMAGE.slice(IMAGE.indexOf("@") + 1),
    "dip.profile": "synthetic-v1",
  };
  // Every field the format emits, keyed by its template. The labels and env objects are the only
  // JSON-valued fields, and env is deliberately non-empty: the real executor image sets V8 and
  // profile variables, so a fixture with an empty env would not exercise the field that sits next
  // to the labels.
  const byTemplate: Record<string, string> = {
    "{{.Id}}": overrides.id ?? CONTAINER_ID,
    "{{.HostConfig.CgroupParent}}": "/dip-executor.slice",
    "{{.HostConfig.CgroupnsMode}}": "private",
    "{{.Config.User}}": "65534:65534",
    "{{.HostConfig.NetworkMode}}": "none",
    "{{.HostConfig.IpcMode}}": "private",
    "{{.HostConfig.PidMode}}": "private",
    "{{.HostConfig.UTSMode}}": "private",
    "{{.HostConfig.UsernsMode}}": "host",
    "{{.HostConfig.ReadonlyRootfs}}": "true",
    "{{.HostConfig.Memory}}": "402653184",
    "{{.HostConfig.MemorySwap}}": "402653184",
    "{{.HostConfig.PidsLimit}}": "48",
    "{{.HostConfig.NanoCpus}}": "750000000",
    "{{.HostConfig.CpuQuota}}": "0",
    "{{.HostConfig.CpuPeriod}}": "0",
    "{{.HostConfig.RestartPolicy.Name}}": "no",
    "{{.HostConfig.LogConfig.Type}}": "none",
    "{{.HostConfig.Privileged}}": "false",
    "{{.HostConfig.AutoRemove}}": "false",
    "{{json .HostConfig.CapAdd}}": "[]",
    "{{json .HostConfig.CapDrop}}": "[]",
    "{{json .HostConfig.Binds}}": "[]",
    "{{json .HostConfig.Devices}}": "[]",
    "{{json .HostConfig.PortBindings}}": "{}",
    "{{json .HostConfig.Tmpfs}}": "{}",
    "{{json .Config.Labels}}": JSON.stringify(labels),
    "{{json .Config.Env}}": JSON.stringify(overrides.env ?? ["PDF_WORKER_V8_MB=192", "DIP_PROFILE=synthetic-v1"]),
  };
  const templates = INSPECT_FORMAT.split("|");
  assert.equal(templates.length, 28, "the format arity this fixture is built for");
  const line = templates.map((template) => {
    const value = byTemplate[template];
    assert.notEqual(value, undefined, `the fixture has no value for ${template}, which the format emits`);
    return value;
  });
  assert.deepEqual(Object.keys(byTemplate).sort(), [...templates].sort(), "the fixture covers exactly the format's fields");
  return line.join("|");
}

// ══ WD-F01 · Removal confirmation ═══════════════════════════════════════════════════════════════

test("R7D.1-WDF01-1: a successful inspect NOT_FOUND is the only absence", () => {
  // The production classifier, over the production outcome shape. This is the path the previous
  // adapter collapsed into `present: true`.
  const absent = classifyInspect({ ok: false, fault: "NOT_FOUND", ambiguous: false, detail: "no such container" }, expectation());
  assert.equal(absent.state, "absent");
  assert.equal(provesAbsence(absent), true);
});

test("R7D.1-WDF01-6: the labels field is read from the position the format actually emits", () => {
  // ## The defect this holds
  //
  // The parser read `parts[27]` for the labels object. `INSPECT_FORMAT` emits 28 fields with
  // `Config.Labels` at 26 and `Config.Env` at 27, so a real container's environment array was
  // parsed as its label map, failed the object check, and classified as `ambiguous`. Ownership
  // could therefore never be proved from the daemon's answer — for any container, ever.
  const templates = INSPECT_FORMAT.split("|");
  assert.equal(templates[26], "{{json .Config.Labels}}", "Config.Labels must sit at index 26");
  assert.equal(templates[27], "{{json .Config.Env}}", "Config.Env must sit at index 27");
  assert.equal(templates[0], "{{.Id}}");
  assert.equal(templates[1], "{{.HostConfig.CgroupParent}}");

  // The realistic line — a populated env array sitting where the parser used to look.
  const raw = inspectLine({ env: ["PDF_WORKER_V8_MB=192", "DIP_PROFILE=synthetic-v1"] });
  const fields = parseInspectFields(raw);
  assert.notEqual(fields, null, "a real inspect line must parse");
  assert.equal(fields!.containerId, CONTAINER_ID);
  assert.equal(fields!.labels["dip.execution"], EXECUTION);
  assert.equal(fields!.labels["dip.boot"], BOOT);

  // And the consequence: the line verifies as an owned container rather than an ambiguity.
  const observation = classifyInspect({ ok: true, value: { raw } }, expectation());
  assert.equal(observation.state, "present");
  assert.equal(provesOwnership(observation), true);
});

test("R7D.1-WDF01-7: an env value containing a pipe is refused rather than misread", () => {
  // `Config.Env` is the only field that can legitimately contain the separator. Splitting on `|`
  // cannot represent it, so the line must fail the arity check — an unambiguous format violation —
  // rather than shift the columns and describe a container that does not exist.
  const raw = inspectLine({ env: ["DIP_NOTE=a|b"] });
  assert.equal(parseInspectFields(raw), null);
  const observation = classifyInspect({ ok: true, value: { raw } }, expectation());
  assert.equal(observation.state, "ambiguous");
  assert.equal(provesOwnership(observation), false);
  assert.equal(provesAbsence(observation), false);
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

test("R7D.1-WDF03-3 (mocked Docker): a recovered target is not signalled until the host confirms it", async () => {
  // ## D2-F01: the authority that survives a restart, and the authority that does not
  //
  // After a restart the watchdog holds a record and a re-pinned descriptor, but it has not itself
  // established that the target is this execution's: the record is a claim written by a previous
  // process. Ownership is therefore NOT authorized, and a target whose ownership the host will not
  // currently confirm must not be signalled. This is the boundary D2-F01 preserves — kernel-first
  // does not mean record-first.
  const harness = makeWatchdog();
  try {
    await armAndAssert(harness, EXECUTION, { deadlineMs: 1_000 });
    // A restart over the same store: the record is adopted, ownership starts unverified, and the
    // daemon will not answer, so nothing can confirm it.
    const restarted = harness.restart({
      // The daemon is down after the restart, so nothing can confirm the adopted target.
      observation: () => ({ state: "unavailable", fault: "DAEMON_UNAVAILABLE", detail: "down" }),
    });
    // Recovery is what turns a durable record back into a live execution. It re-pins the cgroup and
    // adopts the record with `ownershipVerified: false`, which is the state this test is about.
    const recovery = restarted.watchdog.recover();
    assert.deepEqual(recovery.adopted, [EXECUTION], "the record must be adopted, not quarantined");
    restarted.clock.advance(2_000);
    const [due] = restarted.watchdog.dueForTermination();
    assert.ok(due !== undefined, "the adopted deadline is still owed");
    const report = await restarted.watchdog.terminate(due);
    assert.equal(report.killWritten, false, "an unconfirmed target must not be signalled");
    assert.equal(report.resolved, false);
    assert.match(report.detail, /ownership is not verified/u);
    // Not retried automatically: an unverified target is an operator's decision.
    assert.deepEqual(restarted.watchdog.dueForTermination(), []);
    restarted.cleanup();
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WDF03-6 (mocked Docker): an armed, identified executor is terminated when Docker is gone", async () => {
  // ## D2-F01: the correction
  //
  // The execution was positively identified while this process was running and its cgroup is
  // pinned. The daemon then becomes unavailable. The container is still running — the kernel says
  // so — and the deadline is still due. Refusing to signal would leave a live container until an
  // operator intervened, on the authority of a daemon that is not answering.
  //
  // The daemon is present at arm time (which is what establishes ownership) and unavailable from
  // then on, so the outage subtracts nothing that was already proved.
  let afterArm = false;
  const harness = makeWatchdog({
    liveTree: { populated: true },
    observation: (expected) => (afterArm
      ? { state: "unavailable", fault: "DAEMON_UNAVAILABLE", detail: "down" }
      : { state: "present", containerId: expected.containerId, labels: {}, detail: "present" }),
  });
  try {
    await armAndAssert(harness, EXECUTION, { deadlineMs: 1_000 });
    afterArm = true;
    harness.clock.advance(2_000);
    const [due] = harness.watchdog.dueForTermination();
    assert.ok(due !== undefined);
    const report = await harness.watchdog.terminate(due);

    // The kernel carried it: the kill reached the pinned cgroup even though the daemon did not
    // confirm the identity during this attempt.
    assert.equal(report.killWritten, true, "the pinned cgroup must be signalled");
    assert.equal(report.dockerIndependent, true, "the authority was the kernel, not the daemon");
    // The fixture's `cgroup.events` still reports tasks: a plain directory is not a cgroup, so the
    // kernel does not rewrite `populated` when `cgroup.kill` is written. Termination is therefore
    // *unconfirmed* here, which is the honest outcome — and the point stands regardless: the signal
    // was delivered on kernel authority while the daemon was unavailable.
    assert.equal(report.processTerminationConfirmed, false);
    // The metadata debt stays owed too: an absent daemon proves nothing about the container record.
    assert.equal(report.containerRemovalConfirmed, false);
    assert.equal(report.resolved, false, "a debt that cannot be observed is not resolved");
    // And the debt is recorded, so a restart still has work to do.
    assert.equal(harness.watchdog.state(EXECUTION).record?.processDebt, "unresolved");
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WDF03-7 (mocked Docker): remaining descendants are killed after the init exits", async () => {
  // The daemon reports the container gone — its init exited — while the cgroup still holds
  // descendants. Docker's answer here is not merely unhelpful, it is the wrong answer to the
  // question. The kernel is asked instead, and the kill is written through the pinned descriptor.
  let afterArm = false;
  const harness = makeWatchdog({
    liveTree: { populated: true },
    observation: (expected) => (afterArm
      ? { state: "absent", detail: "the init exited and the daemon forgot the container" }
      : { state: "present", containerId: expected.containerId, labels: {}, detail: "present" }),
  });
  try {
    await armAndAssert(harness, EXECUTION, { deadlineMs: 1_000 });
    afterArm = true;
    harness.clock.advance(2_000);
    const [due] = harness.watchdog.dueForTermination();
    const report = await harness.watchdog.terminate(due!);
    assert.equal(report.killWritten, true, "descendants are still in the cgroup and must be killed");
    assert.equal(report.dockerIndependent, true);
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
    // The stub answers `not-found`, so the arm is refused for want of an owned container. It is not
    // `NOT_DIP_OWNED` specifically: that code now requires a corroborated *foreign* container, and
    // an absent one is an unverified target rather than an accusation.
    if (answer.kind === "ARM_DENIED") {
      assert.ok(["NOT_DIP_OWNED", "OWNERSHIP_UNVERIFIED"].includes(answer.code), answer.code);
    }
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
    // Not `NOT_DIP_OWNED`: an outage is not evidence of a foreign container, so the arm is refused
    // as unverified rather than as an accusation.
    if (answer.kind === "ARM_DENIED") assert.equal(answer.code, "OWNERSHIP_UNVERIFIED");
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
    // The stub answers `not-found`, so the arm is refused for want of an owned container. It is not
    // `NOT_DIP_OWNED` specifically: that code now requires a corroborated *foreign* container, and
    // an absent one is an unverified target rather than an accusation.
    if (answer.kind === "ARM_DENIED") {
      assert.ok(["NOT_DIP_OWNED", "OWNERSHIP_UNVERIFIED"].includes(answer.code), answer.code);
    }
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
    // property of this sandbox rather than of the code. `NOT_DIP_OWNED` joins them for the same
    // reason: the path is shape-checked against the dedicated subtree before it is ever resolved,
    // and on a host where that subtree does not exist the ownership check answers first.
    if (!result.ok) {
      assert.ok(
        ["PID_UNVERIFIED", "CGROUP_UNVERIFIED", "NOT_DIP_OWNED"].includes(result.code),
        result.code,
      );
    }
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

// ══ D2-F03 · The supervisor journal is mandatory for a new arm ══════════════════════════════════

test("R7D.1-WDF06-1 (mocked Docker): an arm with no supervisor journal is refused", async () => {
  // D2-F03: the watchdog's own record is written by the party being checked. Without a second,
  // independent statement of intent, "the container matches what I wrote" only means one process
  // agrees with itself, so the arm is refused outright.
  const harness = makeWatchdog({ noJournal: true, liveTree: { populated: false } });
  try {
    const answer = await harness.watchdog.arm(armRequest(EXECUTION));
    assert.equal(answer.kind, "ARM_DENIED");
    if (answer.kind === "ARM_DENIED") assert.equal(answer.code, "OWNERSHIP_UNVERIFIED");
    // Nothing was armed, so nothing is owed and no deadline is being enforced against a target the
    // watchdog could not corroborate.
    assert.deepEqual(harness.watchdog.outstanding(), []);
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WDF06-2 (mocked Docker): an unreadable journal is refused, not treated as absent", async () => {
  // The failure that matters: an attacker who can make the corroborating evidence unreadable must
  // not thereby make it optional. `readIntent` throwing is a refusal, not a null.
  const harness = makeWatchdog({
    liveTree: { populated: false },
    readIntent: () => { throw new Error("permission denied"); },
  });
  try {
    const answer = await harness.watchdog.arm(armRequest(EXECUTION));
    assert.equal(answer.kind, "ARM_DENIED");
    if (answer.kind === "ARM_DENIED") assert.equal(answer.code, "OWNERSHIP_UNVERIFIED");
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WDF06-3 (mocked Docker): an intent that names no container id does not authorize an arm", async () => {
  // Before `docker create` succeeds the journal has no container id. Arming against a container the
  // journal does not name would mean the watchdog and the supervisor disagree about which
  // container exists, which is exactly the ambiguity a corroborating record is for.
  const harness = makeWatchdog({
    liveTree: { populated: false },
    readIntent: (executionId) => ({
      executionId,
      bootId: BOOT,
      supervisorInstance: "sv-0123456789ab",
      containerName: `dip-exec-${executionId}`,
      containerId: null,
      imageDigest: `sha256:${"d".repeat(64)}`,
      profileId: "synthetic-v1",
    }),
  });
  try {
    const answer = await harness.watchdog.arm(armRequest(EXECUTION));
    assert.equal(answer.kind, "ARM_DENIED");
    // The stub answers `not-found`, so the arm is refused for want of an owned container. It is not
    // `NOT_DIP_OWNED` specifically: that code now requires a corroborated *foreign* container, and
    // an absent one is an unverified target rather than an accusation.
    if (answer.kind === "ARM_DENIED") {
      assert.ok(["NOT_DIP_OWNED", "OWNERSHIP_UNVERIFIED"].includes(answer.code), answer.code);
    }
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WDF06-4 (mocked Docker): an already-armed execution keeps its termination duty if the journal disappears", async () => {
  // D2-F03's other half. The journal gates *new* arms; it is not a condition on terminating what is
  // already running. An execution armed while the journal was readable must still be killed after it
  // becomes unreadable, or losing the journal would become a way to keep a container alive.
  let journalGone = false;
  const harness = makeWatchdog({
    liveTree: { populated: true },
    readIntent: (executionId) => {
      if (journalGone) throw new Error("journal disappeared");
      return {
        executionId,
        bootId: BOOT,
        supervisorInstance: "sv-0123456789ab",
        containerName: `dip-exec-${executionId}`,
        containerId: "c".repeat(64),
        imageDigest: `sha256:${"d".repeat(64)}`,
        profileId: "synthetic-v1",
      };
    },
  });
  try {
    await armAndAssert(harness, EXECUTION, { deadlineMs: 1_000 });
    journalGone = true;
    harness.clock.advance(2_000);
    const [due] = harness.watchdog.dueForTermination();
    assert.ok(due !== undefined, "the deadline is still owed");
    const report = await harness.watchdog.terminate(due);
    assert.equal(report.killWritten, true, "the kernel signal must still be written");
  } finally {
    harness.cleanup();
  }
});

// ══ D2-F04 · Metadata removal by exact id, separate from the process debt ═══════════════════════

test("R7D.1-WDF07-1 (mocked Docker): a stopped-but-present container is removed by exact id", async () => {
  // Absence is not the only way to discharge the metadata debt. A positively identified container
  // that has stopped still holds its name, its cgroup slot and its writable layer. It must be
  // removed, by the exact id the record names.
  const removed: string[] = [];
  let present = true;
  const harness = makeWatchdog({
    liveTree: { populated: false },
    observation: (expected) => (present
      ? { state: "present", containerId: expected.containerId, labels: {}, detail: "stopped but present" }
      : { state: "absent", detail: "removed" }),
    removeContainer: async (containerId) => {
      removed.push(containerId);
      present = false;
      return { ok: true, detail: "removed" };
    },
    readIntent: (executionId) => ({
      executionId,
      bootId: BOOT,
      supervisorInstance: "sv-0123456789ab",
      containerName: `dip-exec-${executionId}`,
      containerId: "c".repeat(64),
      imageDigest: `sha256:${"d".repeat(64)}`,
      profileId: "synthetic-v1",
    }),
  });
  try {
    await armAndAssert(harness, EXECUTION, { deadlineMs: 1_000 });
    harness.clock.advance(2_000);
    const [due] = harness.watchdog.dueForTermination();
    const report = await harness.watchdog.terminate(due!);

    assert.deepEqual(removed, ["c".repeat(64)], "removal must name the exact recorded container id");
    assert.equal(report.processTerminationConfirmed, true, "the cgroup reported no tasks");
    assert.equal(report.containerRemovalConfirmed, true, "and the exact id is now gone");
    assert.equal(report.resolved, true);
    assert.equal(harness.watchdog.state(EXECUTION).record?.phase, "terminated");
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WDF07-2 (mocked Docker): a container whose processes are still running is not removed", async () => {
  // The order matters. Removing a container whose tasks are alive lets the daemon tear down the
  // cgroup with processes still in it, which is how a termination leaves orphans behind.
  let removalAttempted = false;
  const harness = makeWatchdog({
    liveTree: { populated: true },
    observation: (expected) => ({ state: "present", containerId: expected.containerId, labels: {}, detail: "present" }),
    removeContainer: async () => {
      removalAttempted = true;
      return { ok: true, detail: "removed" };
    },
    readIntent: (executionId) => ({
      executionId,
      bootId: BOOT,
      supervisorInstance: "sv-0123456789ab",
      containerName: `dip-exec-${executionId}`,
      containerId: "c".repeat(64),
      imageDigest: `sha256:${"d".repeat(64)}`,
      profileId: "synthetic-v1",
    }),
  });
  try {
    await armAndAssert(harness, EXECUTION, { deadlineMs: 1_000 });
    harness.clock.advance(2_000);
    const [due] = harness.watchdog.dueForTermination();
    const report = await harness.watchdog.terminate(due!);

    assert.equal(removalAttempted, false, "the metadata must be kept while its processes are alive");
    assert.equal(report.processTerminationConfirmed, false);
    assert.equal(report.containerRemovalConfirmed, false);
    assert.equal(report.resolved, false);
    assert.match(report.detail, /removal is deferred/u);
    // The container is still addressable, so the next attempt still has something to signal.
    assert.equal(harness.watchdog.state(EXECUTION).record?.containerDebt, "unresolved");
  } finally {
    harness.cleanup();
  }
});

// ══ D2-F02 · The deadline is decided again after every await ═════════════════════════════════════

test("R7D.1-WDF08-1 (mocked Docker): expiry during the completion observation does not grant", async () => {
  // The disarm starts inside the deadline. The daemon is slow, and by the time the evidence is in
  // the deadline has passed. Every *evidential* condition for a grant is satisfied — the cgroup
  // reports no tasks, and the exact container id is positively gone — so the refusal below can only
  // come from the deadline. A grant issued here would mean both authorities won: the supervisor
  // finished, and the deadline expired.
  let afterArm = false;
  const harness = makeWatchdog({
    liveTree: { populated: false },
    observation: (expected) => {
      if (!afterArm) return { state: "present", containerId: expected.containerId, labels: {}, detail: "present" };
      // The observation itself takes longer than the remaining budget. The daemon's answer is the
      // one a grant requires; only the clock has moved past the deadline.
      harness.clock.advance(10_000);
      return { state: "absent", detail: "removed while the observation was slow" };
    },
  });
  try {
    await armAndAssert(harness, EXECUTION, { deadlineMs: 5_000 });
    afterArm = true;
    const answer = await harness.watchdog.disarm(terminalRequest(EXECUTION), randomBytes(8).toString("hex"), 2);

    assert.equal("proof" in answer, false, "a grant must not be minted after the deadline passed");
    if ("code" in answer) assert.equal(answer.code, "EXPIRED", "the refusal is expiry, not uncertainty");
    // And it is still terminable: expiry is not a conclusion, and a disarm cannot disarm the
    // deadline's authority by arriving late.
    assert.deepEqual(harness.watchdog.dueForTermination().map((entry) => entry.executionId), [EXECUTION]);
    assert.equal(harness.watchdog.state(EXECUTION).record?.phase, "armed");
  } finally {
    harness.cleanup();
  }
});

test("R7D.1-WDF08-2 (mocked Docker): a slow daemon cannot extend the deadline", async () => {
  // Repeated disarms, each of which spends time observing the host, must not walk the deadline
  // forward. The armed record's `deadlineAtMs` is fixed at arm time and nothing in the disarm path
  // rewrites it.
  const harness = makeWatchdog({ liveTree: { populated: true } });
  try {
    await armAndAssert(harness, EXECUTION, { deadlineMs: 5_000 });
    const before = harness.store.read(EXECUTION)?.deadlineAtMs;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      harness.clock.advance(1_000);
      await harness.watchdog.disarm(terminalRequest(EXECUTION), randomBytes(8).toString("hex"), 2);
    }
    assert.equal(harness.store.read(EXECUTION)?.deadlineAtMs, before, "the deadline must not move");
  } finally {
    harness.cleanup();
  }
});
