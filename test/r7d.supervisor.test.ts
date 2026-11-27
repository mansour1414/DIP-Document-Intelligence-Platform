/**
 * Supervisor lifecycle, admission and effective preflight (R7D.1 §5, §6, §7).
 *
 * ## Evidence classes
 *
 * **Real:** Unix sockets created in a temporary directory, real framing over them, real journal
 * writes with real fsync, real HMAC, real admission accounting.
 *
 * **Mocked:** the Docker seam. There is no daemon in this environment, so every container in this
 * file is a function that returns a value. Nothing here establishes anything about OS isolation:
 * the preflight tests prove that a *discrepancy between configuration and profile is detected*,
 * not that a conforming container is isolated.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { connect } from "node:net";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import {
  SupervisorExecution,
  LifecycleError,
  parseInspect,
  type DockerSeam,
  type DockerSession,
  type SupervisorOptions,
} from "../src/lib/execution/supervisor";
import { preflightContainer, preflightKernel } from "../src/lib/execution/preflight";
import { admit, newAdmissionState, release, reserve, startSupervisorServer } from "../src/lib/execution/supervisor-server";
import { OwnershipJournal } from "../src/lib/execution/ownership-journal";
import { INSPECT_FORMAT, SYNTHETIC_PROFILE, type ExecutionPolicy, type DockerOutcome } from "../src/lib/execution/docker-lifecycle";
import { signDisarmGrant } from "../src/lib/execution/watchdog-protocol";
import type { TerminalRequest } from "../src/lib/execution/terminal-auth";

const WATCHDOG_SECRET = randomBytes(32);
const CALLER_SECRET = randomBytes(32);

/** A policy that satisfies every validator, built from the approved synthetic profile. */
function policy(overrides: Partial<ExecutionPolicy> = {}): ExecutionPolicy {
  const executionId = "a".repeat(32);
  return {
    image: `sha256:${"d".repeat(64)}`,
    name: `dip-exec-${executionId}`,
    executionId,
    bootId: "boot-0123456789",
    supervisorInstance: "sv-0123456789ab",
    profileId: "synthetic-v1",
    uid: 10001,
    gid: 10001,
    memoryBytes: SYNTHETIC_PROFILE.memoryBytes,
    cpuQuotaMicros: SYNTHETIC_PROFILE.cpuQuotaMicros,
    cpuPeriodMicros: SYNTHETIC_PROFILE.cpuPeriodMicros,
    pidsLimit: SYNTHETIC_PROFILE.pidsLimit,
    tmpfsBudgetBytes: SYNTHETIC_PROFILE.tmpfsBudgetBytes,
    workTmpfsBytes: SYNTHETIC_PROFILE.workTmpfsBytes,
    tmpTmpfsBytes: SYNTHETIC_PROFILE.tmpTmpfsBytes,
    v8OldSpaceMb: SYNTHETIC_PROFILE.v8OldSpaceMb,
    seccompProfile: "runtime/default",
    apparmorProfile: "docker-default",
    cgroupParent: "dip-executor.slice",
    operation: "fill",
    ...overrides,
  } as ExecutionPolicy;
}

/** The inspect fields a conforming container would produce, in INSPECT_FORMAT order. */
function conformingInspect(overrides: Record<string, string> = {}): Record<string, string> {
  const base: Record<string, string> = {
    Id: "c".repeat(64),
    "HostConfig.CgroupParent": "dip-executor.slice",
    "HostConfig.CgroupnsMode": "private",
    "Config.User": "10001:10001",
    "HostConfig.NetworkMode": "none",
    "HostConfig.IpcMode": "none",
    "HostConfig.PidMode": "",
    "HostConfig.UTSMode": "",
    "HostConfig.UsernsMode": "",
    "HostConfig.ReadonlyRootfs": "true",
    "HostConfig.Memory": String(SYNTHETIC_PROFILE.memoryBytes),
    "HostConfig.MemorySwap": String(SYNTHETIC_PROFILE.memoryBytes),
    "HostConfig.PidsLimit": String(SYNTHETIC_PROFILE.pidsLimit),
    "HostConfig.NanoCpus": "0",
    "HostConfig.CpuQuota": String(SYNTHETIC_PROFILE.cpuQuotaMicros),
    "HostConfig.CpuPeriod": String(SYNTHETIC_PROFILE.cpuPeriodMicros),
    "HostConfig.RestartPolicy.Name": "no",
    "HostConfig.LogConfig.Type": "none",
    "HostConfig.Privileged": "false",
    "HostConfig.AutoRemove": "false",
    "HostConfig.CapAdd": "null",
    "HostConfig.CapDrop": '["ALL"]',
    "HostConfig.Binds": "null",
    "HostConfig.Devices": "null",
    "HostConfig.PortBindings": "{}",
    "HostConfig.Tmpfs": JSON.stringify({
      "/work": `rw,noexec,nosuid,nodev,size=${SYNTHETIC_PROFILE.workTmpfsBytes}`,
      "/tmp": `rw,noexec,nosuid,nodev,size=${SYNTHETIC_PROFILE.tmpTmpfsBytes}`,
    }),
    "Config.Labels": JSON.stringify({ "dip.execution.id": "a".repeat(32), "dip.profile.id": "synthetic-v1" }),
    "Config.Env": '["NODE_OPTIONS=--max-old-space-size=256","HOME=/work","LANG=C.UTF-8"]',
    ...overrides,
  };
  return base;
}

const EXPECTED_LABELS = ["dip.execution.id", "dip.profile.id"];

/** A journal in a temporary directory, bound to this test's instances. */
function makeJournal(): { journal: OwnershipJournal; cleanup: () => void } {
  const root = mkdtempSync(join(tmpdir(), "dip-journal-"));
  const journal = new OwnershipJournal(root);
  journal.init();
  journal.bind("sv-0123456789ab", "wd-0123456789ab");
  return { journal, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

function options(journal: OwnershipJournal, docker: DockerSeam, watchdog?: SupervisorOptions["watchdog"]): SupervisorOptions {
  return {
    journal,
    supervisorInstance: "sv-0123456789ab",
    bootId: "boot-0123456789",
    watchdogInstance: "wd-0123456789ab",
    watchdogSecret: WATCHDOG_SECRET,
    callerSecret: CALLER_SECRET,
    limits: { deadlineMs: 20_000, maxInputBytes: 1024, maxOutputBytes: 4096, maxBufferedBytes: 1024 },
    docker,
    watchdog,
    monotonicMs: () => 1_000,
  };
}

/**
 * An inspect seam that reports the container present once and absent afterwards.
 *
 * Preflight must see the container; removal confirmation must not. A single static answer cannot
 * serve both, and using one would make the removal check untested rather than passing.
 */
function sequenceInspect(): DockerSeam["inspect"] {
  let calls = 0;
  return async () => {
    calls += 1;
    if (calls === 1) return { ok: true, value: { raw: Object.values(conformingInspect()).join("|") } };
    return { ok: false, fault: "NOT_FOUND", ambiguous: false, detail: "no such container" };
  };
}

/** A Docker seam whose every method is a stub. Individual tests override what they care about. */
function seam(overrides: Partial<DockerSeam> = {}): DockerSeam {
  const session: DockerSession = {
    stdin: { write: () => true, end: () => undefined, once: () => undefined } as unknown as DockerSession["stdin"],
    stdout: { [Symbol.asyncIterator]: async function* () {} } as unknown as DockerSession["stdout"],
    stderr: { [Symbol.asyncIterator]: async function* () {} } as unknown as DockerSession["stderr"],
    result: { [Symbol.asyncIterator]: async function* () {} } as unknown as DockerSession["result"],
    exited: Promise.resolve(0),
  };
  return {
    create: async () => ({ ok: true, value: { containerId: "c".repeat(64) } }),
    inspect: async () => ({ ok: true, value: { raw: Object.values(conformingInspect()).join("|") } }),
    remove: async () => ({ ok: true, value: { removed: true } }),
    kill: async () => ({ ok: true, value: { killed: true } }),
    start: async () => session,
    ...overrides,
  };
}

test("R7D.1-SV-1: a container is not created until the intent is durable", async () => {
  const { journal, cleanup } = makeJournal();
  try {
    let created = 0;
    const docker = seam({ create: async () => { created += 1; return { ok: true, value: { containerId: "c".repeat(64) } }; } });
    const execution = new SupervisorExecution("a".repeat(32), "b".repeat(16), "fill", options(journal, docker));

    // Skipping `recordIntent` must make `create` refuse, not fall through to the daemon.
    await assert.rejects(execution.create(), (error: unknown) => error instanceof LifecycleError);
    assert.equal(created, 0, "the daemon must not be touched before a durable intent exists");

    execution.recordIntent({ image: policy().image, profileId: "synthetic-v1", policy: policy(), startedMonotonicMs: 0 });
    // The record exists on disk and names no container yet, which is the state recovery needs.
    const record = journal.readSupervisor("a".repeat(32));
    assert.notEqual(record, null);
    assert.equal(record!.containerId, null);
    assert.equal(record!.phase, "intent");

    await execution.create();
    assert.equal(created, 1);
  } finally {
    cleanup();
  }
});

test("R7D.1-SV-2: an ambiguous create refuses and quarantines rather than guessing", async () => {
  const { journal, cleanup } = makeJournal();
  try {
    const ambiguous: DockerOutcome<{ containerId: string }> = {
      ok: false,
      fault: "TIMEOUT",
      ambiguous: true,
      detail: "deadline reached",
    };
    const execution = new SupervisorExecution("a".repeat(32), "b".repeat(16), "fill", options(journal, seam({ create: async () => ambiguous })));
    execution.recordIntent({ image: policy().image, profileId: "synthetic-v1", policy: policy(), startedMonotonicMs: 0 });
    await assert.rejects(execution.create(), (error: unknown) => error instanceof LifecycleError && (error as LifecycleError).refusal === "CREATE_AMBIGUOUS");
    assert.equal(execution.refusal, "CREATE_AMBIGUOUS");
    // Quarantine is a phase write: admission reads it and blocks.
    assert.equal(journal.readSupervisor("a".repeat(32))!.phase, "quarantined");
  } finally {
    cleanup();
  }
});

test("R7D.1-SV-3: a definite create failure does not quarantine", async () => {
  const { journal, cleanup } = makeJournal();
  try {
    const definite: DockerOutcome<{ containerId: string }> = { ok: false, fault: "NOT_FOUND", ambiguous: false, detail: "no such image" };
    const execution = new SupervisorExecution("a".repeat(32), "b".repeat(16), "fill", options(journal, seam({ create: async () => definite })));
    execution.recordIntent({ image: policy().image, profileId: "synthetic-v1", policy: policy(), startedMonotonicMs: 0 });
    await assert.rejects(execution.create(), (error: unknown) => (error as LifecycleError).refusal === "CREATE_FAILED");
    // Nothing was created, so nothing is ambiguous: leaving the record at `intent` lets recovery
    // conclude there is no container rather than quarantining a clean failure.
    assert.equal(journal.readSupervisor("a".repeat(32))!.phase, "intent");
  } finally {
    cleanup();
  }
});

test("R7D.1-SV-4: the caller is not invited to send a body until preflight and arm have passed", async () => {
  const { journal, cleanup } = makeJournal();
  try {
    const execution = new SupervisorExecution("a".repeat(32), "b".repeat(16), "fill", options(journal, seam(), {
      arm: async () => ({ kind: "ARM_ACK", messageId: "1".repeat(16), executionId: "a".repeat(32), watchdogInstance: "wd-0123456789ab", observedCgroupDirInode: 1, observedCgroupEventsInode: 2, observedCgroupKillInode: 3, observedCgroupProcsInode: 4, observedCgroupDevice: "0:25", observedBootId: "boot-0123456789", armedAtMonotonicMs: 1_000, proof: "0".repeat(64) }),
      disarm: async () => ({ proof: "0".repeat(64) }),
    }));

    // Before any gate, the invitation is refused.
    assert.throws(() => execution.readyForBody(), (error: unknown) => error instanceof LifecycleError);
    assert.equal(execution.currentPhase, "admitted");

    execution.recordIntent({ image: policy().image, profileId: "synthetic-v1", policy: policy(), startedMonotonicMs: 0 });
    await execution.create();

    // Still refused: preflight has not run, so a body would reach an unverified container.
    assert.throws(() => execution.readyForBody(), (error: unknown) => error instanceof LifecycleError);
    assert.equal(execution.currentPhase, "container-created");
  } finally {
    cleanup();
  }
});

test("R7D.1-SV-5: a failed preflight blocks the invitation and terminates the container", async () => {
  const { journal, cleanup } = makeJournal();
  try {
    let killed = 0;
    const docker = seam({
      inspect: async () => ({ ok: true, value: { raw: Object.values(conformingInspect({ "HostConfig.NetworkMode": "bridge" })).join("|") } }),
      kill: async () => { killed += 1; return { ok: true, value: { killed: true } }; },
    });
    const execution = new SupervisorExecution("a".repeat(32), "b".repeat(16), "fill", options(journal, docker));
    execution.recordIntent({ image: policy().image, profileId: "synthetic-v1", policy: policy(), startedMonotonicMs: 0 });
    await execution.create();

    await assert.rejects(
      execution.startAndPreflight((observation) => {
        const result = preflightContainer({
          containerId: observation.containerId,
          effective: observation.effective,
          policy: policy(),
          expectedLabels: EXPECTED_LABELS,
        });
        return result.ok ? { ok: true } : { ok: false, code: result.failures[0]!.code };
      }),
      (error: unknown) => error instanceof LifecycleError && (error as LifecycleError).refusal === "PREFLIGHT_FAILED",
    );
    // A container that failed preflight must not be left running with the profile's resources.
    assert.equal(killed, 1);
    assert.throws(() => execution.readyForBody(), (error: unknown) => error instanceof LifecycleError);
  } finally {
    cleanup();
  }
});

test("R7D.1-SV-6: preflight accepts a conforming container and rejects each weakened control", () => {
  const conforming = preflightContainer({
    containerId: "c".repeat(64),
    effective: conformingInspect(),
    policy: policy(),
    expectedLabels: EXPECTED_LABELS,
  });
  assert.equal(conforming.ok, true, JSON.stringify(conforming.failures));

  // Each of these is a distinct way to weaken the profile, and each must be its own code so a
  // report can name the control rather than saying "preflight failed".
  const cases: Array<[Record<string, string>, string]> = [
    [{ "HostConfig.NetworkMode": "host" }, "NETWORK_NOT_NONE"],
    [{ "HostConfig.IpcMode": "host" }, "IPC_NOT_NONE"],
    [{ "HostConfig.PidMode": "host" }, "PID_MODE_NOT_PRIVATE"],
    [{ "HostConfig.ReadonlyRootfs": "false" }, "ROOTFS_NOT_READONLY"],
    [{ "Config.User": "0:0" }, "USER_NOT_EXECUTOR"],
    [{ "HostConfig.Privileged": "true" }, "PRIVILEGED"],
    [{ "HostConfig.CapAdd": '["SYS_ADMIN"]' }, "CAPABILITIES_ADDED"],
    [{ "HostConfig.CapDrop": "null" }, "CAPABILITIES_ADDED"],
    [{ "HostConfig.Binds": '["/var/run/docker.sock:/var/run/docker.sock"]' }, "BINDS_PRESENT"],
    [{ "HostConfig.Devices": '[{"PathOnHost":"/dev/kvm"}]' }, "DEVICES_PRESENT"],
    [{ "HostConfig.PortBindings": '{"80/tcp":[]}' }, "PORTS_PUBLISHED"],
    [{ "HostConfig.Memory": "1073741824" }, "MEMORY_MISMATCH"],
    [{ "HostConfig.MemorySwap": "-1" }, "SWAP_NOT_DISABLED"],
    [{ "HostConfig.PidsLimit": "4096" }, "PIDS_MISMATCH"],
    [{ "HostConfig.CpuQuota": "100000" }, "CPU_MISMATCH"],
    [{ "HostConfig.RestartPolicy.Name": "always" }, "RESTART_POLICY_SET"],
    [{ "HostConfig.LogConfig.Type": "json-file" }, "LOG_DRIVER_UNBOUNDED"],
    [{ "HostConfig.AutoRemove": "true" }, "AUTOREMOVE_ENABLED"],
    [{ "HostConfig.CgroupParent": "system.slice" }, "CGROUP_PARENT_MISMATCH"],
    [{ "HostConfig.CgroupnsMode": "host" }, "CGROUPNS_NOT_PRIVATE"],
    [{ "Config.Env": '["AWS_SECRET_ACCESS_KEY=x"]' }, "ENV_LEAKS_HOST"],
    [{ "Config.Labels": JSON.stringify({ "dip.execution.id": "f".repeat(32) }) }, "LABELS_MISMATCH"],
    [{ "Config.Labels": "not json" }, "LABELS_MISMATCH"],
  ];
  for (const [override, code] of cases) {
    const result = preflightContainer({
      containerId: "c".repeat(64),
      effective: conformingInspect(override),
      policy: policy(),
      expectedLabels: EXPECTED_LABELS,
    });
    assert.equal(result.ok, false, `${code}: a weakened control was accepted`);
    assert.ok(result.failures.some((failure) => failure.code === code), `${code}: got ${result.failures.map((f) => f.code).join(",")}`);
  }
});

test("R7D.1-SV-7: preflight rejects a tmpfs allocation that exceeds the approved budget", () => {
  const overBudget = preflightContainer({
    containerId: "c".repeat(64),
    effective: conformingInspect({
      "HostConfig.Tmpfs": JSON.stringify({
        "/work": `rw,noexec,size=${SYNTHETIC_PROFILE.workTmpfsBytes}`,
        "/tmp": `rw,noexec,size=${SYNTHETIC_PROFILE.tmpTmpfsBytes}`,
        "/extra": "rw,noexec,size=33554432",
      }),
    }),
    policy: policy(),
    expectedLabels: EXPECTED_LABELS,
  });
  assert.equal(overBudget.ok, false);
  assert.ok(overBudget.failures.some((failure) => failure.code === "TMPFS_POLICY_MISMATCH"));
});

test("R7D.1-SV-8: preflight rejects an executable tmpfs mount", () => {
  const executable = preflightContainer({
    containerId: "c".repeat(64),
    effective: conformingInspect({
      "HostConfig.Tmpfs": JSON.stringify({
        "/work": `rw,exec,size=${SYNTHETIC_PROFILE.workTmpfsBytes}`,
        "/tmp": `rw,noexec,size=${SYNTHETIC_PROFILE.tmpTmpfsBytes}`,
      }),
    }),
    policy: policy(),
    expectedLabels: EXPECTED_LABELS,
  });
  assert.equal(executable.ok, false);
});

test("R7D.1-SV-9: kernel preflight refuses a reused PID and an invalid container id", () => {
  const good = preflightKernel({
    containerId: "c".repeat(64),
    initPid: 4242,
    initStartTimeTicks: 100,
    cgroupPath: "/sys/fs/cgroup/dip-executor.slice/dip-exec-aaa",
    observedStartTimeTicks: 100,
  });
  assert.equal(good.ok, true);

  // The PID now names a different process. Any kill aimed at it would hit the wrong process.
  const reused = preflightKernel({
    containerId: "c".repeat(64),
    initPid: 4242,
    initStartTimeTicks: 100,
    cgroupPath: "/sys/fs/cgroup/dip-executor.slice/dip-exec-aaa",
    observedStartTimeTicks: 101,
  });
  assert.equal(reused.ok, false);

  const badId = preflightKernel({ containerId: "abc", initPid: 4242, initStartTimeTicks: 100, cgroupPath: "/sys/fs/cgroup/x", observedStartTimeTicks: 100 });
  assert.equal(badId.ok, false);

  const traversal = preflightKernel({ containerId: "c".repeat(64), initPid: 4242, initStartTimeTicks: 100, cgroupPath: "/sys/fs/cgroup/../../etc", observedStartTimeTicks: 100 });
  assert.equal(traversal.ok, false);
});

test("R7D.1-SV-10: removal must be confirmed by inspection, not by the daemon's success", async () => {
  const { journal, cleanup } = makeJournal();
  try {
    // `rm` reports success but the container is still there: the daemon's claim was wrong.
    const docker = seam({
      remove: async () => ({ ok: true, value: { removed: true } }),
      inspect: async () => ({ ok: true, value: { raw: Object.values(conformingInspect()).join("|") } }),
    });
    const execution = new SupervisorExecution("a".repeat(32), "b".repeat(16), "fill", options(journal, docker));
    execution.recordIntent({ image: policy().image, profileId: "synthetic-v1", policy: policy(), startedMonotonicMs: 0 });
    await execution.create();
    await execution.startAndPreflight(() => ({ ok: true }));
    execution.setObservation({
      containerId: "c".repeat(64), imageDigest: policy().image, initPid: 1, initStartTimeTicks: 0,
      cgroupPath: "/sys/fs/cgroup/x", startedMonotonicMs: 0, effective: conformingInspect(),
    });
    execution.readyForBody();

    await assert.rejects(
      execution.terminateAndRemove(),
      (error: unknown) => error instanceof LifecycleError && (error as LifecycleError).refusal === "REMOVAL_UNCONFIRMED",
    );
  } finally {
    cleanup();
  }
});

test("R7D.1-SV-11: an ambiguous removal is a refusal, not an assumption", async () => {
  const { journal, cleanup } = makeJournal();
  try {
    let inspections = 0;
    const docker = seam({
      inspect: async (): Promise<DockerOutcome<{ raw: string }>> => {
        inspections += 1;
        // The daemon is healthy for preflight, then unreachable for the removal confirmation.
        // Treating an outage as absence would release a document whose container may still run.
        if (inspections === 1) return { ok: true, value: { raw: Object.values(conformingInspect()).join("|") } };
        return { ok: false, fault: "DAEMON_UNAVAILABLE", ambiguous: true, detail: "socket gone" };
      },
    });
    const execution = new SupervisorExecution("a".repeat(32), "b".repeat(16), "fill", options(journal, docker));
    execution.recordIntent({ image: policy().image, profileId: "synthetic-v1", policy: policy(), startedMonotonicMs: 0 });
    await execution.create();
    await execution.startAndPreflight(() => ({ ok: true }));
    execution.setObservation({
      containerId: "c".repeat(64), imageDigest: policy().image, initPid: 1, initStartTimeTicks: 0,
      cgroupPath: "/sys/fs/cgroup/x", startedMonotonicMs: 0, effective: conformingInspect(),
    });
    execution.readyForBody();
    await assert.rejects(
      execution.terminateAndRemove(),
      (error: unknown) => (error as LifecycleError).refusal === "REMOVAL_UNCONFIRMED",
    );
  } finally {
    cleanup();
  }
});

test("R7D.1-SV-12: admission allows one active executor and refuses the second", () => {
  const state = newAdmissionState();
  const now = 1_000;
  const workerReservation = reserve(state, "worker", now, 30_000);

  const first = admit(state, { role: "app", operation: "inspect", requestId: "1".repeat(16), executionId: "a".repeat(32) }, now, { reservationTtlMs: 30_000, maxConnections: 4 });
  assert.equal(first.ok, true);

  // A second caller, of either role, is refused with BUSY: there is no queue. Deferring would
  // mean holding a connection and an unsent body, which is unbounded in the wrong dimension.
  const second = admit(state, {
    role: "worker", operation: "fill", requestId: "2".repeat(16),
    reservationId: workerReservation.reservationId, executionId: "b".repeat(32),
  }, now, { reservationTtlMs: 30_000, maxConnections: 4 });
  assert.equal(second.ok, false);
  assert.equal((second as { code: string }).code, "BUSY");

  release(state, "a".repeat(32));
  const third = admit(state, {
    role: "worker", operation: "fill", requestId: "3".repeat(16),
    reservationId: workerReservation.reservationId, executionId: "c".repeat(32),
  }, now, { reservationTtlMs: 30_000, maxConnections: 4 });
  assert.equal(third.ok, true);
});

test("R7D.1-SV-13: admission enforces role × operation and a live reservation", () => {
  const state = newAdmissionState();
  const now = 1_000;
  const limits = { reservationTtlMs: 30_000, maxConnections: 4 };

  // The app role may inspect and nothing else. A fill from the web process is refused before it
  // can occupy the executor.
  const appFill = admit(state, { role: "app", operation: "fill", requestId: "1".repeat(16), executionId: "a".repeat(32) }, now, limits);
  assert.equal((appFill as { code: string }).code, "OPERATION_NOT_PERMITTED");

  // A worker without a reservation is refused: the reservation is what makes "who may fill" a
  // server-side fact rather than a claim.
  const noReservation = admit(state, { role: "worker", operation: "fill", requestId: "2".repeat(16), executionId: "a".repeat(32) }, now, limits);
  assert.equal((noReservation as { code: string }).code, "RESERVATION_REQUIRED");

  // An expired reservation is refused and purged.
  const stale = reserve(state, "worker", now, 1);
  const expired = admit(state, {
    role: "worker", operation: "fill", requestId: "3".repeat(16), reservationId: stale.reservationId, executionId: "a".repeat(32),
  }, now + 10, limits);
  assert.equal((expired as { code: string }).code, "RESERVATION_INVALID");

  // A malformed request cannot occupy the executor slot.
  const malformed = admit(state, { role: "worker", operation: "render", requestId: "4".repeat(16), executionId: "a".repeat(32) }, now, limits);
  assert.equal((malformed as { code: string }).code, "BAD_REQUEST");
  assert.equal(state.activeExecution, null);
});

test("R7D.1-SV-14: admission bounds connections per role", () => {
  const state = newAdmissionState();
  const limits = { reservationTtlMs: 30_000, maxConnections: 2 };
  // The counter is what a socket increments on accept. Two are allowed; the third is refused even
  // though no execution is active.
  state.connections.set("app", 2);
  const refused = admit(state, { role: "app", operation: "inspect", requestId: "1".repeat(16), executionId: "a".repeat(32) }, 1_000, limits);
  assert.equal((refused as { code: string }).code, "TOO_MANY_CONNECTIONS");
});

test("R7D.1-SV-15: reservations are unpredictable and distinct", () => {
  const state = newAdmissionState();
  const ids = new Set<string>();
  for (let index = 0; index < 32; index += 1) {
    const reservation = reserve(state, "worker", 1_000, 30_000);
    assert.match(reservation.reservationId, /^[a-f0-9]{48}$/u);
    ids.add(reservation.reservationId);
  }
  assert.equal(ids.size, 32, "reservation ids must not repeat");
});

test("R7D.1-SV-16: the role sockets are real, separate, and mode 0600", async () => {
  const root = mkdtempSync(join(tmpdir(), "dip-sock-"));
  const paths = { app: join(root, "app.sock"), worker: join(root, "worker.sock") };
  const handled: string[] = [];
  const server = await startSupervisorServer({
    socketPaths: paths,
    handle: async ({ role, socket }) => {
      handled.push(role);
      socket.write(`${JSON.stringify({ kind: "DONE", role })}\n`);
    },
  });
  try {
    for (const path of Object.values(paths)) {
      const mode = statSync(path).mode & 0o777;
      assert.equal(mode, 0o600, `${path} must not be group- or world-accessible`);
    }

    // Connect to the app socket and identify as a worker. The role must come from the socket.
    const reply = await new Promise<string>((resolve, reject) => {
      const socket = connect(paths.app, () => {
        socket.write(`${JSON.stringify({ operation: "inspect", requestId: "1".repeat(16), executionId: "a".repeat(32) })}\n`);
      });
      let buffer = "";
      socket.on("data", (chunk: Buffer) => {
        buffer += chunk.toString("utf8");
        if (buffer.includes("\n")) {
          socket.destroy();
          resolve(buffer);
        }
      });
      socket.on("error", reject);
    });
    assert.match(reply, /ADMITTED/u);
    assert.match(reply, /"role":"app"/u, "the app socket must produce the app role");
  } finally {
    await server.stop();
    rmSync(root, { recursive: true, force: true });
  }
});

test("R7D.1-SV-17: an over-long preamble closes the connection without work", async () => {
  const root = mkdtempSync(join(tmpdir(), "dip-sock-"));
  const paths = { app: join(root, "app.sock"), worker: join(root, "worker.sock") };
  let handled = 0;
  const server = await startSupervisorServer({
    socketPaths: paths,
    handle: async () => { handled += 1; },
  });
  try {
    const closed = await new Promise<boolean>((resolve) => {
      const socket = connect(paths.app, () => {
        // No newline, and more than the preamble bound: an unauthenticated peer must not be able
        // to make the server buffer.
        socket.write("x".repeat(2_000));
      });
      socket.on("close", () => resolve(true));
      socket.on("error", () => resolve(true));
      setTimeout(() => resolve(false), 2_000).unref();
    });
    assert.equal(closed, true);
    assert.equal(handled, 0);
  } finally {
    await server.stop();
    rmSync(root, { recursive: true, force: true });
  }
});

test("R7D.1-SV-18: a second connection is refused while an execution is active", async () => {
  const root = mkdtempSync(join(tmpdir(), "dip-sock-"));
  const paths = { app: join(root, "app.sock"), worker: join(root, "worker.sock") };
  let releaseFirst: (() => void) | null = null as (() => void) | null;
  const server = await startSupervisorServer({
    socketPaths: paths,
    handle: async () => {
      await new Promise<void>((resolve) => { releaseFirst = resolve as () => void; });
    },
  });
  const open = (path: string): Promise<string> => new Promise((resolve, reject) => {
    const socket = connect(path, () => {
      socket.write(`${JSON.stringify({ operation: "inspect", requestId: randomBytes(8).toString("hex"), executionId: randomBytes(16).toString("hex") })}\n`);
    });
    let buffer = "";
    socket.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
      if (buffer.includes("\n")) {
        socket.destroy();
        resolve(buffer);
      }
    });
    socket.on("error", reject);
  });
  try {
    const first = await open(paths.app);
    assert.match(first, /ADMITTED/u);
    // The handler is still running, so the executor slot is occupied.
    const second = await open(paths.app);
    assert.match(second, /BUSY/u);
  } finally {
    (releaseFirst as (() => void) | null)?.();
    await server.stop();
    rmSync(root, { recursive: true, force: true });
  }
});

test("R7D.1-SV-19: the terminal commit requires a verified watchdog grant", async () => {
  const { journal, cleanup } = makeJournal();
  try {
    const execution = new SupervisorExecution("a".repeat(32), "b".repeat(16), "fill", options(journal, seam({
      // Present for preflight, absent afterwards: the container really is removed.
      inspect: sequenceInspect(),
    }), {
      arm: async () => ({ kind: "ARM_ACK", messageId: "1".repeat(16), executionId: "a".repeat(32), watchdogInstance: "wd-0123456789ab", observedCgroupDirInode: 1, observedCgroupEventsInode: 2, observedCgroupKillInode: 3, observedCgroupProcsInode: 4, observedCgroupDevice: "0:25", observedBootId: "boot-0123456789", armedAtMonotonicMs: 1_000, proof: "0".repeat(64) }),
      // A grant whose proof is not a valid signature. The supervisor must verify it rather than
      // accepting the watchdog's word.
      disarm: async () => ({ proof: "0".repeat(64) }),
    }));
    execution.recordIntent({ image: policy().image, profileId: "synthetic-v1", policy: policy(), startedMonotonicMs: 0 });
    await execution.create();
    await execution.startAndPreflight(() => ({ ok: true }));
    execution.setObservation({
      containerId: "c".repeat(64), imageDigest: policy().image, initPid: 1, initStartTimeTicks: 0,
      cgroupPath: "/sys/fs/cgroup/x", startedMonotonicMs: 0, effective: conformingInspect(),
    });
    execution.readyForBody();
    await execution.terminateAndRemove();

    await assert.rejects(
      execution.authorize({ requestId: "b".repeat(16), resultBytes: 10, resultDigest: "e".repeat(64), metaBytes: 128, outcome: "committed", nonce: "0123456789abcdef" }),
      (error: unknown) => error instanceof LifecycleError && (error as LifecycleError).refusal === "COMMIT_REFUSED",
    );
  } finally {
    cleanup();
  }
});

test("R7D.1-SV-20: a correctly signed grant produces a commit the caller can verify", async () => {
  const { journal, cleanup } = makeJournal();
  try {
    const expectation = {
      executionId: "a".repeat(32),
      requestId: "b".repeat(16),
      operation: "fill" as const,
      resultDigest: "e".repeat(64),
      resultBytes: 10,
      metaBytes: 128,
      containerId: "c".repeat(64),
      containerName: `dip-exec-${"a".repeat(32)}`,
      bootId: "boot-0123456789",
      supervisorInstance: "sv-0123456789ab",
      watchdogInstance: "wd-0123456789ab",
    };
    let seen: TerminalRequest | null = null;
    const execution = new SupervisorExecution("a".repeat(32), "b".repeat(16), "fill", options(journal, seam({ inspect: sequenceInspect() }), {
      arm: async () => ({ kind: "ARM_ACK", messageId: "1".repeat(16), executionId: "a".repeat(32), watchdogInstance: "wd-0123456789ab", observedCgroupDirInode: 1, observedCgroupEventsInode: 2, observedCgroupKillInode: 3, observedCgroupProcsInode: 4, observedCgroupDevice: "0:25", observedBootId: "boot-0123456789", armedAtMonotonicMs: 1_000, proof: "0".repeat(64) }),
      disarm: async (request) => {
        seen = request;
        const grant = signDisarmGrant(WATCHDOG_SECRET, request);
        return { proof: grant.proof };
      },
    }));
    execution.recordIntent({ image: policy().image, profileId: "synthetic-v1", policy: policy(), startedMonotonicMs: 0 });
    await execution.create();
    await execution.startAndPreflight(() => ({ ok: true }));
    execution.setObservation({
      containerId: "c".repeat(64), imageDigest: policy().image, initPid: 1, initStartTimeTicks: 0,
      cgroupPath: "/sys/fs/cgroup/x", startedMonotonicMs: 0, effective: conformingInspect(),
    });
    execution.readyForBody();
    await execution.terminateAndRemove();

    const result = await execution.authorize({
      requestId: "b".repeat(16), resultBytes: 10, resultDigest: "e".repeat(64), metaBytes: 128,
      outcome: "committed", nonce: "0123456789abcdef",
    });
    assert.equal(result.commit.ok, true);
    if (!result.commit.ok) return;
    // The disarm the supervisor sent must describe this execution's container and outcome: the
    // watchdog signs what it was given, so the binding has to be right at the source.
    assert.equal(seen!.containerId, expectation.containerId);
    assert.equal(seen!.resultDigest, expectation.resultDigest);
    assert.equal(seen!.containerRemoved, true);
    // The commit is signed in the caller's direction and carries the execution's identity.
    assert.equal(result.message.context.executionId, "a".repeat(32));
    assert.match(result.message.proof, /^[a-f0-9]{64}$/u);
  } finally {
    cleanup();
  }
});

test("R7D.1-SV-21: a result that does not match its declaration is discarded, not truncated", async () => {
  const { journal, cleanup } = makeJournal();
  try {
    const execution = new SupervisorExecution("a".repeat(32), "b".repeat(16), "fill", options(journal, seam(), undefined));
    execution.recordIntent({ image: policy().image, profileId: "synthetic-v1", policy: policy(), startedMonotonicMs: 0 });
    await execution.create();
    // A start seam whose result stream yields nothing at all: the frame is absent, so the stream
    // faults rather than reporting a zero-byte document.
    await execution.startAndPreflight(() => ({ ok: true }));
    execution.readyForBody();
    await execution.streamInput(emptyStream());
    await assert.rejects(
      execution.collectResult({ bytes: 0, digest: "0".repeat(64) }),
      (error: unknown) => error instanceof LifecycleError,
    );
    assert.equal(execution.refusal, "RESULT_INVALID");
  } finally {
    cleanup();
  }
});

test("R7D.1-SV-22: the body is bounded by the configured input limit", async () => {
  const { journal, cleanup } = makeJournal();
  try {
    const execution = new SupervisorExecution("a".repeat(32), "b".repeat(16), "fill", options(journal, seam()));
    execution.recordIntent({ image: policy().image, profileId: "synthetic-v1", policy: policy(), startedMonotonicMs: 0 });
    await execution.create();
    await execution.startAndPreflight(() => ({ ok: true }));
    execution.readyForBody();
    // The limit in this harness is 1024 bytes; 2 KiB must be refused mid-stream, not after it is
    // fully read.
    await assert.rejects(
      execution.streamInput(streamOf(Buffer.alloc(2_048, 1))),
      (error: unknown) => error instanceof LifecycleError && (error as LifecycleError).refusal === "INPUT_MISMATCH",
    );
  } finally {
    cleanup();
  }
});

test("R7D.1-SV-23: parseInspect keys the effective state by inner path, for both template forms", () => {
  // `{{.X}}` and `{{json .X}}` must land on the same key. If they do not, a preflight lookup by
  // name reads `undefined` for half its controls and a missing control reads as a passing one.
  const fields = Object.values(conformingInspect());
  assert.equal(fields.length, INSPECT_FORMAT.split("|").length, "the fixture must match the format");
  const parsed = parseInspect(fields, "c".repeat(64), policy());

  // Plain form and json form are both present and both keyed by the inner path.
  assert.equal(parsed.effective["HostConfig.NetworkMode"], "none");
  assert.equal(parsed.effective["HostConfig.Binds"], "null");
  assert.equal(parsed.effective["Config.Labels"], conformingInspect()["Config.Labels"]);
  assert.equal(parsed.effective["HostConfig.CgroupParent"], "dip-executor.slice");

  // Every requested field resolved to a key. Some values are legitimately empty — an empty
  // PidMode means "private", which is what the profile wants — so the assertion is on presence,
  // not on content.
  assert.equal(Object.keys(parsed.effective).length, INSPECT_FORMAT.split("|").length);
  for (const key of Object.keys(parsed.effective)) {
    assert.equal(typeof parsed.effective[key], "string", `the field for ${key} did not resolve`);
  }
  assert.equal(parsed.effective["HostConfig.PidMode"], "", "an empty pid mode means private namespace");
});

// ── stream helpers ───────────────────────────────────────────────────────────────────────────

function streamOf(bytes: Buffer): NodeJS.ReadableStream {
  return {
    [Symbol.asyncIterator]: async function* () {
      yield bytes;
    },
  } as unknown as NodeJS.ReadableStream;
}

function emptyStream(): NodeJS.ReadableStream {
  return {
    [Symbol.asyncIterator]: async function* () {},
  } as unknown as NodeJS.ReadableStream;
}
