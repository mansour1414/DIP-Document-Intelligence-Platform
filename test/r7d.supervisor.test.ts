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
import { existsSync, mkdtempSync, rmSync, statSync } from "node:fs";
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
import { admit, newAdmissionState, releaseResolved, reserve, startRoleSockets } from "../src/lib/execution/role-sockets";
import { OwnershipJournal } from "../src/lib/execution/ownership-journal";
import { INSPECT_FORMAT, SYNTHETIC_PROFILE, type ExecutionPolicy, type DockerOutcome } from "../src/lib/execution/docker-lifecycle";
import { signDisarmGrant, type ArmAck } from "../src/lib/execution/watchdog-protocol";
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
    hostFacts: HOST_FACTS,
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
    // D2: the running container's init process, by exact id. The PID is arbitrary but stable, and
    // the host facts below answer for it.
    state: async (id: string) => ({ ok: true, value: { pid: 4_242, running: true, containerId: id } }),
    ...overrides,
  };
}

/**
 * The kernel facts preflight reads, answered from a fixture.
 *
 * **Mocked evidence.** This environment has no writable cgroup2 mount and no Docker daemon, so a
 * real container cannot be observed. The fixture answers consistently — the same cgroup for the
 * same PID — which is what makes the *sequence* under test meaningful; it establishes nothing about
 * kernel enforcement.
 */
const HOST_FACTS = Object.freeze({
  // The arguments are part of the contract preflight uses; the fixture answers the same cgroup for
  // any pid because there is only one container in these tests.
  startTimeTicks: () => 100,
  cgroupMembership: () => `/dip-executor.slice/dip-exec-${"a".repeat(32)}`,
  cgroup2Mount: () => ({ path: "/sys/fs/cgroup", device: "0:25" }),
});


/**
 * Walk the lifecycle from intent to a released body.
 *
 * D2 changed the gate: `readyForBody` now requires `armed`, not merely `preflight-passed`. A test
 * that wants to describe a released body therefore has to arm, and arming requires an ack that
 * matches the observation preflight took — which is the point of the gate, so the helper supplies
 * exactly that rather than a permissive stub.
 */
const ARM_ACK_STUB: SupervisorOptions["watchdog"] = {
  arm: async (request) => ({
    kind: "ARM_ACK",
    messageId: request.messageId,
    executionId: request.executionId,
    watchdogInstance: "wd-0123456789ab",
    observedCgroupDirInode: 1,
    observedCgroupEventsInode: 2,
    observedCgroupKillInode: 3,
    observedCgroupProcsInode: 4,
    observedCgroupDevice: "0:25",
    observedBootId: "boot-0123456789",
    armedAtMonotonicMs: request.startedMonotonicMs,
    proof: "0".repeat(64),
  }),
  disarm: async () => ({ code: "UNCERTAIN" }),
};

/** Record, create, start, preflight and arm — the sequence that releases a body. */
async function armToReady(execution: SupervisorExecution): Promise<void> {
  execution.recordIntent({ image: policy().image, profileId: "synthetic-v1", policy: policy(), startedMonotonicMs: 0 });
  await execution.create();
  await execution.startAndPreflight(() => ({ ok: true }));
  await execution.armWatchdog();
  execution.readyForBody();
}

test("R7D.1-SV-1: a container is not created until the intent is durable", async () => {
  const { journal, cleanup } = makeJournal();
  try {
    let created = 0;
    const docker = seam({ create: async () => { created += 1; return { ok: true, value: { containerId: "c".repeat(64) } }; } });
    const execution = new SupervisorExecution("a".repeat(32), "b".repeat(16), "fill", options(journal, docker, ARM_ACK_STUB));

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
      // D2: the ack must echo the exchange it answers. A stub with a fixed message id is a
      // different exchange, and the supervisor now refuses it — which is the check under test
      // elsewhere and must not be tripped by the fixture here.
      arm: async (request) => ({ kind: "ARM_ACK", messageId: request.messageId, executionId: request.executionId, watchdogInstance: "wd-0123456789ab", observedCgroupDirInode: 1, observedCgroupEventsInode: 2, observedCgroupKillInode: 3, observedCgroupProcsInode: 4, observedCgroupDevice: "0:25", observedBootId: "boot-0123456789", armedAtMonotonicMs: request.startedMonotonicMs, proof: "0".repeat(64) }),
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
    const execution = new SupervisorExecution("a".repeat(32), "b".repeat(16), "fill", options(journal, docker, ARM_ACK_STUB));
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
    const execution = new SupervisorExecution("a".repeat(32), "b".repeat(16), "fill", options(journal, docker, ARM_ACK_STUB));
    await armToReady(execution);

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
    const execution = new SupervisorExecution("a".repeat(32), "b".repeat(16), "fill", options(journal, docker, ARM_ACK_STUB));
    await armToReady(execution);
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

  releaseResolved(state, "a".repeat(32), true);
  // A reservation is single-use, so the third request needs a fresh one — the first was consumed
  // when the second request was *processed*, even though that request was then refused as BUSY.
  const thirdReservation = reserve(state, "worker", now, 30_000);
  const third = admit(state, {
    role: "worker", operation: "fill", requestId: "3".repeat(16),
    reservationId: thirdReservation.reservationId, executionId: "c".repeat(32),
  }, now, { reservationTtlMs: 30_000, maxConnections: 4 });
  assert.equal(third.ok, true);
});

test("R7D.1-SV-13: admission enforces role × operation and a live reservation", () => {
  const state = newAdmissionState();
  const now = 1_000;
  const limits = { reservationTtlMs: 30_000, maxConnections: 4 };

  // ## Role × operation is no longer enforced here
  //
  // It is checked by the socket server *after* it has authenticated the peer, so that a policy
  // refusal is never reported as a handshake failure — a caller must be able to tell "I am not
  // allowed to do this" from "I did not prove who I am". `admit` therefore only sees requests that
  // passed that check; the enforcement itself is asserted against a real socket in D2R-4.

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
  // ## Why this is no longer a preamble test
  //
  // The sockets used to dispatch on a newline-terminated JSON preamble that any peer could write.
  // They now require the full authenticated handshake, so the old version of this test — write a
  // preamble, read `ADMITTED` — would be testing a protocol that no longer exists. What survives
  // and still matters is the filesystem property: two sockets, separate, not world-readable. The
  // handshake is `r7d.role-sockets.test.ts`'s subject, and is tested there against real sockets.
  const root = mkdtempSync(join(tmpdir(), "dip-sock-"));
  const paths = { app: join(root, "app.sock"), worker: join(root, "worker.sock") };
  const server = await startRoleSockets({
    socketPaths: paths,
    secrets: { app: randomBytes(32), worker: randomBytes(32) },
    supervisorInstance: "sv-0123456789ab",
    bootId: "b".repeat(32),
    handle: async () => { /* never reached: no peer authenticates here */ },
  });
  try {
    assert.notEqual(paths.app, paths.worker, "the roles must not share an inode");
    assert.equal(existsSync(paths.app), true);
    assert.equal(existsSync(paths.worker), true);
    for (const path of Object.values(paths)) {
      const mode = statSync(path).mode & 0o777;
      assert.equal(mode, 0o600, `${path} must not be group- or world-accessible`);
    }
  } finally {
    await server.stop();
    rmSync(root, { recursive: true, force: true });
  }
});

test("R7D.1-SV-17: an unauthenticated peer that writes a preamble is refused, not dispatched", async () => {
  // The exact bytes the old protocol accepted. Under the authenticated transport they are not even
  // a frame: the first four bytes are read as a length prefix and the message is refused.
  const root = mkdtempSync(join(tmpdir(), "dip-sock-"));
  const paths = { app: join(root, "app.sock"), worker: join(root, "worker.sock") };
  let handled = 0;
  const server = await startRoleSockets({
    socketPaths: paths,
    secrets: { app: randomBytes(32), worker: randomBytes(32) },
    supervisorInstance: "sv-0123456789ab",
    bootId: "b".repeat(32),
    handle: async () => { handled += 1; },
  });
  try {
    const reply = await new Promise<string>((resolve) => {
      const socket = connect(paths.app, () => {
        socket.write(`${JSON.stringify({ operation: "inspect", requestId: "1".repeat(16), executionId: "a".repeat(32) })}\n`);
      });
      let buffer = "";
      socket.on("data", (chunk: Buffer) => { buffer += chunk.toString("utf8"); });
      socket.on("close", () => resolve(buffer));
      socket.on("error", () => resolve(buffer));
      setTimeout(() => { socket.destroy(); resolve(buffer); }, 2_000).unref();
    });
    assert.equal(handled, 0, "no handler may run for an unauthenticated peer");
    assert.equal(reply.includes("ADMITTED"), false, "and nothing may be admitted");
  } finally {
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
      // D2: the ack must echo the exchange it answers. A stub with a fixed message id is a
      // different exchange, and the supervisor now refuses it — which is the check under test
      // elsewhere and must not be tripped by the fixture here.
      arm: async (request) => ({ kind: "ARM_ACK", messageId: request.messageId, executionId: request.executionId, watchdogInstance: "wd-0123456789ab", observedCgroupDirInode: 1, observedCgroupEventsInode: 2, observedCgroupKillInode: 3, observedCgroupProcsInode: 4, observedCgroupDevice: "0:25", observedBootId: "boot-0123456789", armedAtMonotonicMs: request.startedMonotonicMs, proof: "0".repeat(64) }),
      // A grant whose proof is not a valid signature. The supervisor must verify it rather than
      // accepting the watchdog's word.
      disarm: async () => ({ proof: "0".repeat(64) }),
    }));
    await armToReady(execution);
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
      // D2: the ack must echo the exchange it answers. A stub with a fixed message id is a
      // different exchange, and the supervisor now refuses it — which is the check under test
      // elsewhere and must not be tripped by the fixture here.
      arm: async (request) => ({ kind: "ARM_ACK", messageId: request.messageId, executionId: request.executionId, watchdogInstance: "wd-0123456789ab", observedCgroupDirInode: 1, observedCgroupEventsInode: 2, observedCgroupKillInode: 3, observedCgroupProcsInode: 4, observedCgroupDevice: "0:25", observedBootId: "boot-0123456789", armedAtMonotonicMs: request.startedMonotonicMs, proof: "0".repeat(64) }),
      disarm: async (request) => {
        seen = request;
        const grant = signDisarmGrant(WATCHDOG_SECRET, request);
        return { proof: grant.proof };
      },
    }));
    await armToReady(execution);
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
    const execution = new SupervisorExecution("a".repeat(32), "b".repeat(16), "fill", options(journal, seam(), ARM_ACK_STUB));
    // A start seam whose result stream yields nothing at all: the frame is absent, so the stream
    // faults rather than reporting a zero-byte document.
    await armToReady(execution);
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
    const execution = new SupervisorExecution("a".repeat(32), "b".repeat(16), "fill", options(journal, seam(), ARM_ACK_STUB));
    await armToReady(execution);
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

// ══ D2 · The readiness gate ═════════════════════════════════════════════════════════════════════

test("R7D.1-SV-24: a body cannot be released before the watchdog is armed", async () => {
  // ## The defect this closes
  //
  // `readyForBody` used to accept `preflight-passed`. A supervisor could therefore invite a caller to
  // stream a document into a container that no deadline was enforced against, and if the arm was
  // then refused the bytes were already in flight.
  const { journal, cleanup } = makeJournal();
  try {
    const execution = new SupervisorExecution("a".repeat(32), "b".repeat(16), "fill", options(journal, seam(), ARM_ACK_STUB));
    execution.recordIntent({ image: policy().image, profileId: "synthetic-v1", policy: policy(), startedMonotonicMs: 0 });
    await execution.create();
    await execution.startAndPreflight(() => ({ ok: true }));
    // Preflight passed. The watchdog has not been asked.
    assert.throws(
      () => execution.readyForBody(),
      (error: unknown) => error instanceof LifecycleError
        && (error as LifecycleError).refusal === "ARM_REFUSED"
        && /before the watchdog is armed/u.test(error.message),
    );
    // And the refusal is recorded, so a caller cannot retry into a released body.
    assert.equal(execution.refusal, "ARM_REFUSED");

    // After arming, the same call succeeds. A fresh journal, because one execution identity may only
    // advance through one journal's sequence — a second record for the same id in the same run is a
    // fencing violation, which the journal refuses (correctly).
    const second = makeJournal();
    try {
      const armed = new SupervisorExecution("a".repeat(32), "b".repeat(16), "fill", options(second.journal, seam(), ARM_ACK_STUB));
      await armToReady(armed);
      assert.equal(armed.currentPhase, "ready-for-body");
    } finally {
      second.cleanup();
    }
  } finally {
    cleanup();
  }
});

test("R7D.1-SV-25: an arm ack describing a different exchange is refused", async () => {
  // Every field the acknowledgement can disagree with is checked: the exchange id, the watchdog
  // instance, the boot, and the cgroup identity. A stub that agrees with the supervisor on the
  // execution but not on the message is still a different arm.
  const { cleanup } = makeJournal();
  // Only the fields an honest ack has, so an override cannot change the discriminant.
  type AckFields = Omit<ArmAck, "kind">;
  const cases: Array<[string, Partial<AckFields>]> = [
    ["message", { messageId: "f".repeat(16) }],
    ["execution", { executionId: "f".repeat(32) }],
    ["instance", { watchdogInstance: "wd-impostor-1" }],
    ["boot", { observedBootId: "00000000-0000-4000-8000-000000000000" }],
  ];
  for (const [name, override] of cases) {
    // One journal per case: the same execution identity cannot be recorded twice in one journal.
    const caseJournal = makeJournal();
    try {
      // A stub that answers with an ack identical to the honest one except for one field. Written
      // out rather than spread, so the type is an `ArmAck` and not a union of every stub shape.
      const watchdog: NonNullable<SupervisorOptions["watchdog"]> = {
        arm: async (request): Promise<ArmAck> => ({
          kind: "ARM_ACK",
          messageId: request.messageId,
          executionId: request.executionId,
          watchdogInstance: "wd-0123456789ab",
          observedCgroupDirInode: 1,
          observedCgroupEventsInode: 2,
          observedCgroupKillInode: 3,
          observedCgroupProcsInode: 4,
          observedCgroupDevice: "0:25",
          observedBootId: "boot-0123456789",
          armedAtMonotonicMs: request.startedMonotonicMs,
          proof: "0".repeat(64),
          ...override,
        }),
        disarm: async () => ({ code: "UNCERTAIN" }),
      };
      const execution = new SupervisorExecution("a".repeat(32), "b".repeat(16), "fill", options(caseJournal.journal, seam(), watchdog));
      execution.recordIntent({ image: policy().image, profileId: "synthetic-v1", policy: policy(), startedMonotonicMs: 0 });
      await execution.create();
      await execution.startAndPreflight(() => ({ ok: true }));
      await assert.rejects(
        execution.armWatchdog(),
        (error: unknown) => error instanceof LifecycleError && (error as LifecycleError).refusal === "ARM_REFUSED",
        name,
      );
      // And no body may be released after a refused arm.
      assert.throws(() => execution.readyForBody(), (error: unknown) => error instanceof LifecycleError);
      assert.notEqual(execution.currentPhase, "ready-for-body", name);
    } finally {
      caseJournal.cleanup();
      cleanup();
    }
  }
});

test("R7D.1-SV-26: a commit is refused after the deadline, before the watchdog is even asked", async () => {
  // D2-F02 at the supervisor boundary: the deadline is re-decided immediately before the commit is
  // requested. A clock that has moved past the budget refuses without a disarm attempt, so no grant
  // can be minted for an execution that already expired.
  const { journal, cleanup } = makeJournal();
  try {
    let now = 0;
    let disarms = 0;
    const watchdog: NonNullable<SupervisorOptions["watchdog"]> = {
      ...ARM_ACK_STUB!,
      disarm: async () => { disarms += 1; return { code: "UNCERTAIN" }; },
    };
    const execution = new SupervisorExecution("a".repeat(32), "b".repeat(16), "fill", {
      ...options(journal, seam({ inspect: sequenceInspect() }), watchdog),
      limits: { deadlineMs: 1_000, maxInputBytes: 1024, maxOutputBytes: 4096, maxBufferedBytes: 1024 },
      monotonicMs: () => now,
    });
    await armToReady(execution);
    await execution.terminateAndRemove();
    // The budget is 1 s. The clock moves past it between removal and the commit.
    now = 2_000;
    await assert.rejects(
      execution.authorize({ requestId: "b".repeat(16), resultBytes: 10, resultDigest: "e".repeat(64), metaBytes: 128, outcome: "committed", nonce: "0123456789abcdef" }),
      (error: unknown) => error instanceof LifecycleError
        && (error as LifecycleError).refusal === "COMMIT_REFUSED"
        && /deadline passed/u.test(error.message),
    );
    assert.equal(disarms, 0, "an expired execution must not even ask the watchdog for a grant");
  } finally {
    cleanup();
  }
});
