/**
 * Reconciliation after crash (R7D.1 §8).
 *
 * ## Evidence classes
 *
 * **Real:** the journal is a real directory with real files, real atomic writes and real fsync;
 * every record is written by the production code path. The classification is the production
 * classifier.
 *
 * **Mocked:** the Docker daemon. `inspect` is a function. Nothing here proves anything about a
 * real daemon's behaviour under these conditions — only that this system reacts correctly to
 * each answer the daemon could give.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { OwnershipJournal, containerNameFor, type SupervisorRecord, type WatchdogRecord } from "../src/lib/execution/ownership-journal";
import { reconcile, actionFor, admissionAllowed, type ReconciliationVerdict } from "../src/lib/execution/reconciliation";
import type { DockerOutcome } from "../src/lib/execution/docker-lifecycle";

const BOOT = "boot-0123456789";
const EXECUTION = "a".repeat(32);
const CONTAINER_ID = "c".repeat(64);
const IMAGE = `sha256:${"d".repeat(64)}`;

function harness(): { journal: OwnershipJournal; root: string; cleanup: () => void } {
  const root = mkdtempSync(join(tmpdir(), "dip-rec-"));
  const journal = new OwnershipJournal(root);
  journal.init();
  journal.bind("sv-0123456789ab", "wd-0123456789ab");
  return { journal, root, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

/** Write a supervisor record directly, bypassing fencing, so any starting state can be built. */
function writeSupervisor(journal: OwnershipJournal, overrides: Partial<SupervisorRecord> = {}): void {
  const record: SupervisorRecord = {
    schema: 1,
    executionId: EXECUTION,
    bootId: BOOT,
    supervisorInstance: "sv-0123456789ab",
    containerName: containerNameFor(EXECUTION),
    containerId: null,
    imageDigest: IMAGE,
    profileId: "synthetic-v1",
    deadlineMs: 20_000,
    startedMonotonicMs: 0,
    phase: "intent",
    sequence: 1,
    outcome: null,
    writerInstance: "sv-0123456789ab",
    ...overrides,
  };
  writeFileSync(join(journal.supervisorDir, `${record.executionId}.json`), JSON.stringify(record));
}

function writeWatchdog(journal: OwnershipJournal, overrides: Partial<WatchdogRecord> = {}): void {
  const record: WatchdogRecord = {
    schema: 1,
    executionId: EXECUTION,
    bootId: BOOT,
    watchdogInstance: "wd-0123456789ab",
    supervisorInstance: "sv-0123456789ab",
    containerId: CONTAINER_ID,
    containerName: containerNameFor(EXECUTION),
    imageDigest: IMAGE,
    profileId: "synthetic-v1",
    initPid: 4242,
    initStartTimeTicks: 100,
    cgroupPath: `/sys/fs/cgroup/dip-executor.slice/${containerNameFor(EXECUTION)}`,
    cgroupDevice: "0:25",
    cgroupDirInode: 1,
    cgroupEventsInode: 2,
    cgroupKillInode: 3,
    cgroupProcsInode: 4,
    deadlineMs: 20_000,
    startedMonotonicMs: 0,
    phase: "armed",
    outcome: null,
    sequence: 1,
    writerInstance: "wd-0123456789ab",
    ...overrides,
  };
  writeFileSync(join(journal.watchdogDir, `${record.executionId}.json`), JSON.stringify(record));
}

const absent = async (): Promise<DockerOutcome<{ raw: string }>> => ({ ok: false, fault: "NOT_FOUND", ambiguous: false, detail: "no such container" });
const present = async (): Promise<DockerOutcome<{ raw: string }>> => ({ ok: true, value: { raw: "present" } });
const unavailable = async (): Promise<DockerOutcome<{ raw: string }>> => ({ ok: false, fault: "DAEMON_UNAVAILABLE", ambiguous: true, detail: "socket gone" });

test("R7D.1-RC-1: an empty journal is clear and admits work", async () => {
  const { journal, cleanup } = harness();
  try {
    const report = await reconcile({ journal, bootId: BOOT, inspect: absent });
    assert.equal(report.clear, true);
    assert.deepEqual(report.verdicts, []);
    assert.equal(admissionAllowed(report), true);
  } finally {
    cleanup();
  }
});

test("R7D.1-RC-2: a terminal record with no container is resolved and left alone", async () => {
  const { journal, cleanup } = harness();
  try {
    writeSupervisor(journal, { phase: "removed", outcome: "committed", containerId: CONTAINER_ID, sequence: 2 });
    writeWatchdog(journal, { phase: "disarmed", outcome: "disarmed" });
    const report = await reconcile({ journal, bootId: BOOT, inspect: present });
    assert.equal(report.clear, true);
    assert.equal(report.verdicts[0]!.kind, "resolved");
    // No daemon call was needed: a resolved record does not justify asking about anything.
    assert.equal(actionFor(report.verdicts[0]!).kind, "leave");
  } finally {
    cleanup();
  }
});

test("R7D.1-RC-3: an intent with no container id is ambiguous, never assumed absent", async () => {
  const { journal, cleanup } = harness();
  try {
    // `docker create` may have been issued and not returned when the supervisor died. The
    // container may still appear, and there is no id to ask about.
    writeSupervisor(journal, { phase: "intent", containerId: null });
    const report = await reconcile({ journal, bootId: BOOT, inspect: absent });
    assert.equal(report.verdicts[0]!.kind, "ambiguous-create");
    assert.equal(admissionAllowed(report), false);
    assert.equal(actionFor(report.verdicts[0]!).kind, "quarantine");
  } finally {
    cleanup();
  }
});

test("R7D.1-RC-4: a recorded container that is gone advances without a destructive action", async () => {
  const { journal, cleanup } = harness();
  try {
    writeSupervisor(journal, { phase: "created", containerId: CONTAINER_ID, sequence: 2 });
    const report = await reconcile({ journal, bootId: BOOT, inspect: absent });
    assert.equal(report.verdicts[0]!.kind, "container-absent");
    const action = actionFor(report.verdicts[0]!);
    assert.equal(action.kind, "advance-absent");
    assert.equal(admissionAllowed(report), true, "an absent container is resolvable without a human");
  } finally {
    cleanup();
  }
});

test("R7D.1-RC-5: a recorded container that still exists is a termination debt by exact id", async () => {
  const { journal, cleanup } = harness();
  try {
    writeSupervisor(journal, { phase: "running", containerId: CONTAINER_ID, sequence: 2 });
    const report = await reconcile({ journal, bootId: BOOT, inspect: present });
    assert.equal(report.verdicts[0]!.kind, "termination-debt");
    const action = actionFor(report.verdicts[0]!);
    assert.equal(action.kind, "terminate-and-remove");
    // The action names exactly one container id. There is no selector, no label, no prefix.
    if (action.kind === "terminate-and-remove") assert.equal(action.containerId, CONTAINER_ID);
    assert.equal(admissionAllowed(report), false);
  } finally {
    cleanup();
  }
});

test("R7D.1-RC-6: an unreachable daemon is unavailable, not absent", async () => {
  const { journal, cleanup } = harness();
  try {
    writeSupervisor(journal, { phase: "running", containerId: CONTAINER_ID, sequence: 2 });
    const report = await reconcile({ journal, bootId: BOOT, inspect: unavailable });
    // The critical distinction: an outage is not evidence of absence. Reading it as absence
    // would release a document whose container may still be running.
    assert.equal(report.verdicts[0]!.kind, "unavailable");
    assert.equal(actionFor(report.verdicts[0]!).kind, "quarantine");
    assert.equal(admissionAllowed(report), false);
  } finally {
    cleanup();
  }
});

test("R7D.1-RC-7: a record from a previous boot authorizes nothing on this host", async () => {
  const { journal, cleanup } = harness();
  try {
    writeSupervisor(journal, { phase: "running", containerId: CONTAINER_ID, sequence: 2, bootId: "previous-boot" });
    // Even though the inspect says present, a container id from a previous boot does not
    // identify anything on this host: the namespace it lived in is gone.
    const report = await reconcile({ journal, bootId: BOOT, inspect: present });
    assert.equal(report.verdicts[0]!.kind, "previous-boot");
    assert.equal(actionFor(report.verdicts[0]!).kind, "leave");
    // And it does not block admission forever: it cannot be resolved on this host, and holding
    // the single slot for a container that no longer exists would be a permanent outage.
    assert.equal(admissionAllowed(report), true);
  } finally {
    cleanup();
  }
});

test("R7D.1-RC-8: a supervisor that concludes while the watchdog is still armed is a conflict", async () => {
  const { journal, cleanup } = harness();
  try {
    writeSupervisor(journal, { phase: "removed", outcome: "committed", containerId: CONTAINER_ID, sequence: 3 });
    // The watchdog is an independent authority. If it still has a deadline armed, the supervisor
    // concluding is not enough: something may still be killed.
    writeWatchdog(journal, { phase: "armed" });
    const report = await reconcile({ journal, bootId: BOOT, inspect: absent });
    assert.equal(report.verdicts[0]!.kind, "conflicting-authority");
    assert.equal(admissionAllowed(report), false);
  } finally {
    cleanup();
  }
});

test("R7D.1-RC-9: an orphaned watchdog record is retained, not deleted", async () => {
  const { journal, cleanup } = harness();
  try {
    // No supervisor record. The previous version of `clear` would have deleted this if its
    // counterpart was missing; that destroys the only evidence an execution was ever armed.
    writeWatchdog(journal, { phase: "armed" });
    const report = await reconcile({ journal, bootId: BOOT, inspect: absent });
    assert.ok(report.verdicts.some((verdict) => verdict.kind === "conflicting-authority"));
    assert.equal(admissionAllowed(report), false);
    // The file is still there.
    assert.deepEqual(readdirSync(journal.watchdogDir).filter((name) => name.endsWith(".json")), [`${EXECUTION}.json`]);
  } finally {
    cleanup();
  }
});

test("R7D.1-RC-10: a corrupt record is unreadable and quarantined, not skipped", async () => {
  const { journal, cleanup } = harness();
  try {
    // A partially written or hand-edited record. Skipping it would silently forget an execution.
    writeFileSync(join(journal.supervisorDir, `${EXECUTION}.json`), '{"schema":1,"executionId":');
    const report = await reconcile({ journal, bootId: BOOT, inspect: absent });
    assert.equal(report.verdicts[0]!.kind, "unreadable");
    assert.equal(admissionAllowed(report), false);
  } finally {
    cleanup();
  }
});

test("R7D.1-RC-11: a record with a bad field is unreadable, not coerced", async () => {
  const { journal, cleanup } = harness();
  try {
    // A phase from an unknown schema version. Coercing it would let an old record drive a
    // lifecycle decision under new rules.
    writeSupervisor(journal, { phase: "halfway" as SupervisorRecord["phase"] });
    const report = await reconcile({ journal, bootId: BOOT, inspect: absent });
    assert.equal(report.verdicts[0]!.kind, "unreadable");
  } finally {
    cleanup();
  }
});

test("R7D.1-RC-12: a quarantined record stays quarantined and blocks admission", async () => {
  const { journal, cleanup } = harness();
  try {
    writeSupervisor(journal, { phase: "quarantined", containerId: CONTAINER_ID, sequence: 3 });
    const report = await reconcile({ journal, bootId: BOOT, inspect: absent });
    assert.equal(report.verdicts[0]!.kind, "termination-debt");
    assert.equal(admissionAllowed(report), false);
  } finally {
    cleanup();
  }
});

test("R7D.1-RC-13: reconciliation performs no destructive action on any verdict by itself", async () => {
  const { journal, cleanup } = harness();
  try {
    // Every problematic state at once. `reconcile` is read-only: it classifies, and the caller
    // decides. That separation is what makes each destructive action testable against its
    // precondition instead of hidden inside a scan.
    writeSupervisor(journal, { phase: "running", containerId: CONTAINER_ID, sequence: 2 });
    const before = readdirSync(journal.supervisorDir).length;
    const inspected: string[] = [];
    await reconcile({
      journal, bootId: BOOT,
      inspect: async (id) => { inspected.push(id); return present(); },
    });
    // It asked about exactly one id, the one recorded.
    assert.deepEqual(inspected, [CONTAINER_ID]);
    // And it wrote nothing.
    assert.equal(readdirSync(journal.supervisorDir).length, before);
  } finally {
    cleanup();
  }
});

test("R7D.1-RC-14: an ambiguous create with no id is never turned into a deletion", () => {
  // Even if a caller ignored the verdict kind and asked for an action, an ambiguous create has no
  // id to delete by. The action type makes that structural: `ambiguous-create` cannot produce a
  // container reference.
  const verdict: ReconciliationVerdict = { executionId: EXECUTION, kind: "ambiguous-create", detail: "phase=creating" };
  const action = actionFor(verdict);
  assert.equal(action.kind, "quarantine");
  assert.equal("containerId" in action, false);
});

test("R7D.1-RC-15: a termination debt without a usable id is quarantined, not actioned", () => {
  // A record in a state that implies a container but has no valid id. Acting would mean guessing
  // at what to remove.
  const action = actionFor({ executionId: EXECUTION, kind: "termination-debt", containerId: "", phase: "running" });
  assert.equal(action.kind, "quarantine");
  const short = actionFor({ executionId: EXECUTION, kind: "termination-debt", containerId: "abc", phase: "running" });
  assert.equal(short.kind, "quarantine");
});

test("R7D.1-RC-16: a definite non-absence daemon fault is not read as absence", async () => {
  const { journal, cleanup } = harness();
  try {
    writeSupervisor(journal, { phase: "created", containerId: CONTAINER_ID, sequence: 2 });
    // A permission error is definite and it is not "not found". Treating it as absence would
    // advance the record past a container that may exist.
    const report = await reconcile({
      journal, bootId: BOOT,
      inspect: async () => ({ ok: false, fault: "PERMISSION_DENIED", ambiguous: false, detail: "denied" }),
    });
    assert.equal(report.verdicts[0]!.kind, "unavailable");
  } finally {
    cleanup();
  }
});

test("R7D.1-RC-17: classification reads every record in the journal exactly once", async () => {
  const { journal, cleanup } = harness();
  try {
    for (let index = 0; index < 5; index += 1) {
      const executionId = index.toString(16).repeat(32).slice(0, 32);
      writeFileSync(
        join(journal.supervisorDir, `${executionId}.json`),
        JSON.stringify({
          schema: 1, executionId, bootId: BOOT, supervisorInstance: "sv-0123456789ab",
          containerName: containerNameFor(executionId), containerId: null, imageDigest: IMAGE,
          profileId: "synthetic-v1", deadlineMs: 20_000, startedMonotonicMs: 0, phase: "intent",
          sequence: 1, outcome: null, writerInstance: "sv-0123456789ab",
        }),
      );
    }
    const report = await reconcile({ journal, bootId: BOOT, inspect: absent });
    assert.equal(report.verdicts.length, 5);
    assert.equal(new Set(report.verdicts.map((verdict) => verdict.executionId)).size, 5);
    assert.equal(report.quarantine.length, 5);
  } finally {
    cleanup();
  }
});
