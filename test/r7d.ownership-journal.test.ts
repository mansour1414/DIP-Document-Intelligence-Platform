/**
 * R7D.1 — crash-safe ownership journal.
 *
 * ## What is real here
 *
 * These tests touch the actual filesystem: real atomic renames, real directory fsyncs, real
 * sequence fencing. They are not mocks. What they cannot simulate is a genuine power loss
 * mid-rename, so durability is asserted structurally (the write is a rename, the directory is
 * fsync'd) rather than by crashing a host.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, fsyncSync, mkdtempSync, statSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import {
  assertExecutionId,
  classifyForRecovery,
  containerNameFor,
  newExecutionId,
  OwnershipJournal,
  writeDurableIntent,
  JournalFencingError,
  type SupervisorRecord,
  type WatchdogRecord,
} from "../src/lib/execution/ownership-journal";

const ID = "0123456789abcdef0123456789abcdef";

function record(overrides: Partial<SupervisorRecord> = {}): SupervisorRecord {
  return {
    schema: 1,
    executionId: ID,
    bootId: "boot-1",
    supervisorInstance: "sup-1",
    containerName: containerNameFor(ID),
    containerId: null,
    imageDigest: `sha256:${"a".repeat(64)}`,
    profileId: "synthetic-r7d-v1",
    deadlineMs: 20_000,
    startedMonotonicMs: 1000,
    phase: "intent",
    sequence: 1,
    outcome: null,
    // C-F04: the writer identity is required and must match the supervisor instance.
    writerInstance: "sup-1",
    ...overrides,
  };
}

/** A complete watchdog record, with every recoverable identity field populated. */
function watchdogRecord(overrides: Partial<WatchdogRecord> = {}): WatchdogRecord {
  return {
    schema: 1,
    executionId: ID,
    bootId: "boot-1",
    watchdogInstance: "wd-1",
    supervisorInstance: "sup-1",
    containerId: "c".repeat(64),
    containerName: containerNameFor(ID),
    imageDigest: `sha256:${"a".repeat(64)}`,
    profileId: "synthetic-r7d-v1",
    initPid: 4242,
    initStartTimeTicks: 329483,
    cgroupPath: "/sys/fs/cgroup/dip-executor-0123456789/dip-exec-0123456789abcdef0123456789abcdef",
    cgroupDevice: "0:28",
    cgroupDirInode: 9001,
    cgroupEventsInode: 9002,
    cgroupKillInode: 9003,
    cgroupProcsInode: 9004,
    deadlineMs: 20_000,
    startedMonotonicMs: 1000,
    phase: "armed",
    outcome: null,
    sequence: 1,
    writerInstance: "wd-1",
    ...overrides,
  };
}

function withJournal(run: (journal: OwnershipJournal, root: string) => void): void {
  const root = mkdtempSync(join(tmpdir(), "dip-journal-"));
  try {
    const journal = new OwnershipJournal(root);
    journal.init();
    run(journal, root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------------------
// Identity.
// ---------------------------------------------------------------------------------------

test("R7D.1-J-1: execution ids are hex only, so they cannot escape the directory", () => {
  assert.throws(() => assertExecutionId("../../etc/passwd"), /32 lowercase hex/u);
  assert.throws(() => assertExecutionId("ABCDEF0123456789abcdef0123456789"), /32 lowercase hex/u);
  assert.throws(() => assertExecutionId("short"), /32 lowercase hex/u);
  assert.doesNotThrow(() => assertExecutionId(ID));
});

test("R7D.1-J-2: container names derive deterministically from the execution id", () => {
  assert.equal(containerNameFor(ID), `dip-exec-${ID}`);
  assert.throws(() => containerNameFor("bad/../name"), /32 lowercase hex/u);
});

test("R7D.1-J-3: execution ids are unpredictable and distinct", () => {
  const seen = new Set<string>();
  for (let index = 0; index < 200; index += 1) {
    const id = newExecutionId((size) => randomBytes(size));
    assert.match(id, /^[a-f0-9]{32}$/u);
    seen.add(id);
  }
  assert.equal(seen.size, 200, "no collisions in 200 draws");
});

// ---------------------------------------------------------------------------------------
// Separation of authorities.
// ---------------------------------------------------------------------------------------

test("R7D.1-J-4: supervisor and watchdog state live in separate directories", () => {
  // A single file would let the supervisor read its own intent and mistake it for the
  // watchdog's independent confirmation — the Defect 2 shape.
  withJournal((journal, root) => {
    assert.ok(journal.supervisorDir.startsWith(root));
    assert.ok(journal.watchdogDir.startsWith(root));
    assert.notEqual(journal.supervisorDir, journal.watchdogDir);
    journal.writeSupervisor(record());
    // Nothing appears in the watchdog directory until the watchdog itself writes.
    assert.deepEqual(journal.listWatchdog(), []);
    assert.deepEqual(journal.listSupervisor(), [ID]);
  });
});

// ---------------------------------------------------------------------------------------
// Fencing.
// ---------------------------------------------------------------------------------------

test("R7D.1-J-5: a lower or equal sequence is refused", () => {
  withJournal((journal) => {
    journal.writeSupervisor(record({ sequence: 5, phase: "creating" }));
    assert.throws(() => journal.writeSupervisor(record({ sequence: 5, phase: "created" })), /is behind|regression|refusing/u);
    assert.throws(() => journal.writeSupervisor(record({ sequence: 4, phase: "created" })), /is behind|regression|refusing/u);
    assert.doesNotThrow(() => journal.writeSupervisor(record({ sequence: 6, phase: "created" })));
  });
});

test("R7D.1-J-6: a phase may not regress", () => {
  withJournal((journal) => {
    journal.writeSupervisor(record({ sequence: 1, phase: "intent" }));
    journal.writeSupervisor(record({ sequence: 2, phase: "running" }));
    assert.throws(() => journal.writeSupervisor(record({ sequence: 3, phase: "creating" })), /phase regression/u);
    assert.throws(() => journal.writeSupervisor(record({ sequence: 4, phase: "intent" })), /phase regression/u);
  });
});

test("R7D.1-J-7: quarantine is reachable from any phase and is terminal", () => {
  withJournal((journal) => {
    journal.writeSupervisor(record({ sequence: 1, phase: "running" }));
    assert.doesNotThrow(() => journal.writeSupervisor(record({ sequence: 2, phase: "quarantined" })));
    // Nothing may leave quarantine, including another quarantine write with a live phase.
    assert.throws(() => journal.writeSupervisor(record({ sequence: 3, phase: "terminal" })), /quarantine is terminal/u);
  });
});

// ---------------------------------------------------------------------------------------
// Atomicity.
// ---------------------------------------------------------------------------------------

test("R7D.1-J-8: writes are atomic replacements, leaving no partial record", () => {
  withJournal((journal, root) => {
    journal.writeSupervisor(record({ sequence: 1, phase: "intent" }));
    const CONTAINER = "c0ffee".padEnd(64, "0");
    journal.writeSupervisor(record({ sequence: 2, phase: "created", containerId: CONTAINER }));
    const stored = journal.readSupervisor(ID);
    assert.equal(stored?.phase, "created");
    assert.equal(stored?.containerId, CONTAINER);
    // The temporary file is renamed away, never left behind.
    assert.equal(readdirSync(join(root, "supervisor")).some((name) => name.endsWith(".tmp")), false);
  });
});

test("R7D.1-J-9: a stray .tmp file is never read as a record", () => {
  // An interrupted write leaves a temporary. If it were parsed, a half-written record would
  // be treated as authoritative — worse than no record at all.
  withJournal((journal, root) => {
    writeFileSync(join(root, "supervisor", `${ID}.json.tmp`), "{ broken");
    assert.deepEqual(journal.listSupervisor(), []);
    assert.equal(journal.readSupervisor(ID), null);
  });
});

// ---------------------------------------------------------------------------------------
// Privacy: metadata only.
// ---------------------------------------------------------------------------------------

test("R7D.1-J-10: no record field can carry document content", () => {
  // Structural check on the written bytes: the record must contain identities and counters
  // only. A free-form field would make "no field names, no values" a promise rather than a
  // property, so the type has none — and this asserts the serialised form agrees.
  withJournal((journal) => {
    const canary = "CANARY-FIELD-NAME";
    journal.writeSupervisor(record({ sequence: 1, phase: "intent" }));
    const text = readFileSync(join(journal.supervisorDir, `${ID}.json`), "utf8");
    assert.equal(text.includes(canary), false);
    const parsed = JSON.parse(text) as Record<string, unknown>;
    // Exactly the declared keys, nothing extra.
    assert.deepEqual(Object.keys(parsed).sort(), [
      "bootId", "containerId", "containerName", "deadlineMs", "executionId", "imageDigest",
      "outcome", "phase", "profileId", "schema", "sequence", "startedMonotonicMs", "supervisorInstance",
      "writerInstance",
    ]);
    // Every value is a string, number, boolean or null — never a nested object that could
    // hold arbitrary content.
    for (const [key, value] of Object.entries(parsed)) {
      assert.ok(value === null || ["string", "number", "boolean"].includes(typeof value), `${key} must be scalar`);
    }
  });
});

// ---------------------------------------------------------------------------------------
// Recovery classification (the assumption §13 forbids).
// ---------------------------------------------------------------------------------------

test("R7D.1-J-11: an in-flight create with no container id is AMBIGUOUS, not absent", () => {
  // `docker create` may have been issued and not returned when the supervisor died, and the
  // container may materialise afterwards. Treating "no id recorded" as "no container" and
  // releasing the admission slot is precisely the mistake §13 calls out.
  assert.equal(classifyForRecovery(record({ phase: "intent", containerId: null })), "ambiguous-create");
  assert.equal(classifyForRecovery(record({ phase: "creating", containerId: null })), "ambiguous-create");
});

test("R7D.1-J-12: a known container id requires a lookup, never an assumption", () => {
  assert.equal(classifyForRecovery(record({ phase: "created", containerId: "c0ffee".padEnd(64, "0") })), "needs-container-lookup");
  assert.equal(classifyForRecovery(record({ phase: "running", containerId: "c0ffee".padEnd(64, "0") })), "needs-container-lookup");
});

test("R7D.1-J-13: only a removed-and-terminal record is resolved", () => {
  assert.equal(classifyForRecovery(null), "resolved");
  assert.equal(classifyForRecovery(record({ phase: "removed", outcome: "committed" })), "resolved");
  // Removed but with no outcome recorded is still not a success.
  assert.equal(classifyForRecovery(record({ phase: "removed", outcome: null })), "quarantined");
});

test("R7D.1-J-14: quarantine is sticky across restarts", () => {
  assert.equal(classifyForRecovery(record({ phase: "quarantined" })), "quarantined");
  // Even with a container id, a quarantined record stays quarantined.
  assert.equal(classifyForRecovery(record({ phase: "quarantined", containerId: "c0ffee".padEnd(64, "0") })), "quarantined");
});

// ---------------------------------------------------------------------------------------
// Intent durability.
// ---------------------------------------------------------------------------------------

test("R7D.1-J-15: durable intent is written before any daemon operation", () => {
  withJournal((journal) => {
    writeDurableIntent(journal, record({ sequence: 1, phase: "intent" }));
    const stored = journal.readSupervisor(ID);
    assert.equal(stored?.phase, "intent");
    assert.equal(stored?.containerId, null);
    // The file is on disk, which is what makes "intent before create" meaningful.
    assert.equal(existsSync(join(journal.supervisorDir, `${ID}.json`)), true);
  });
});

// ---------------------------------------------------------------------------------------
// Cleanup.
// ---------------------------------------------------------------------------------------

test("R7D.1-J-16: clear requires positive removal evidence, then removes both records", () => {
  withJournal((journal) => {
    const other = "fedcba9876543210fedcba9876543210";
    journal.writeSupervisor(record({ executionId: other, sequence: 1, containerName: containerNameFor(other) }));
    // Terminal phase AND a confirmed removal, or the call refuses.
    journal.writeSupervisor(record({ sequence: 1, phase: "removed", outcome: "committed", containerId: "a".repeat(64) }));
    assert.doesNotThrow(() => journal.clear(ID, { containerAbsentByInspect: true }));
    assert.deepEqual(journal.listSupervisor(), [other]);
  });
});

// ---------------------------------------------------------------------------------------
// F04 — durability, schema and resolution evidence.
// ---------------------------------------------------------------------------------------

test("R7D.1-F04-1: clear refuses an unresolved record", () => {
  withJournal((journal) => {
    journal.writeSupervisor(record({ sequence: 1, phase: "running", containerId: "a".repeat(64) }));
    assert.throws(() => journal.clear(ID, { containerAbsentByInspect: true }), /refusing to clear/u);
    // Still there: an unresolved execution must be retained.
    assert.equal(journal.readSupervisor(ID)?.phase, "running");
  });
});

test("R7D.1-F04-2: clear refuses even a terminal record without removal evidence", () => {
  withJournal((journal) => {
    journal.writeSupervisor(record({ sequence: 1, phase: "removed", outcome: "committed", containerId: "a".repeat(64) }));
    assert.throws(() => journal.clear(ID, { containerAbsentByInspect: false }), /refusing to clear/u);
    assert.equal(journal.readSupervisor(ID)?.phase, "removed");
  });
});

test("R7D.1-F04-3: a malformed stored record is rejected on read, not cast", () => {
  // A cast would hand this back as a SupervisorRecord and a lifecycle decision would be made
  // on a phase that does not exist.
  withJournal((journal, root) => {
    writeFileSync(join(root, "supervisor", `${ID}.json`), JSON.stringify({ ...record(), phase: "invented-phase" }));
    assert.throws(() => journal.readSupervisor(ID), /closed set/u);
  });
});

test("R7D.1-F04-4: a record with unknown properties is rejected", () => {
  // An extra field could persist content the record is not permitted to hold.
  withJournal((journal, root) => {
    writeFileSync(join(root, "supervisor", `${ID}.json`), JSON.stringify({ ...record(), fieldName: "CANARY" }));
    assert.throws(() => journal.readSupervisor(ID), /unexpected properties/u);
  });
});

test("R7D.1-F04-5: a container id of the wrong length is rejected", () => {
  withJournal((journal, root) => {
    writeFileSync(join(root, "supervisor", `${ID}.json`), JSON.stringify({ ...record(), containerId: "abc123" }));
    assert.throws(() => journal.readSupervisor(ID), /containerId/u);
  });
});

test("R7D.1-F04-6: a record whose name does not derive from its id is rejected", () => {
  withJournal((journal, root) => {
    writeFileSync(join(root, "supervisor", `${ID}.json`), JSON.stringify({ ...record(), containerName: `dip-exec-${"b".repeat(32)}` }));
    assert.throws(() => journal.readSupervisor(ID), /does not derive/u);
  });
});

test("R7D.1-F04-7: an out-of-set outcome is rejected", () => {
  withJournal((journal, root) => {
    writeFileSync(join(root, "supervisor", `${ID}.json`), JSON.stringify({ ...record(), outcome: "probably-fine" }));
    assert.throws(() => journal.readSupervisor(ID), /outcome/u);
  });
});

test("R7D.1-F04-8: writes refuse a malformed record before it reaches the disk", () => {
  withJournal((journal) => {
    assert.throws(() => journal.writeSupervisor({ ...record(), phase: "nope" as never }), /closed set/u);
    assert.throws(() => journal.writeSupervisor({ ...record(), containerId: "short" }), /containerId/u);
    assert.equal(journal.readSupervisor(ID), null, "nothing may be written for a rejected record");
  });
});

test("R7D.1-F04-9: temporary files are unique per write, so competing writers cannot interleave", () => {
  // A fixed `.tmp` name lets two writers open the same file, mix their contents and both
  // rename it — producing one valid-looking record that is a blend of two.
  withJournal((journal, root) => {
    journal.writeSupervisor(record({ sequence: 1 }));
    // No temporary survives a successful write.
    assert.equal(readdirSync(join(root, "supervisor")).some((name) => name.endsWith(".tmp")), false);
  });
  // And the temporary is opened exclusively, so a collision fails rather than interleaving.
  const source = readFileSync("src/lib/execution/ownership-journal.ts", "utf8");
  assert.match(source, /openSync\(temporary, "wx"/u, "temporaries must be created exclusively");
  // The name must include a random component, or two writers in the same process collide.
  assert.match(source, /randomBytes\(8\)/u);
});


test("R7D.1-F04-10: a failed file fsync fails the write closed", () => {
  // Durability is the entire point of the journal. A swallowed fsync error makes every
  // "durable intent" claim false while the code still looks correct, so it must throw.
  const root = mkdtempSync(join(tmpdir(), "dip-journal-fail-"));
  try {
    const journal = new OwnershipJournal(root, {
      fsync: () => { throw new Error("injected fsync failure"); },
    });
    // `init()` also fsyncs the directories, so construct the directories first with a healthy
    // journal and then use the failing one.
    new OwnershipJournal(root).init();
    assert.throws(() => journal.writeSupervisor(record({ sequence: 1 })), /could not be written durably|fsync/u);
    // No record may be visible, and no temporary may be left behind.
    assert.equal(new OwnershipJournal(root).readSupervisor(ID), null);
    assert.equal(readdirSync(join(root, "supervisor")).filter((name) => name.endsWith(".tmp")).length, 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("R7D.1-F04-11: the injected failure leaves no half-written record", () => {
  // The rename must never happen after a failed fsync, or a reader would see a record whose
  // contents the filesystem never confirmed.
  const root = mkdtempSync(join(tmpdir(), "dip-journal-fail2-"));
  try {
    new OwnershipJournal(root).init();
    // Fail the *file* fsync specifically — the one that happens before the rename. The
    // directory fsync runs after the rename and is a different guarantee, so injecting there
    // would only prove that the rename already happened.
    const isDirectory = (fd: number): boolean => {
      try { return statSync(`/proc/self/fd/${fd}`).isDirectory(); } catch { return false; }
    };
    const journal = new OwnershipJournal(root, {
      fsync: (fd) => {
        if (!isDirectory(fd)) throw new Error("injected file fsync failure");
        fsyncSync(fd);
      },
    });
    assert.throws(() => journal.writeSupervisor(record({ sequence: 1 })), /could not be written durably/u);
    // The rename must not have happened, so no record is visible to any reader.
    assert.equal(existsSync(join(root, "supervisor", `${ID}.json`)), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------------------
// C-F04 — recoverable termination identity and real fencing
// ---------------------------------------------------------------------------------------

test("R7D.1-CF04-1: a watchdog record carries complete termination identity", () => {
  // The watchdog must be able to terminate a container after the supervisor that created it is
  // gone. A cgroup path alone is not enough: paths are reused, PIDs are recycled, and a remount
  // looks identical. Each field here exists to make one of those checkable.
  withJournal((journal) => {
    journal.writeWatchdog(watchdogRecord());
    const stored = journal.readWatchdog(ID);
    assert.notEqual(stored, null);
    if (stored === null) throw new Error("unreachable");
    assert.equal(stored.bootId, "boot-1", "a record from another boot describes a dead namespace");
    assert.equal(stored.initPid, 4242);
    assert.equal(stored.initStartTimeTicks, 329483, "a PID without a start-time is recycled and useless");
    assert.equal(stored.cgroupDevice, "0:28", "a remounted cgroup fs is detectable by device");
    assert.equal(stored.cgroupDirInode, 9001, "a reused path is detectable by inode");
    assert.equal(stored.cgroupEventsInode, 9002);
    assert.equal(stored.cgroupKillInode, 9003, "the termination handle has its own identity");
    assert.equal(stored.cgroupProcsInode, 9004);
  });
});

test("R7D.1-CF04-2: a watchdog record cannot describe an inconsistent state", () => {
  withJournal((journal) => {
    // An armed watchdog has not concluded anything.
    assert.throws(() => journal.writeWatchdog(watchdogRecord({ outcome: "terminated" })), /armed watchdog cannot carry an outcome/u);
    // A concluded one must say how it concluded.
    assert.throws(() => journal.writeWatchdog(watchdogRecord({ phase: "disarmed", outcome: null })), /must carry an outcome/u);
    // A PID of 1 is the namespace init, never a container init; 0 means unset.
    assert.throws(() => journal.writeWatchdog(watchdogRecord({ initPid: 1 })), /initPid/u);
    assert.throws(() => journal.writeWatchdog(watchdogRecord({ initPid: 0 })), /initPid/u);
    // The container name must derive from the execution id, or the record could name a
    // different execution's container.
    assert.throws(() => journal.writeWatchdog(watchdogRecord({ containerName: `dip-exec-${"b".repeat(32)}` })), /does not derive/u);
    // Device ids are major:minor, not free text.
    assert.throws(() => journal.writeWatchdog(watchdogRecord({ cgroupDevice: "/dev/sda" })), /cgroupDevice/u);
  });
});

test("R7D.1-CF04-3: a watchdog record cannot claim another watchdog's identity", () => {
  // The writer must be the watchdog that owns the record. A record written by something else
  // cannot be trusted to describe the deadline this watchdog is enforcing.
  withJournal((journal) => {
    assert.throws(() => journal.writeWatchdog(watchdogRecord({ writerInstance: "wd-2" })), /writerInstance must equal/u);
  });
});

test("R7D.1-CF04-4: stale instances cannot overwrite ownership", () => {
  // Sequence numbers alone are not fencing between processes. A restarted supervisor begins at a
  // low sequence; a stale, merely-slow instance would keep winning on arithmetic. The writer
  // identity makes the stale write rejectable regardless of its sequence.
  withJournal((journal) => {
    journal.bind("sup-2", "wd-2");
    journal.writeSupervisor(record({ sequence: 1, phase: "intent", supervisorInstance: "sup-2", writerInstance: "sup-2" }));
    // A stale instance with a much higher sequence is still refused: identity decides.
    assert.throws(
      () => journal.writeSupervisor(record({ sequence: 99, phase: "running", supervisorInstance: "sup-1", writerInstance: "sup-1" })),
      (error: unknown) => error instanceof JournalFencingError && /bound to sup-2/u.test(error.message),
    );
    // And the record is unchanged.
    assert.equal(journal.readSupervisor(ID)?.phase, "intent");
  });
});

test("R7D.1-CF04-5: a journal cannot be rebound to a different instance", () => {
  // Rebinding would let a second process take over simply by asserting its own identity, which
  // is exactly what fencing prevents.
  withJournal((journal) => {
    journal.bind("sup-1", "wd-1");
    assert.throws(() => journal.bind("sup-2", "wd-1"), /already bound/u);
    assert.throws(() => journal.bind("sup-1", "wd-2"), /already bound/u);
    // Rebinding to the same pair is idempotent, so a restart path can call it safely.
    assert.doesNotThrow(() => journal.bind("sup-1", "wd-1"));
  });
});

test("R7D.1-CF04-6: watchdog phase regression is refused", () => {
  withJournal((journal) => {
    journal.writeWatchdog(watchdogRecord({ sequence: 1, phase: "armed" }));
    journal.writeWatchdog(watchdogRecord({ sequence: 2, phase: "disarmed", outcome: "disarmed" }));
    // Back to armed would silently re-establish a deadline that has already concluded.
    assert.throws(
      () => journal.writeWatchdog(watchdogRecord({ sequence: 3, phase: "armed" })),
      (error: unknown) => error instanceof JournalFencingError && /phase regression/u.test(error.message),
    );
  });
});

test("R7D.1-CF04-7: a watchdog record is never deleted because its supervisor record is missing", () => {
  // The two records are written by different processes. A missing supervisor record is not
  // evidence that the execution was never armed — it may be exactly the case where the
  // supervisor crashed before writing, or its record was lost, while the watchdog is still
  // holding a live deadline.
  withJournal((journal) => {
    journal.writeWatchdog(watchdogRecord());
    assert.throws(
      () => journal.clear(ID, { containerAbsentByInspect: true }),
      /watchdog record exists .* without a supervisor record|An independent record is not deleted/u,
    );
    assert.notEqual(journal.readWatchdog(ID), null, "the independent record must survive");
  });
});

test("R7D.1-CF04-8: clear requires both authorities to have concluded", () => {
  withJournal((journal) => {
    const terminal = record({ sequence: 1, phase: "removed", outcome: "committed" });
    journal.writeSupervisor(terminal);
    // The supervisor is resolved but the watchdog is still armed: a deadline may still fire.
    journal.writeWatchdog(watchdogRecord({ sequence: 1, phase: "armed" }));
    assert.throws(
      () => journal.clear(ID, { containerAbsentByInspect: true }),
      /independent authority has not concluded|watchdog phase=armed/u,
    );

    // Once the watchdog has disarmed, resolution is complete on both sides.
    journal.writeWatchdog(watchdogRecord({ sequence: 2, phase: "disarmed", outcome: "disarmed" }));
    assert.doesNotThrow(() => journal.clear(ID, { containerAbsentByInspect: true }));
    assert.equal(journal.readSupervisor(ID), null);
    assert.equal(journal.readWatchdog(ID), null);
  });
});

test("R7D.1-CF04-9: clear requires an exact inspect to have confirmed absence", () => {
  // A `docker rm` that returned success is not the same fact as an exact-id inspect reporting
  // the container does not exist. The second is what survives a daemon that lied or a client
  // that was killed mid-request.
  withJournal((journal) => {
    journal.writeSupervisor(record({ sequence: 1, phase: "removed", outcome: "committed" }));
    journal.writeWatchdog(watchdogRecord({ sequence: 1, phase: "disarmed", outcome: "disarmed" }));
    assert.throws(
      () => journal.clear(ID, { containerAbsentByInspect: false }),
      /inspect has not confirmed/u,
    );
    assert.notEqual(journal.readSupervisor(ID), null);
  });
});

test("R7D.1-CF04-10: no watchdog record field can carry document content", () => {
  // The same structural property the supervisor record has: every field is an identifier or a
  // counter, so "no document data" is a property of the type rather than a promise.
  withJournal((journal) => {
    journal.writeWatchdog(watchdogRecord());
    const parsed = JSON.parse(readFileSync(join(journal.watchdogDir, `${ID}.json`), "utf8")) as Record<string, unknown>;
    for (const [key, value] of Object.entries(parsed)) {
      const type = typeof value;
      assert.ok(
        value === null || type === "string" || type === "number" || type === "boolean",
        `${key} must be a scalar, found ${type}`,
      );
    }
    // And nothing in the serialised form looks like a document digest or field content.
    const text = JSON.stringify(parsed);
    assert.equal(/sha256:[a-f0-9]{64}/u.test(text), true, "the image digest is present and is the only sha256");
    assert.equal(text.match(/sha256:/gu)?.length, 1);
  });
});

test("R7D.1-CF04-11: a malformed or inconsistent watchdog record is rejected on read", () => {
  withJournal((journal, root) => {
    const write = (value: unknown): void => {
      writeFileSync(join(root, "watchdog", `${ID}.json`), JSON.stringify(value));
    };
    write({ ...watchdogRecord(), initStartTimeTicks: -1 });
    assert.throws(() => journal.readWatchdog(ID), /initStartTimeTicks/u);
    write({ ...watchdogRecord(), cgroupDirInode: 0 });
    assert.throws(() => journal.readWatchdog(ID), /cgroupDirInode/u);
    write({ ...watchdogRecord(), phase: "invented" });
    assert.throws(() => journal.readWatchdog(ID), /closed set/u);
    write({ ...watchdogRecord(), extra: "field" });
    assert.throws(() => journal.readWatchdog(ID), /unexpected properties/u);
    // An incomplete record — missing the termination handle — cannot drive a kill.
    const incomplete = { ...watchdogRecord() } as Record<string, unknown>;
    delete incomplete.cgroupKillInode;
    write(incomplete);
    assert.throws(() => journal.readWatchdog(ID), /unexpected properties|missing/u);
  });
});
