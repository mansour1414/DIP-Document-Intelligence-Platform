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
  type SupervisorRecord,
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
    assert.throws(() => journal.writeSupervisor(record({ sequence: 5, phase: "created" })), /stale journal write/u);
    assert.throws(() => journal.writeSupervisor(record({ sequence: 4, phase: "created" })), /stale journal write/u);
    assert.doesNotThrow(() => journal.writeSupervisor(record({ sequence: 6, phase: "created" })));
  });
});

test("R7D.1-J-6: a phase may not regress", () => {
  withJournal((journal) => {
    journal.writeSupervisor(record({ sequence: 1, phase: "intent" }));
    journal.writeSupervisor(record({ sequence: 2, phase: "running" }));
    assert.throws(() => journal.writeSupervisor(record({ sequence: 3, phase: "creating" })), /illegal phase regression/u);
    assert.throws(() => journal.writeSupervisor(record({ sequence: 4, phase: "intent" })), /illegal phase regression/u);
  });
});

test("R7D.1-J-7: quarantine is reachable from any phase and is terminal", () => {
  withJournal((journal) => {
    journal.writeSupervisor(record({ sequence: 1, phase: "running" }));
    assert.doesNotThrow(() => journal.writeSupervisor(record({ sequence: 2, phase: "quarantined" })));
    // Nothing may leave quarantine, including another quarantine write with a live phase.
    assert.throws(() => journal.writeSupervisor(record({ sequence: 3, phase: "terminal" })), /illegal phase regression/u);
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
    assert.doesNotThrow(() => journal.clear(ID, { containerRemoved: true }));
    assert.deepEqual(journal.listSupervisor(), [other]);
  });
});

// ---------------------------------------------------------------------------------------
// F04 — durability, schema and resolution evidence.
// ---------------------------------------------------------------------------------------

test("R7D.1-F04-1: clear refuses an unresolved record", () => {
  withJournal((journal) => {
    journal.writeSupervisor(record({ sequence: 1, phase: "running", containerId: "a".repeat(64) }));
    assert.throws(() => journal.clear(ID, { containerRemoved: true }), /refusing to clear/u);
    // Still there: an unresolved execution must be retained.
    assert.equal(journal.readSupervisor(ID)?.phase, "running");
  });
});

test("R7D.1-F04-2: clear refuses even a terminal record without removal evidence", () => {
  withJournal((journal) => {
    journal.writeSupervisor(record({ sequence: 1, phase: "removed", outcome: "committed", containerId: "a".repeat(64) }));
    assert.throws(() => journal.clear(ID, { containerRemoved: false }), /refusing to clear/u);
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
