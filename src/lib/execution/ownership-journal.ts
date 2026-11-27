/**
 * Crash-safe metadata-only ownership journal (R7D.1 §13).
 *
 * ## What is in the journal, and what can never be
 *
 * Only identities and lifecycle facts: an opaque execution id, a boot id, a supervisor
 * instance id, a container id when known, the image digest, the profile, a monotonic
 * deadline, and a sequence number.
 *
 * Never: document bytes, field names, field values, document hashes, storage keys,
 * credentials, or raw diagnostics. Those four exclusions are the ones that are easy to get
 * wrong by accident — a "helpful" error message carrying a field name would violate §13 and
 * §19 through the back door, so the record type below is a closed union with no free-form
 * string field.
 *
 * ## Why two files per execution
 *
 * Supervisor-owned and Watchdog-owned state are separate files in separate directories.
 * A single file would mean the supervisor could observe its own intent and mistake it for
 * the watchdog's independent confirmation — precisely the defect §16 says the abandoned
 * implementation had, where a file's existence stood in for a live armed deadline.
 *
 * ## Why the write is an atomic replace
 *
 * `rename` within one filesystem is atomic, so a reader sees either the old record or the
 * new one and never a torn mixture. Writing in place would allow a crash mid-write to leave
 * a valid-looking but partially updated record — and a partially updated lifecycle record is
 * worse than a missing one, because it looks authoritative.
 *
 * The directory is fsync'd after the rename. Without that, the rename is durable in the
 * filesystem's metadata only in memory, and a host crash can lose the record entirely.
 */

import { randomBytes } from "node:crypto";
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, unlinkSync, writeFileSync, writeSync, existsSync } from "node:fs";
import { join } from "node:path";

/**
 * A durability operation failed.
 *
 * Distinct from a policy refusal: this means the filesystem did not confirm the write. The
 * caller must treat the record as absent and quarantine, never as written.
 */
export class JournalDurabilityError extends Error {
  constructor(message: string, readonly cause?: unknown) {
    super(message);
    this.name = "JournalDurabilityError";
  }
}

/**
 * A stored record failed schema validation.
 *
 * Also distinct: the file exists but does not describe anything trustworthy. Treated as
 * quarantine, because a record that cannot be read is an execution whose ownership cannot be
 * positively resolved.
 */
export class JournalSchemaError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JournalSchemaError";
  }
}

/** Lifecycle phases, in the only order they may occur. */
export const JOURNAL_PHASES = [
  /** Intent recorded; no daemon operation issued yet. */
  "intent",
  /** `docker create` issued. A container may or may not exist. */
  "creating",
  /** Container id known. */
  "created",
  /** `docker start` issued. */
  "starting",
  /** Watchdog armed and acknowledged. */
  "armed",
  /** Body transfer and execution in progress. */
  "running",
  /** Terminal outcome recorded. */
  "terminal",
  /** Container removal confirmed. */
  "removed",
  /** Ownership could not be positively resolved. Admission blocked. */
  "quarantined",
] as const;

export type JournalPhase = (typeof JOURNAL_PHASES)[number];

/** The distance each phase may advance to. Used to fence stale transitions. */
const PHASE_ORDER: Readonly<Record<JournalPhase, number>> = Object.freeze({
  intent: 0,
  creating: 1,
  created: 2,
  starting: 3,
  armed: 4,
  running: 5,
  terminal: 6,
  removed: 7,
  // Quarantine is terminal and reachable from anywhere; it is ordered last so any live
  // phase may move into it, and nothing may move out.
  quarantined: 8,
});

/**
 * A supervisor-owned record.
 *
 * Every field is an identifier or a counter. There is no free-form text field, which is
 * what makes "no field names or values" a structural property rather than a promise.
 */
export type SupervisorRecord = {
  schema: 1;
  executionId: string;
  bootId: string;
  supervisorInstance: string;
  containerName: string;
  /** Present once `docker create` has reported an id. */
  containerId: string | null;
  imageDigest: string;
  profileId: string;
  /** Monotonic deadline in milliseconds, interpreted against `bootId` + boot clock. */
  deadlineMs: number;
  /** Monotonic clock reading at intent time. Paired with bootId; never a wall clock. */
  startedMonotonicMs: number;
  phase: JournalPhase;
  /** Monotonically increasing; a lower value never overwrites a higher one. */
  sequence: number;
  /** Set only in `terminal`, and only from a closed vocabulary. */
  outcome: null | "committed" | "refused" | "timeout" | "cancelled" | "failed";
};

/** A watchdog-owned record. Deliberately a different file from the supervisor's. */
export type WatchdogRecord = {
  schema: 1;
  executionId: string;
  bootId: string;
  watchdogInstance: string;
  containerId: string;
  /** Verified cgroup path, which is the identity the watchdog actually enforces against. */
  cgroupPath: string;
  /** The `cgroup.events` inode at arm time, so a re-created cgroup is detectable. */
  cgroupEventsInode: number;
  deadlineMs: number;
  startedMonotonicMs: number;
  phase: "armed" | "disarmed" | "expired" | "quarantined";
  sequence: number;
};

// ---------------------------------------------------------------------------------------
// Strict schema validation
// ---------------------------------------------------------------------------------------
//
// TypeScript types vanish at run time. A `SupervisorRecord` annotation guarantees nothing
// about a parsed JSON file, and a cast would let an edited or truncated record drive a
// lifecycle decision. These validators are the runtime contract.

/**
 * Require an object with exactly `allowed` keys.
 *
 * Unknown properties are rejected rather than ignored: a record carrying a field this schema
 * does not define is either a schema mismatch or an attempt to persist something the record is
 * not permitted to hold. Both should stop the read.
 */
function assertExactKeys(value: unknown, allowed: readonly string[], what: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new JournalSchemaError(`${what} is not an object`);
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const expected = [...allowed].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    const unexpected = keys.filter((key) => !expected.includes(key));
    throw new JournalSchemaError(`${what} has unexpected properties: ${unexpected.join(", ") || "(missing keys)"}`);
  }
  return record;
}

function assertString(value: unknown, what: string, pattern: RegExp): string {
  if (typeof value !== "string" || !pattern.test(value)) throw new JournalSchemaError(`${what} is not an acceptable string`);
  return value;
}

function assertNumber(value: unknown, what: string, min: number, max = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max) {
    throw new JournalSchemaError(`${what} is not an acceptable integer`);
  }
  return value;
}

const SUPERVISOR_KEYS = [
  "schema", "executionId", "bootId", "supervisorInstance", "containerName",
  "containerId", "imageDigest", "profileId", "deadlineMs", "startedMonotonicMs",
  "phase", "sequence", "outcome",
] as const;

const WATCHDOG_KEYS = [
  "schema", "executionId", "bootId", "watchdogInstance", "containerId",
  "cgroupPath", "cgroupEventsInode", "deadlineMs", "startedMonotonicMs", "phase", "sequence",
] as const;

/** Validate a supervisor record. Used on write and on read. */
export function assertSupervisorRecord(value: unknown): SupervisorRecord {
  const record = assertExactKeys(value, SUPERVISOR_KEYS, "supervisor record");
  if (record.schema !== 1) throw new JournalSchemaError("supervisor record schema must be 1");
  const executionId = assertString(record.executionId, "executionId", /^[a-f0-9]{32}$/u);
  const containerName = assertString(record.containerName, "containerName", /^dip-exec-[a-f0-9]{32}$/u);
  if (containerName !== `dip-exec-${executionId}`) throw new JournalSchemaError("containerName does not derive from executionId");
  const phase = record.phase;
  if (typeof phase !== "string" || !(JOURNAL_PHASES as readonly string[]).includes(phase)) {
    throw new JournalSchemaError("phase is not in the closed set");
  }
  const outcome = record.outcome;
  const OUTCOMES = ["committed", "refused", "timeout", "cancelled", "failed"];
  if (outcome !== null && (typeof outcome !== "string" || !OUTCOMES.includes(outcome))) {
    throw new JournalSchemaError("outcome is not in the closed set");
  }
  // A container id is all-hex or absent. A partial id is not a shorter identifier, it is a
  // record that cannot be used to reconcile anything.
  if (record.containerId !== null) assertString(record.containerId, "containerId", /^[a-f0-9]{64}$/u);
  assertString(record.imageDigest, "imageDigest", /^sha256:[a-f0-9]{64}$/u);
  assertString(record.bootId, "bootId", /^[a-z0-9-]{4,64}$/u);
  assertString(record.supervisorInstance, "supervisorInstance", /^[a-z0-9-]{4,64}$/u);
  assertString(record.profileId, "profileId", /^[a-z0-9-]{4,64}$/u);
  assertNumber(record.deadlineMs, "deadlineMs", 1);
  assertNumber(record.startedMonotonicMs, "startedMonotonicMs", 0);
  assertNumber(record.sequence, "sequence", 1);
  return value as SupervisorRecord;
}

export function parseSupervisorRecord(value: unknown): SupervisorRecord {
  return assertSupervisorRecord(value);
}

/** Validate a watchdog record. Used on write and on read. */
export function assertWatchdogRecord(value: unknown): WatchdogRecord {
  const record = assertExactKeys(value, WATCHDOG_KEYS, "watchdog record");
  if (record.schema !== 1) throw new JournalSchemaError("watchdog record schema must be 1");
  assertString(record.executionId, "executionId", /^[a-f0-9]{32}$/u);
  assertString(record.bootId, "bootId", /^[a-z0-9-]{4,64}$/u);
  assertString(record.watchdogInstance, "watchdogInstance", /^[a-z0-9-]{4,64}$/u);
  assertString(record.containerId, "containerId", /^[a-f0-9]{64}$/u);
  // A cgroup path is an absolute kernel path; anything else is not one.
  assertString(record.cgroupPath, "cgroupPath", /^\/sys\/fs\/cgroup\/[A-Za-z0-9._/-]+$/u);
  assertNumber(record.cgroupEventsInode, "cgroupEventsInode", 1);
  assertNumber(record.deadlineMs, "deadlineMs", 1);
  assertNumber(record.startedMonotonicMs, "startedMonotonicMs", 0);
  const phase = record.phase;
  if (phase !== "armed" && phase !== "disarmed" && phase !== "expired" && phase !== "quarantined") {
    throw new JournalSchemaError("watchdog phase is not in the closed set");
  }
  assertNumber(record.sequence, "sequence", 1);
  return value as WatchdogRecord;
}

export function parseWatchdogRecord(value: unknown): WatchdogRecord {
  return assertWatchdogRecord(value);
}

/** Validate an opaque execution id: hex only, so it cannot smuggle a path separator. */
export function assertExecutionId(id: string): void {
  if (!/^[a-f0-9]{32}$/u.test(id)) throw new Error("execution id must be 32 lowercase hex characters");
}

export function newExecutionId(randomBytes: (size: number) => Buffer): string {
  return randomBytes(16).toString("hex");
}

/** Validate a container name derived from an execution id. */
export function containerNameFor(executionId: string): string {
  assertExecutionId(executionId);
  return `dip-exec-${executionId}`;
}

/**
 * The journal, rooted at two sibling directories so the two authorities cannot collide.
 *
 * The root is created with mode 0700: the records are metadata-only, but they still
 * describe running containers and their cgroups, which is information an unrelated local
 * user has no reason to read.
 */
export class OwnershipJournal {
  readonly supervisorDir: string;
  readonly watchdogDir: string;
  /**
   * The fsync primitive.
   *
   * Injectable so the durability failure path can be exercised. Without this the only way to
   * test "a failed fsync must fail closed" is to corrupt a filesystem, which is not something a
   * test suite should do — and the path would then never be covered at all.
   */
  private readonly fsync: (fd: number) => void;

  constructor(root: string, options: { fsync?: (fd: number) => void } = {}) {
    this.supervisorDir = join(root, "supervisor");
    this.watchdogDir = join(root, "watchdog");
    this.fsync = options.fsync ?? ((fd: number) => fsyncSync(fd));
  }

  /** Create both directories, durable against a crash immediately after. */
  init(): void {
    for (const dir of [this.supervisorDir, this.watchdogDir]) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      this.fsyncDir(dir);
    }
  }

  private supervisorPath(executionId: string): string {
    assertExecutionId(executionId);
    return join(this.supervisorDir, `${executionId}.json`);
  }

  private watchdogPath(executionId: string): string {
    assertExecutionId(executionId);
    return join(this.watchdogDir, `${executionId}.json`);
  }

  /**
   * Atomically replace a file's contents and fsync the directory.
   *
   * The temporary name is derived from the target so two concurrent writers target the same
   * temporary file and one of them wins the rename — which is correct, because the sequence
   * check rejects the loser's content if it is stale.
   */
  private atomicWrite(path: string, contents: string): void {
    // A fixed `.tmp` name is unsafe under competing writes: two writers open the same file,
    // interleave their contents, and both rename it into place. The result is one valid-looking
    // record containing a mixture of two. The name is therefore unique per write, created
    // exclusively (`wx` fails if it somehow exists), and removed on any failure path.
    const temporary = `${path}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
    let fd: number | undefined;
    try {
      fd = openSync(temporary, "wx", 0o600);
      writeSync(fd, contents);
      // fsync the file before the rename, so the renamed entry points at durable content and
      // not at a page cache entry a crash can still lose.
      this.fsync(fd);
    } catch (error) {
      // Fail closed. An unwritten or fsync-less intent record is not a durable intent, and
      // continuing would mean the daemon is asked to create a container the journal cannot
      // describe after a crash.
      if (fd !== undefined) {
        try { closeSync(fd); } catch { /* already failing */ }
        fd = undefined;
      }
      try { unlinkSync(temporary); } catch { /* nothing to remove */ }
      throw new JournalDurabilityError("the journal record could not be written durably", error);
    } finally {
      if (fd !== undefined) closeSync(fd);
    }
    renameSync(temporary, path);
    // A directory fsync that fails means the rename may not survive a crash. That is exactly
    // the condition the journal exists to rule out, so it is an error, not a note.
    this.fsyncDir(path.slice(0, path.lastIndexOf("/")));
  }

  /**
   * fsync a directory, or fail.
   *
   * The previous version swallowed the error with a comment about portability. That is wrong
   * for this file: durability of the rename is the entire reason the journal is crash-safe, and
   * a silently skipped fsync makes every "durable intent" claim false while leaving the code
   * looking correct. If the filesystem genuinely cannot fsync a directory, that is a property
   * to discover at start-up, not to hide per write.
   */
  private fsyncDir(dir: string): void {
    let fd: number | undefined;
    try {
      fd = openSync(dir, "r");
      this.fsync(fd);
    } catch (error) {
      throw new JournalDurabilityError(`the journal directory ${dir} could not be fsync'd`, error);
    } finally {
      if (fd !== undefined) closeSync(fd);
    }
  }

  /**
   * Read a supervisor record, validating it strictly.
   *
   * A cast would be the same mistake as the protocol decoder's: it would hand back whatever
   * the file contained, and a hand-edited or partially-written record — a phase from an older
   * schema, a container id of the wrong length — would then drive a lifecycle decision.
   */
  readSupervisor(executionId: string): SupervisorRecord | null {
    const path = this.supervisorPath(executionId);
    if (!existsSync(path)) return null;
    return parseSupervisorRecord(JSON.parse(readFileSync(path, "utf8")));
  }

  readWatchdog(executionId: string): WatchdogRecord | null {
    const path = this.watchdogPath(executionId);
    if (!existsSync(path)) return null;
    return parseWatchdogRecord(JSON.parse(readFileSync(path, "utf8")));
  }

  /**
   * Advance a supervisor record, fencing stale transitions.
   *
   * Two things are refused: moving backwards in the phase order, and writing a sequence
   * that is not strictly greater than the stored one. The second is what stops a supervisor
   * that lost a race — or a restarted instance working from an old snapshot — from
   * reasserting an earlier view of the world.
   */
  writeSupervisor(record: SupervisorRecord): void {
    // Validate the record itself before it reaches the disk. A caller that built a malformed
    // record — a phase not in the closed set, a container id of the wrong length — must fail
    // here, while the caller still has the context to handle it.
    assertSupervisorRecord(record);
    assertExecutionId(record.executionId);
    const previous = this.readSupervisor(record.executionId);
    if (previous) {
      if (record.sequence <= previous.sequence) {
        throw new Error(`stale journal write: sequence ${record.sequence} is not greater than ${previous.sequence}`);
      }
      if (PHASE_ORDER[record.phase] < PHASE_ORDER[previous.phase] && record.phase !== "quarantined") {
        throw new Error(`illegal phase regression: ${previous.phase} -> ${record.phase}`);
      }
    }
    this.atomicWrite(this.supervisorPath(record.executionId), JSON.stringify(record));
  }

  writeWatchdog(record: WatchdogRecord): void {
    assertWatchdogRecord(record);
    assertExecutionId(record.executionId);
    const previous = this.readWatchdog(record.executionId);
    if (previous && record.sequence <= previous.sequence) {
      throw new Error(`stale watchdog write: sequence ${record.sequence} is not greater than ${previous.sequence}`);
    }
    this.atomicWrite(this.watchdogPath(record.executionId), JSON.stringify(record));
  }

  /** Execution ids present in the supervisor directory. */
  listSupervisor(): string[] {
    return this.listDir(this.supervisorDir, ".json");
  }

  listWatchdog(): string[] {
    return this.listDir(this.watchdogDir, ".json");
  }

  private listDir(dir: string, suffix: string): string[] {
    if (!existsSync(dir)) return [];
    return readdirSync(dir)
      // A leftover `.tmp` is an interrupted write. It is not a record and must never be
      // mistaken for one, so it is filtered rather than parsed.
      .filter((name) => name.endsWith(suffix))
      .map((name) => name.slice(0, -suffix.length))
      .filter((id) => /^[a-f0-9]{32}$/u.test(id))
      .sort();
  }

  /**
   * Remove both records, but only with positive evidence that the execution is resolved.
   *
   * The previous version deleted whatever files happened to be there. That let a caller
   * discard an unresolved execution — an execution whose container might still exist — simply
   * by calling it. Removal now requires the record to be in a terminal phase *and* the container
   * to be gone, and refuses otherwise.
   */
  clear(executionId: string, evidence: { containerRemoved: boolean }): void {
    assertExecutionId(executionId);
    const record = this.readSupervisor(executionId);
    if (record !== null) {
      const resolved = record.phase === "removed" && record.outcome !== null;
      if (!resolved || !evidence.containerRemoved) {
        throw new Error(
          `refusing to clear ${executionId}: phase=${record.phase} outcome=${String(record.outcome)} `
          + `containerRemoved=${String(evidence.containerRemoved)}. Retention is required until ownership is positively resolved.`,
        );
      }
    }
    for (const path of [this.supervisorPath(executionId), this.watchdogPath(executionId)]) {
      if (existsSync(path)) unlinkSync(path);
    }
  }
}

/**
 * Classify what a restart must do with a record it finds.
 *
 * The distinction that matters: an execution whose container id is unknown **cannot** be
 * assumed absent. `docker create` may have been issued and not yet returned when the
 * supervisor died, and the container may materialise afterwards. Treating "no id recorded"
 * as "no container" is exactly the assumption §13 forbids.
 */
export function classifyForRecovery(record: SupervisorRecord | null): "resolved" | "needs-container-lookup" | "ambiguous-create" | "quarantined" {
  if (!record) return "resolved";
  if (record.phase === "quarantined") return "quarantined";
  if (record.phase === "removed" && record.outcome !== null) return "resolved";
  if (record.containerId) return "needs-container-lookup";
  // No container id and an in-flight create: the container may still appear.
  if (record.phase === "creating" || record.phase === "intent") return "ambiguous-create";
  return "quarantined";
}

/**
 * Scan-free single write helper used by tests and by the supervisor's intent step.
 *
 * Exported separately so a caller can write an intent record without constructing a whole
 * journal, which is what the intent-before-create ordering requires: the intent must be
 * durable before the daemon is asked to do anything.
 */
export function writeDurableIntent(journal: OwnershipJournal, record: SupervisorRecord): void {
  journal.writeSupervisor(record);
  const path = join(journal.supervisorDir, `${record.executionId}.json`);
  // Re-open and fsync the file after the atomic write, because the intent record is the one
  // that must survive a crash *immediately* after this call returns.
  const fd = openSync(path, "r");
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/** Write a record directly, bypassing sequence fencing. Test-only; not used in production. */
export function unsafeWriteRaw(path: string, value: unknown): void {
  writeFileSync(path, JSON.stringify(value));
}
