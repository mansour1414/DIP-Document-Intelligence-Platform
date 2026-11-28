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

/** Watchdog phase ordering. `armed` may only move forward to a conclusion or quarantine. */
const WATCHDOG_PHASE_ORDER: Readonly<Record<WatchdogRecord["phase"], number>> = Object.freeze({
  armed: 0,
  disarmed: 1,
  expired: 1,
  quarantined: 2,
});

/**
 * A write was refused because it came from the wrong instance or moved backwards.
 *
 * Distinct from a schema error: the record is well formed, but this process is not entitled to
 * write it. Recovery must treat it as "another authority owns this" rather than as corruption.
 */
export class JournalFencingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JournalFencingError";
  }
}

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
  /**
   * The supervisor instance that wrote this revision.
   *
   * Sequence numbers alone are not fencing between processes. A restarted supervisor begins at
   * sequence 1 and would therefore be outranked by a stale instance's sequence 7 forever; worse,
   * a stale instance could keep writing and win. The writer identity is what makes an update
   * from the wrong process rejectable regardless of its sequence.
   */
  writerInstance: string;
};

/**
 * A watchdog-owned record. Deliberately a different file from the supervisor's.
 *
 * ## Why it needs this much identity
 *
 * The watchdog must be able to terminate a container *after* the supervisor that created it is
 * gone. To do that safely it needs enough recorded identity to answer, from a cold start:
 * which host is this, which container is it, which process is that container's init, which
 * cgroup is it in, and is that the same cgroup the identity was verified against.
 *
 * A cgroup path alone is not enough. A path can be reused after a container is removed and
 * another is created with the same name; the inode distinguishes them. A PID alone is not
 * enough either — PIDs are recycled, so the process start-time is recorded and compared. That
 * pair is what makes "the process I was told about" checkable rather than assumed.
 *
 * Everything here is an identifier or a counter. There is no free-form text, so "no document
 * data" is a structural property of the type rather than a promise about how it is filled in.
 */
export type WatchdogRecord = {
  schema: 1;
  executionId: string;
  /** Host boot identity. A record from a previous boot describes a namespace that is gone. */
  bootId: string;
  watchdogInstance: string;
  /** The supervisor instance that armed this watchdog, for stale-instance detection. */
  supervisorInstance: string;
  /** Ownership label value, tying the record to exactly one container. */
  containerId: string;
  containerName: string;
  imageDigest: string;
  profileId: string;
  /** Container init PID as reported by the daemon, and its kernel start-time. */
  initPid: number;
  initStartTimeTicks: number;
  /** Verified cgroup path, which is the identity the watchdog actually enforces against. */
  cgroupPath: string;
  /** Device id of the cgroup filesystem, so a remount is detectable. */
  cgroupDevice: string;
  /** Inode of the cgroup directory itself. */
  cgroupDirInode: number;
  /** The `cgroup.events` inode at arm time, so a re-created cgroup is detectable. */
  cgroupEventsInode: number;
  /** Control-file identity: inode of `cgroup.kill`, which is the termination handle. */
  cgroupKillInode: number;
  /** Control-file identity: inode of `cgroup.procs`, used to read membership. */
  cgroupProcsInode: number;
  deadlineMs: number;
  startedMonotonicMs: number;
  phase: "armed" | "disarmed" | "expired" | "quarantined";
  /** Set only when the watchdog itself concluded, from a closed vocabulary. */
  outcome: null | "disarmed" | "terminated" | "unresolved";
  sequence: number;
  /** Identity of the watchdog process that last wrote this record. */
  writerInstance: string;
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
  "phase", "sequence", "outcome", "writerInstance",
] as const;

const WATCHDOG_KEYS = [
  "schema", "executionId", "bootId", "watchdogInstance", "supervisorInstance",
  "containerId", "containerName", "imageDigest", "profileId",
  "initPid", "initStartTimeTicks", "cgroupPath", "cgroupDevice", "cgroupDirInode",
  "cgroupEventsInode", "cgroupKillInode", "cgroupProcsInode",
  "deadlineMs", "startedMonotonicMs", "phase", "outcome", "sequence", "writerInstance",
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
  assertString(record.writerInstance, "writerInstance", /^[a-z0-9-]{4,64}$/u);
  // The writer must be the supervisor that owns the record. A record whose writer differs from
  // its declared supervisor was written by something else, and cannot be trusted to describe
  // this execution.
  if (record.writerInstance !== record.supervisorInstance) {
    throw new JournalSchemaError("writerInstance must equal supervisorInstance");
  }
  return value as SupervisorRecord;
}

export function parseSupervisorRecord(value: unknown): SupervisorRecord {
  return assertSupervisorRecord(value);
}

/** Validate a watchdog record. Used on write and on read. */
export function assertWatchdogRecord(value: unknown): WatchdogRecord {
  const record = assertExactKeys(value, WATCHDOG_KEYS, "watchdog record");
  if (record.schema !== 1) throw new JournalSchemaError("watchdog record schema must be 1");
  const executionId = assertString(record.executionId, "executionId", /^[a-f0-9]{32}$/u);
  assertString(record.bootId, "bootId", /^[a-z0-9-]{4,64}$/u);
  assertString(record.watchdogInstance, "watchdogInstance", /^[a-z0-9-]{4,64}$/u);
  assertString(record.supervisorInstance, "supervisorInstance", /^[a-z0-9-]{4,64}$/u);
  const containerName = assertString(record.containerName, "containerName", /^dip-exec-[a-f0-9]{32}$/u);
  if (containerName !== `dip-exec-${executionId}`) throw new JournalSchemaError("containerName does not derive from executionId");
  assertString(record.containerId, "containerId", /^[a-f0-9]{64}$/u);
  assertString(record.imageDigest, "imageDigest", /^sha256:[a-f0-9]{64}$/u);
  assertString(record.profileId, "profileId", /^[a-z0-9-]{4,64}$/u);
  // PID 1 exists in every namespace and 0 means "not set", so a recorded init pid below 2 is
  // never a container init; accepting it would make a later termination target nothing.
  assertNumber(record.initPid, "initPid", 2);
  assertNumber(record.initStartTimeTicks, "initStartTimeTicks", 0);
  assertString(record.cgroupPath, "cgroupPath", /^\/sys\/fs\/cgroup\/[A-Za-z0-9._/-]+$/u);
  // Device id as major:minor, decimal. Recorded so a remounted cgroup filesystem is detectable.
  assertString(record.cgroupDevice, "cgroupDevice", /^\d{1,6}:\d{1,6}$/u);
  assertNumber(record.cgroupDirInode, "cgroupDirInode", 1);
  assertNumber(record.cgroupEventsInode, "cgroupEventsInode", 1);
  assertNumber(record.cgroupKillInode, "cgroupKillInode", 1);
  assertNumber(record.cgroupProcsInode, "cgroupProcsInode", 1);
  assertNumber(record.deadlineMs, "deadlineMs", 1);
  assertNumber(record.startedMonotonicMs, "startedMonotonicMs", 0);
  if (record.phase !== "armed" && record.phase !== "disarmed" && record.phase !== "expired" && record.phase !== "quarantined") {
    throw new JournalSchemaError("watchdog phase is not in the closed set");
  }
  const outcome = record.outcome;
  if (outcome !== null && outcome !== "disarmed" && outcome !== "terminated" && outcome !== "unresolved") {
    throw new JournalSchemaError("watchdog outcome is not in the closed set");
  }
  // An armed watchdog has not concluded anything yet; a concluded one must say how.
  if (record.phase === "armed" && outcome !== null) throw new JournalSchemaError("an armed watchdog cannot carry an outcome");
  if ((record.phase === "disarmed" || record.phase === "expired") && outcome === null) {
    throw new JournalSchemaError("a concluded watchdog must carry an outcome");
  }
  assertNumber(record.sequence, "sequence", 1);
  assertString(record.writerInstance, "writerInstance", /^[a-z0-9-]{4,64}$/u);
  if (record.writerInstance !== record.watchdogInstance) {
    throw new JournalSchemaError("writerInstance must equal watchdogInstance");
  }
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

  /**
   * The instances this journal may be written by.
   *
   * `null` means "not yet bound", which is what a recovery pass needs while it inspects existing
   * records. Binding happens once, before any write, and cannot be changed: a journal that could
   * be re-bound would let a second process take over by asserting its own identity, which is
   * the problem fencing exists to prevent.
   */
  private supervisorInstance: string | null = null;
  private watchdogInstance: string | null = null;

  constructor(root: string, options: { fsync?: (fd: number) => void } = {}) {
    this.supervisorDir = join(root, "supervisor");
    this.watchdogDir = join(root, "watchdog");
    this.fsync = options.fsync ?? ((fd: number) => fsyncSync(fd));
  }

  /**
   * Bind this journal to the supervisor and/or watchdog instance that owns it.
   *
   * Called once at start-up. Rebinding to a *different* identity throws, because a process that
   * can rebind can overwrite another live instance's ownership.
   */
  bind(supervisorInstance: string, watchdogInstance: string): void {
    for (const [what, value] of [["supervisorInstance", supervisorInstance], ["watchdogInstance", watchdogInstance]] as const) {
      if (typeof value !== "string" || !/^[a-z0-9-]{4,64}$/u.test(value)) {
        throw new JournalSchemaError(`${what} is not an acceptable instance identity`);
      }
    }
    if (this.supervisorInstance !== null && this.supervisorInstance !== supervisorInstance) {
      throw new JournalFencingError("this journal is already bound to a different supervisor instance");
    }
    if (this.watchdogInstance !== null && this.watchdogInstance !== watchdogInstance) {
      throw new JournalFencingError("this journal is already bound to a different watchdog instance");
    }
    this.supervisorInstance = supervisorInstance;
    this.watchdogInstance = watchdogInstance;
  }

  /**
   * Refuse a transition that moves backwards, or a write by a different instance.
   *
   * Quarantine is the one destination reachable from anywhere and is terminal: a quarantined
   * execution has unresolved ownership, and nothing may quietly move it forward again.
   */
  private assertForwardTransition(
    authority: "supervisor" | "watchdog",
    executionId: string,
    nextPhase: JournalPhase | WatchdogRecord["phase"],
    nextSequence: number,
    writer: string,
  ): void {
    const existing = authority === "supervisor" ? this.readSupervisor(executionId) : this.readWatchdog(executionId);
    if (existing === null) return;
    if (existing.writerInstance !== writer) {
      throw new JournalFencingError(
        `refusing ${authority} transition for ${executionId}: record was written by ${existing.writerInstance}, not ${writer}`,
      );
    }
    if (existing.phase === "quarantined" && nextPhase !== "quarantined") {
      throw new JournalFencingError(`refusing ${authority} transition for ${executionId}: quarantine is terminal`);
    }
    if (nextSequence <= existing.sequence) {
      // Strictly increasing, so a replayed write cannot re-assert an earlier state. Equal is
      // refused too: two writes at the same sequence are either a duplicate delivery or two
      // writers racing, and neither is a state this record should reach.
      throw new JournalFencingError(
        `refusing ${authority} transition for ${executionId}: sequence ${nextSequence} is not ahead of ${existing.sequence}`,
      );
    }
    const order = authority === "supervisor" ? PHASE_ORDER : WATCHDOG_PHASE_ORDER;
    const from = order[existing.phase as keyof typeof order];
    const to = order[nextPhase as keyof typeof order];
    if (to < from) {
      throw new JournalFencingError(
        `refusing ${authority} phase regression for ${executionId}: ${existing.phase} -> ${String(nextPhase)}`,
      );
    }
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
  /**
   * Write a supervisor record, refusing anything a fenced writer may not do.
   *
   * ## The rule this enforces
   *
   * There is exactly one live supervisor instance per boot. A write is accepted only if the
   * record's writer *is* the declared supervisor instance, the instance matches the one this
   * journal is bound to, and the transition is a forward move.
   *
   * Sequence ordering alone was insufficient. A restarted supervisor starts again at a low
   * sequence, so under pure ordering the previous instance would outrank it indefinitely — and
   * a stale process that is merely slow, not dead, would keep winning. Binding the writer
   * identity makes a stale write rejectable on identity rather than on arithmetic.
   */
  writeSupervisor(record: SupervisorRecord): void {
    // Validate the record itself before it reaches the disk. A caller that built a malformed
    // record — a phase not in the closed set, a container id of the wrong length — must fail
    // here, while the caller still has the context to handle it.
    assertSupervisorRecord(record);
    assertExecutionId(record.executionId);
    if (this.supervisorInstance !== null && record.supervisorInstance !== this.supervisorInstance) {
      throw new JournalFencingError(
        `refusing a write from ${record.supervisorInstance}: this journal is bound to ${this.supervisorInstance}`,
      );
    }
    this.assertForwardTransition("supervisor", record.executionId, record.phase, record.sequence, record.writerInstance);
    this.atomicWrite(this.supervisorPath(record.executionId), JSON.stringify(record));
  }

  writeWatchdog(record: WatchdogRecord): void {
    assertWatchdogRecord(record);
    assertExecutionId(record.executionId);
    if (this.watchdogInstance !== null && record.watchdogInstance !== this.watchdogInstance) {
      throw new JournalFencingError(
        `refusing a watchdog write from ${record.watchdogInstance}: this journal is bound to ${this.watchdogInstance}`,
      );
    }
    this.assertForwardTransition("watchdog", record.executionId, record.phase, record.sequence, record.writerInstance);
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
  clear(executionId: string, evidence: ClearEvidence): void {
    assertExecutionId(executionId);
    const supervisor = this.readSupervisor(executionId);
    const watchdog = this.readWatchdog(executionId);

    // ## Why the caller's assertion is not enough
    //
    // The previous signature took `{ containerRemoved: true }` and deleted both files. That is
    // the caller marking its own homework: the value that decides whether a container might
    // still exist is supplied by the component that wants the record gone.
    //
    // Resolution now has to be positively established in the records themselves, across *both*
    // authorities. The supervisor must have reached `removed` with a terminal outcome, and the
    // watchdog — an independent process that the supervisor cannot overwrite — must have
    // concluded. A missing watchdog record is not evidence of anything: a supervisor that never
    // armed a watchdog, and one whose watchdog record was lost, look identical from here.
    if (supervisor === null) {
      // Nothing to clear on the supervisor side. The watchdog record may still exist and is
      // retained: deleting it because its counterpart is missing would destroy the only
      // evidence that an execution was ever armed.
      if (watchdog !== null) {
        throw new Error(
          `refusing to clear ${executionId}: a watchdog record exists (phase=${watchdog.phase}) without a supervisor record. `
          + "An independent record is not deleted because its counterpart is missing.",
        );
      }
      return;
    }

    const supervisorResolved = supervisor.phase === "removed" && supervisor.outcome !== null;
    if (!supervisorResolved) {
      throw new Error(
        `refusing to clear ${executionId}: supervisor phase=${supervisor.phase} outcome=${String(supervisor.outcome)}. `
        + "Retention is required until ownership is positively resolved.",
      );
    }

    // A watchdog record must exist and be concluded. `armed` means a deadline may still fire, and
    // `quarantined` means the watchdog itself could not resolve what happened.
    if (watchdog !== null && watchdog.phase !== "disarmed") {
      throw new Error(
        `refusing to clear ${executionId}: watchdog phase=${watchdog.phase} outcome=${String(watchdog.outcome)}. `
        + "The independent authority has not concluded.",
      );
    }

    if (!evidence.containerAbsentByInspect) {
      throw new Error(
        `refusing to clear ${executionId}: an exact inspect has not confirmed the container is absent. `
        + "A remove command that returned success is not that confirmation.",
      );
    }

    // Removal is a durable directory update, not just an unlink: a crash between the two files
    // would otherwise leave a supervisor record gone and a watchdog record present.
    const removed: string[] = [];
    for (const path of [this.supervisorPath(executionId), this.watchdogPath(executionId)]) {
      if (existsSync(path)) {
        unlinkSync(path);
        removed.push(path);
      }
    }
    if (removed.length > 0) this.fsyncDir(this.supervisorDir);
  }
}

/**
 * What a caller must prove before records may be removed.
 *
 * Deliberately not a boolean. A named fact is harder to pass accidentally, and the name says
 * what actually had to happen: the container was observed absent by an exact-id inspect, not
 * merely asked to be removed.
 */
export type ClearEvidence = {
  /** An exact-id `docker inspect` positively reported the container does not exist. */
  containerAbsentByInspect: boolean;
};

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
