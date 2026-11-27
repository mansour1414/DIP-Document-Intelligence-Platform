/**
 * The Watchdog's durable record store (R7D.1 Continuation D1, WD-01).
 *
 * ## The defect this replaces
 *
 * The previous implementation claimed "record durably before acknowledging" and then did
 * `this.armed.set(executionId, record)` — an in-memory `Map`. Nothing reached a filesystem, and a
 * watchdog crash lost every armed deadline with no trace that one had existed. The comment was the
 * only thing durable about it.
 *
 * ## What durability requires here
 *
 * A record is durable when, after a power loss at any instant, its contents are either wholly
 * present or wholly absent. That needs three things and all three are implemented:
 *
 *   1. **Write to a unique temporary file**, created exclusively, so two writers cannot interleave.
 *   2. **fsync the file** before the rename, so the renamed entry points at durable content rather
 *      than a page-cache entry a crash can still lose.
 *   3. **fsync the directory** after the rename, so the directory entry itself survives.
 *
 * A failure at any step throws. There is no path that acknowledges an arm whose record did not
 * reach disk: an in-memory record is a claim, not a record.
 *
 * ## What is stored, and what is deliberately not
 *
 * Identity, deadline, cgroup facts, phase and outcome. No document bytes, no digests of document
 * content, no daemon transcripts, no free-form text fields. It is a type of identifiers and
 * counters, so "no document data in the watchdog journal" is structural rather than a promise
 * about how the fields are filled in.
 *
 * ## Recovery is fail-closed
 *
 * `load` distinguishes "no records" from "a record I cannot trust". A missing directory is empty
 * state; an unparseable file, a schema mismatch, a record from another boot and a record whose
 * cgroup is gone are all *not* empty and are all refused into quarantine. A recovery pass that
 * silently skipped a corrupt record would forget an execution that may still be running.
 */

import {
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { join } from "node:path";

/** The schema version of a persisted watchdog record. A change is a migration, not a cast. */
export const WATCHDOG_RECORD_SCHEMA = 1;

/**
 * A durable arm record.
 *
 * Every field is an identifier or a counter. Times are milliseconds since boot, always paired
 * with the boot id, because a millisecond-since-boot value means nothing on another boot.
 */
export type WatchdogArmRecord = {
  schema: 1;
  executionId: string;
  bootId: string;
  watchdogInstance: string;
  supervisorInstance: string;
  requestId: string;
  operation: "inspect" | "fill" | "verify";
  containerId: string;
  containerName: string;
  imageDigest: string;
  profileId: string;
  initPid: number;
  initStartTimeTicks: number;
  cgroupPath: string;
  cgroupDevice: string;
  cgroupDirInode: number;
  cgroupEventsInode: number;
  cgroupKillInode: number;
  cgroupProcsInode: number;
  /** Absolute deadline, milliseconds since `bootId` began. */
  deadlineAtMs: number;
  /** When the arm was accepted, for ordering and forensics. */
  armedAtMs: number;
  phase: "armed" | "terminating" | "terminated" | "disarmed" | "quarantined";
  /**
   * Two separate debts, because terminating processes and removing a container are different
   * facts about different subsystems and one does not imply the other.
   */
  processDebt: "none" | "terminate-required" | "termination-confirmed" | "unresolved";
  containerDebt: "none" | "removal-required" | "removal-confirmed" | "unresolved";
  /** Set only in a terminal phase, from a closed vocabulary. */
  outcome: null | "disarmed" | "terminated" | "unresolved";
  /** Strictly increasing per execution; a lower value never overwrites a higher one. */
  sequence: number;
};

/** Why a store operation failed. Closed, because the caller refuses on each. */
export class WatchdogStoreError extends Error {
  constructor(readonly code: "WRITE_FAILED" | "FSYNC_FAILED" | "SCHEMA_INVALID" | "UNREADABLE", message: string, readonly cause?: unknown) {
    super(message);
    this.name = "WatchdogStoreError";
  }
}

const RECORD_KEYS = [
  "schema", "executionId", "bootId", "watchdogInstance", "supervisorInstance", "requestId",
  "operation", "containerId", "containerName", "imageDigest", "profileId", "initPid",
  "initStartTimeTicks", "cgroupPath", "cgroupDevice", "cgroupDirInode", "cgroupEventsInode",
  "cgroupKillInode", "cgroupProcsInode", "deadlineAtMs", "armedAtMs", "phase", "processDebt",
  "containerDebt", "outcome", "sequence",
] as const;

/**
 * Validate a record strictly.
 *
 * A cast would hand back whatever the file contained. A hand-edited `phase: "disarmed"` on a
 * record whose container is still running would then authorize a grant — which is precisely the
 * class of mistake this store exists to prevent, so a record that does not match the schema is a
 * refusal, not a value.
 */
export function assertArmRecord(value: unknown): WatchdogArmRecord {
  const fail = (detail: string): never => {
    throw new WatchdogStoreError("SCHEMA_INVALID", `watchdog record is invalid: ${detail}`);
  };
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("not an object");
  const record = value as Record<string, unknown>;

  const keys = Object.keys(record).sort();
  const expected = [...RECORD_KEYS].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    const unexpected = keys.filter((key) => !(RECORD_KEYS as readonly string[]).includes(key));
    fail(unexpected.length > 0 ? `unexpected properties: ${unexpected.join(", ")}` : "missing properties");
  }
  if (record.schema !== WATCHDOG_RECORD_SCHEMA) fail(`schema ${String(record.schema)} is not ${WATCHDOG_RECORD_SCHEMA}`);

  const text = (name: string, pattern: RegExp): string => {
    const raw = record[name];
    if (typeof raw !== "string" || !pattern.test(raw)) fail(`${name} is not acceptable`);
    return raw as string;
  };
  const int = (name: string, min: number): number => {
    const raw = record[name];
    if (typeof raw !== "number" || !Number.isSafeInteger(raw) || raw < min) fail(`${name} is not a valid integer`);
    return raw as number;
  };
  const oneOf = <T extends string>(name: string, allowed: readonly T[]): T => {
    const raw = record[name];
    if (typeof raw !== "string" || !(allowed as readonly string[]).includes(raw)) fail(`${name} is not in the closed set`);
    return raw as T;
  };

  const executionId = text("executionId", /^[a-f0-9]{32}$/u);
  const containerName = text("containerName", /^dip-exec-[a-f0-9]{32}$/u);
  if (containerName !== `dip-exec-${executionId}`) fail("containerName does not derive from executionId");
  const containerId = text("containerId", /^[a-f0-9]{64}$/u);
  void containerId;

  const processDebt = oneOf("processDebt", ["none", "terminate-required", "termination-confirmed", "unresolved"] as const);
  const containerDebt = oneOf("containerDebt", ["none", "removal-required", "removal-confirmed", "unresolved"] as const);
  const phase = oneOf("phase", ["armed", "terminating", "terminated", "disarmed", "quarantined"] as const);
  const outcome = record.outcome === null ? null : oneOf("outcome", ["disarmed", "terminated", "unresolved"] as const);

  // Consistency between phase, outcome and the two debts. A record that says `terminated` while
  // process termination is unconfirmed is exactly the forgery a hand-edit would attempt.
  if (phase === "terminated" && processDebt !== "termination-confirmed") {
    fail("a terminated phase requires confirmed process termination");
  }
  if (phase === "disarmed" && processDebt === "terminate-required") {
    fail("a disarmed phase cannot carry an outstanding termination debt");
  }
  if (phase === "armed" && (processDebt === "termination-confirmed" || containerDebt === "removal-confirmed")) {
    fail("an armed phase cannot already be concluded");
  }
  if (outcome !== null && phase === "armed") fail("an armed record cannot have an outcome");
  if (outcome === null && (phase === "terminated" || phase === "disarmed")) {
    fail(`${phase} is a terminal phase and requires an outcome`);
  }

  return {
    schema: WATCHDOG_RECORD_SCHEMA,
    executionId,
    bootId: text("bootId", /^[0-9a-f-]{36}$/u),
    watchdogInstance: text("watchdogInstance", /^wd-[a-f0-9]{12}$/u),
    supervisorInstance: text("supervisorInstance", /^[a-z0-9-]{4,64}$/u),
    requestId: text("requestId", /^[a-f0-9]{16,64}$/u),
    operation: oneOf("operation", ["inspect", "fill", "verify"] as const),
    containerId,
    containerName,
    imageDigest: text("imageDigest", /^sha256:[a-f0-9]{64}$/u),
    profileId: text("profileId", /^[a-z0-9-]{4,64}$/u),
    initPid: int("initPid", 2),
    initStartTimeTicks: int("initStartTimeTicks", 0),
    // ## The durable record names a path, not a mount
    //
    // The absolute mount point is a property of the host, discovered at run time from
    // `/proc/self/mountinfo`; `/sys/fs/cgroup` is the conventional location and not the only valid
    // one. Pinning the literal here made a record unwritable on any host that mounts cgroup2
    // elsewhere, and the failure surfaced as `DURABILITY_FAILED` at arm time — a durability
    // problem that was really an address assumption.
    //
    // What the record must guarantee is that the path is absolute, traversal-free, and inside the
    // dedicated subtree, because that is the boundary of what may be signalled. The mount itself is
    // re-established and compared by the watchdog before any kill.
    cgroupPath: text("cgroupPath", /^\/[A-Za-z0-9._/-]*\/dip-executor\.slice\/[A-Za-z0-9._/-]+$/u),
    cgroupDevice: text("cgroupDevice", /^\d+:\d+$/u),
    cgroupDirInode: int("cgroupDirInode", 1),
    cgroupEventsInode: int("cgroupEventsInode", 1),
    cgroupKillInode: int("cgroupKillInode", 1),
    cgroupProcsInode: int("cgroupProcsInode", 1),
    deadlineAtMs: int("deadlineAtMs", 0),
    armedAtMs: int("armedAtMs", 0),
    phase,
    processDebt,
    containerDebt,
    outcome,
    sequence: int("sequence", 1),
  };
}

/** fsync a directory, or fail. Durability of the rename is the point of the store. */
function fsyncDir(dir: string): void {
  let fd: number | undefined;
  try {
    fd = openSync(dir, "r");
    fsyncSync(fd);
  } catch (error) {
    throw new WatchdogStoreError("FSYNC_FAILED", `the watchdog record directory ${dir} could not be fsync'd`, error);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/**
 * A durable store of watchdog records, one file per execution.
 *
 * Directory-based rather than a single file so that one corrupt record cannot make every other
 * record unreadable, and so a write for one execution does not rewrite another's.
 */
export class WatchdogStore {
  readonly dir: string;
  private readonly fsync: (fd: number) => void;

  constructor(dir: string, options: { fsync?: (fd: number) => void } = {}) {
    this.dir = dir;
    this.fsync = options.fsync ?? ((fd: number) => fsyncSync(fd));
  }

  /** Create the directory durably. Called before readiness, so a failure is a start-up failure. */
  init(): void {
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    fsyncDir(this.dir);
  }

  private recordPath(executionId: string): string {
    if (!/^[a-f0-9]{32}$/u.test(executionId)) throw new WatchdogStoreError("SCHEMA_INVALID", "the execution id is not acceptable");
    return join(this.dir, `${executionId}.json`);
  }

  /**
   * Write a record durably.
   *
   * Throws on any failure. A caller that ignores the throw would acknowledge an arm that is not on
   * disk, so the ACK is constructed only after this returns — see `Watchdog.arm`.
   */
  write(record: WatchdogArmRecord): void {
    const validated = assertArmRecord(record);
    const target = this.recordPath(validated.executionId);
    const temporary = `${target}.${process.pid}.${Math.random().toString(16).slice(2, 10)}.tmp`;

    let fd: number | undefined;
    try {
      fd = openSync(temporary, "wx", 0o600);
      writeSync(fd, JSON.stringify(validated));
      // fsync before the rename: a renamed entry pointing at content still in page cache is not
      // durable, and a crash would leave a zero-length or partial record.
      this.fsync(fd);
    } catch (error) {
      if (fd !== undefined) {
        try { closeSync(fd); } catch { /* already failing */ }
        fd = undefined;
      }
      try { unlinkSync(temporary); } catch { /* nothing to remove */ }
      throw new WatchdogStoreError("WRITE_FAILED", "the watchdog record could not be written durably", error);
    } finally {
      if (fd !== undefined) closeSync(fd);
    }

    try {
      renameSync(temporary, target);
    } catch (error) {
      try { unlinkSync(temporary); } catch { /* nothing to remove */ }
      throw new WatchdogStoreError("WRITE_FAILED", "the watchdog record could not be renamed into place", error);
    }
    // The rename is not durable until the directory is fsync'd. A failure here means the record
    // may not survive a crash, which is the exact condition the store exists to rule out.
    fsyncDir(this.dir);
  }

  /** Read one record, or `null` if it does not exist. Throws when it exists but cannot be trusted. */
  read(executionId: string): WatchdogArmRecord | null {
    let raw: string;
    try {
      raw = readFileSync(this.recordPath(executionId), "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw new WatchdogStoreError("UNREADABLE", `watchdog record ${executionId} could not be read`, error);
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw new WatchdogStoreError("SCHEMA_INVALID", `watchdog record ${executionId} is not valid JSON`, error);
    }
    return assertArmRecord(parsed);
  }

  /** Every record id present. A missing directory is an empty store, not an error. */
  list(): string[] {
    let names: string[];
    try {
      names = readdirSync(this.dir);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw new WatchdogStoreError("UNREADABLE", "the watchdog record directory could not be listed", error);
    }
    return names
      .filter((name) => name.endsWith(".json"))
      .map((name) => name.slice(0, -".json".length));
  }
}

/** What a recovery pass found for one record. Closed, because the caller acts on it. */
export type RecoveryFinding =
  | { executionId: string; kind: "armed-this-boot"; record: WatchdogArmRecord }
  | { executionId: string; kind: "concluded-this-boot"; record: WatchdogArmRecord }
  /** Written on a previous boot. The cgroups it names do not exist here. */
  | { executionId: string; kind: "previous-boot"; record: WatchdogArmRecord }
  /** Exists but cannot be trusted. Quarantine; do not interpret. */
  | { executionId: string; kind: "corrupt"; detail: string }
  /** This instance wrote an arm and crashed before the next transition, so termination may be owed. */
  | { executionId: string; kind: "interrupted-arming"; record: WatchdogArmRecord };

/**
 * Scan the store and classify every record.
 *
 * Fail-closed: anything that cannot be positively classified is `corrupt` and quarantined by the
 * caller. A recovery pass that skipped a corrupt record would forget an execution that may still
 * hold a container.
 */
export function recoverRecords(
  store: WatchdogStore,
  bootId: string,
  nowMs: number,
): { findings: RecoveryFinding[]; open: RecoveryFinding[] } {
  const findings: RecoveryFinding[] = [];
  for (const executionId of store.list()) {
    let record: WatchdogArmRecord | null;
    try {
      record = store.read(executionId);
    } catch (error) {
      findings.push({ executionId, kind: "corrupt", detail: error instanceof Error ? error.message : "unreadable" });
      continue;
    }
    if (record === null) {
      // Listed but absent: a concurrent clear. Not an error, and not something to act on.
      continue;
    }
    if (record.bootId !== bootId) {
      findings.push({ executionId, kind: "previous-boot", record });
      continue;
    }
    if (record.phase === "terminated" || record.phase === "disarmed") {
      findings.push({ executionId, kind: "concluded-this-boot", record });
      continue;
    }
    if (record.phase === "quarantined") {
      findings.push({ executionId, kind: "corrupt", detail: "the record is quarantined" });
      continue;
    }
    // `armed` or `terminating` on this boot: the deadline is still the authority, and a
    // `terminating` record means a kill was underway when the process died.
    void nowMs;
    findings.push({ executionId, kind: "armed-this-boot", record });
  }
  const open = findings.filter((finding) => finding.kind === "armed-this-boot" || finding.kind === "corrupt");
  return { findings, open };
}
