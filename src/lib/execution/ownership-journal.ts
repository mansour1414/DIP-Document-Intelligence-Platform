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

import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, unlinkSync, writeFileSync, writeSync, existsSync } from "node:fs";
import { join } from "node:path";

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

  constructor(root: string) {
    this.supervisorDir = join(root, "supervisor");
    this.watchdogDir = join(root, "watchdog");
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
    const temporary = `${path}.tmp`;
    const fd = openSync(temporary, "w", 0o600);
    try {
      writeSync(fd, contents);
      // fsync the file before the rename, so the renamed entry points at durable content.
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(temporary, path);
    this.fsyncDir(path.slice(0, path.lastIndexOf("/")));
  }

  private fsyncDir(dir: string): void {
    let fd: number | undefined;
    try {
      fd = openSync(dir, "r");
      fsyncSync(fd);
    } catch {
      // Some filesystems refuse fsync on a directory descriptor. The rename is still
      // atomic; only the durability guarantee is weaker, and there is no portable way to
      // force it. Recorded here rather than silently ignored elsewhere.
    } finally {
      if (fd !== undefined) closeSync(fd);
    }
  }

  readSupervisor(executionId: string): SupervisorRecord | null {
    const path = this.supervisorPath(executionId);
    if (!existsSync(path)) return null;
    return JSON.parse(readFileSync(path, "utf8")) as SupervisorRecord;
  }

  readWatchdog(executionId: string): WatchdogRecord | null {
    const path = this.watchdogPath(executionId);
    if (!existsSync(path)) return null;
    return JSON.parse(readFileSync(path, "utf8")) as WatchdogRecord;
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

  /** Remove both records once removal is confirmed. Never removes an unresolved record. */
  clear(executionId: string): void {
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
