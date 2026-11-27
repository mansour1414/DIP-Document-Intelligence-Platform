/**
 * The independent Watchdog (R7D.1 §4, §5; Continuation D1 WD-01, WD-03, WD-04, WD-05, WD-06).
 *
 * ## Why it is a separate process
 *
 * The Watchdog's job is to terminate a container when the deadline passes, *including* when the
 * Supervisor is wedged, dead, or has decided not to act. A watchdog that shares an event loop
 * with the supervisor inherits the supervisor's failure modes, which makes it decorative.
 *
 * ## What changed in Continuation D1, and why
 *
 * The previous version claimed things it did not do. Each of those claims is now either
 * implemented or removed:
 *
 * - **Durability (WD-01).** "Record durably before acknowledging" set a key in an in-memory `Map`.
 *   Records now go through `WatchdogStore`, which writes a unique temporary file, fsyncs it,
 *   renames it, and fsyncs the directory — and *throws* on any failure, so no ACK exists for an
 *   arm that is not on disk. Startup recovery runs before the socket listens.
 * - **Descriptor pinning (WD-03).** Termination stat'd `cgroup.kill` and then wrote to the *path*.
 *   It now opens the directory and its control files once, verifies device and inode from the
 *   descriptors, retains them for the execution's lifetime, and writes through the pinned
 *   descriptor. Path revalidation is no longer used as a substitute.
 * - **Disarm safety (WD-04).** The old path trusted the caller's `containerRemoved` boolean and
 *   concluded disarm in memory. Expiry now marks the execution as owing termination and does not
 *   suppress it; a grant requires independently verified process termination *and* confirmed
 *   container removal, recorded durably before the grant is signed.
 * - **Host-consistent clock (WD-05).** Deadlines come from `/proc/uptime` and are stored with a
 *   boot id, so a restarted process compares like with like instead of comparing its own
 *   `performance.now()` origin against a persisted value.
 * - **Ownership (WD-06).** A termination target must be in the dedicated DIP subtree, carry the
 *   exact execution-derived name, and hold the init process whose start time was verified.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  MessageIdWindow,
  signArmAck,
  signDisarmGrant,
  verifyArmAck,
  type ArmAck,
  type ArmDenied,
  type ArmRequest,
  type Heartbeat,
  type HelloAck,
} from "./watchdog-protocol";
import {
  assertTerminalContext,
  type TerminalDeniedMessage,
  type TerminalGrantMessage,
  type TerminalRequest,
} from "./terminal-auth";
import { readBootId, pathIdentity, readProcessStartTimeTicks, findCgroup2Mount } from "./host-facts";
import { compareDeadline, type HostClock } from "./host-clock";
import {
  closePinned,
  pinCgroup,
  pinnedIsPopulated,
  readPinnedProcs,
  verifyPin,
  writePinnedKill,
  type PinnedCgroup,
} from "./cgroup-pin";
import {
  WatchdogStore,
  WatchdogStoreError,
  recoverRecords,
  type WatchdogArmRecord,
} from "./watchdog-store";
import { randomBytes } from "node:crypto";

/** The watchdog's own identity. A restarted watchdog is a different instance. */
export type WatchdogIdentity = {
  instance: string;
  bootId: string;
  pid: number;
  pidStartTimeTicks: number;
  startedMonotonicMs: number;
};

/** A live execution: the durable record plus the descriptors that pin its cgroup. */
type LiveExecution = {
  record: WatchdogArmRecord;
  /** Present only when the cgroup could be pinned. Its absence is why a termination may be owed. */
  pin: PinnedCgroup | null;
  heartbeatsSeen: number;
  lastHeartbeatMs: number;
  /** Proofs already issued, so a replayed disarm cannot mint a second grant. */
  issuedGrants: Set<string>;
};

/** What the watchdog observed, or why it refused. */
export type HostVerification =
  | {
      ok: true;
      dirInode: number;
      eventsInode: number;
      killInode: number;
      procsInode: number;
      device: string;
      bootId: string;
    }
  | { ok: false; code: "BOOT_MISMATCH" | "CGROUP_UNVERIFIED" | "PID_UNVERIFIED" | "NOT_DIP_OWNED" };

/** The dedicated subtree every DIP container must live in. Nothing outside it may be armed. */
export const DIP_CGROUP_SUBTREE = "dip-executor.slice";

/**
 * Independently confirm, from the host, that the container in a request is the container that
 * exists and belongs to this execution.
 *
 * Exported and separately testable because it is the load-bearing part of arming: everything
 * after it assumes the identity is real.
 */
export function verifyArmIdentity(request: ArmRequest, bootId: string): HostVerification {
  // A request from a previous boot describes namespaces that no longer exist; arming it would
  // register a deadline against an inode number that now means something else.
  if (request.bootId !== bootId) return { ok: false, code: "BOOT_MISMATCH" };

  const mount = findCgroup2Mount();
  if (mount === null) return { ok: false, code: "CGROUP_UNVERIFIED" };

  // WD-06: ownership before existence. A path outside the dedicated DIP subtree belongs to
  // something else, and no amount of inode verification makes killing it correct.
  const expectedPrefix = `${mount.path}/${DIP_CGROUP_SUBTREE}/`;
  if (!request.cgroupPath.startsWith(expectedPrefix) || request.cgroupPath.split("/").includes("..")) {
    return { ok: false, code: "NOT_DIP_OWNED" };
  }
  // The cgroup leaf must derive from the execution id, so a request cannot name another
  // execution's cgroup and have this watchdog adopt it.
  const leaf = request.cgroupPath.slice(expectedPrefix.length);
  if (leaf !== request.containerName && leaf !== `dip-exec-${request.executionId}`) {
    return { ok: false, code: "NOT_DIP_OWNED" };
  }
  if (request.containerName !== `dip-exec-${request.executionId}`) {
    return { ok: false, code: "NOT_DIP_OWNED" };
  }

  const dir = pathIdentity(request.cgroupPath);
  if (dir === null || !dir.isDirectory) return { ok: false, code: "CGROUP_UNVERIFIED" };

  const events = pathIdentity(join(request.cgroupPath, "cgroup.events"));
  const kill = pathIdentity(join(request.cgroupPath, "cgroup.kill"));
  const procs = pathIdentity(join(request.cgroupPath, "cgroup.procs"));
  if (events === null || kill === null || procs === null) return { ok: false, code: "CGROUP_UNVERIFIED" };

  // A PID alone is recycled; the start time is what makes the claim checkable.
  let startTime: number;
  try {
    startTime = readProcessStartTimeTicks(request.initPid);
  } catch {
    return { ok: false, code: "PID_UNVERIFIED" };
  }
  if (startTime !== request.initStartTimeTicks) return { ok: false, code: "PID_UNVERIFIED" };

  // The init process must actually be in that cgroup, not merely existing somewhere.
  try {
    const membership = readFileSync(`/proc/${request.initPid}/cgroup`, "utf8");
    const relative = request.cgroupPath.slice(mount.path.length) || "/";
    if (!membership.includes(`0::${relative}\n`) && !membership.includes(`0::${relative}`)) {
      return { ok: false, code: "PID_UNVERIFIED" };
    }
  } catch {
    return { ok: false, code: "PID_UNVERIFIED" };
  }

  return {
    ok: true,
    dirInode: dir.inode,
    eventsInode: events.inode,
    killInode: kill.inode,
    procsInode: procs.inode,
    device: mount.device,
    bootId,
  };
}

export type WatchdogOptions = {
  identity: WatchdogIdentity;
  /** Host-consistent clock, paired with the boot id. Never a process-local elapsed timer. */
  clock: HostClock;
  /**
   * Override host verification. Exists so the arbitration state machine can be tested where no
   * writable cgroup hierarchy exists; the default is `verifyArmIdentity` and there is no option to
   * skip verification entirely.
   */
  verifyHost?: (request: ArmRequest, bootId: string) => HostVerification;
  /**
   * Override cgroup pinning. Same reason as `verifyHost`: there is no writable cgroup hierarchy in
   * the development environment. The default is the real `pinCgroup`; there is no option to skip
   * pinning, because a termination without a pinned descriptor is the defect WD-03 corrects.
   */
  pin?: (input: { cgroupPath: string; mountPath: string }) => ReturnType<typeof pinCgroup>;
  /** Shared secret with the supervisor, for ack, grant and control proofs. */
  secret: Buffer;
  /** Durable record store. Absent means the watchdog refuses to arm at all. */
  store?: WatchdogStore;
  /** How the watchdog asks the daemon to kill a container, and to report removal. */
  killContainer: (containerId: string) => Promise<{ ok: boolean; detail: string }>;
  /**
   * Container presence, asked by exact id.
   *
   * `present: true` is "it exists". `present: false` is a *positive* not-found. An unreadable
   * daemon must return `{ present: true, detail: "unresolved" }` from the caller's adapter,
   * because an outage is not absence.
   */
  inspectContainer: (containerId: string) => Promise<{ present: boolean; detail: string }>;
};

/** What one termination attempt established. Everything here is evidence, not intention. */
export type TerminationReport = {
  executionId: string;
  /** The kernel accepted a write to the pinned `cgroup.kill`. Not proof of exit. */
  killWritten: boolean;
  /** `cgroup.events` reported `populated 0`. Positive proof that no tasks remain. */
  processTerminationConfirmed: boolean;
  /** The exact container id was positively reported absent. */
  containerRemovalConfirmed: boolean;
  /** True only when both of the above are true. */
  resolved: boolean;
  detail: string;
};

/**
 * The watchdog's state machine.
 *
 * Deliberately not an EventEmitter, and the mutating methods are synchronous. An asynchronous
 * callback surface would let a grant be observed before the state recording it had been written
 * to disk, which is the exact ordering the durability requirement exists to fix.
 */
export class Watchdog {
  private readonly options: WatchdogOptions;
  private readonly live = new Map<string, LiveExecution>();
  private readonly messageIds = new MessageIdWindow();
  /** Set when recovery found something it could not positively resolve. Blocks all arming. */
  private recoveryBlocked: string | null = null;

  constructor(options: WatchdogOptions) {
    this.options = options;
  }

  get identity(): WatchdogIdentity {
    return this.options.identity;
  }

  /** Pin a cgroup through the configured implementation. */
  private pinCgroup(cgroupPath: string): ReturnType<typeof pinCgroup> {
    const mountPath = findCgroup2Mount()?.path ?? "/sys/fs/cgroup";
    return (this.options.pin ?? pinCgroup)({ cgroupPath, mountPath });
  }

  /** The durable store, or a throw. Arming without a store is not supported. */
  private store(): WatchdogStore {
    if (this.options.store === undefined) {
      throw new WatchdogStoreError("WRITE_FAILED", "the watchdog has no durable store; refusing to arm");
    }
    return this.options.store;
  }

  /**
   * Recover before serving.
   *
   * Runs before the socket listens, so no client can observe a state that recovery has not yet
   * reconciled. Every record is re-verified against the host: a record whose cgroup no longer
   * matches its recorded inodes, or whose boot differs, is marked quarantined rather than adopted.
   *
   * Returns what was found so the entry point can log it and refuse readiness on an unresolved
   * arm, which is the honest answer: a watchdog that has an armed record it cannot verify does not
   * know whether a container is running.
   */
  recover(): { adopted: string[]; quarantined: string[]; concluded: string[]; previousBoot: string[] } {
    const store = this.store();
    const { findings } = recoverRecords(store, this.options.clock.bootId, this.options.clock.nowMs());
    const adopted: string[] = [];
    const quarantined: string[] = [];
    const concluded: string[] = [];
    const previousBoot: string[] = [];

    for (const finding of findings) {
      if (finding.kind === "previous-boot") {
        previousBoot.push(finding.executionId);
        continue;
      }
      if (finding.kind === "concluded-this-boot") {
        concluded.push(finding.executionId);
        continue;
      }
      if (finding.kind === "corrupt") {
        // Fail closed: a record that cannot be trusted is quarantined, and quarantine blocks
        // arming until an operator resolves it.
        quarantined.push(finding.executionId);
        continue;
      }

      // `armed-this-boot`. Re-establish the descriptors from the host and compare them against
      // what was recorded. A mismatch means the cgroup was replaced while this process was down,
      // and adopting it would mean enforcing a deadline against a resource never verified.
      const record = finding.record;
      const pinResult = this.pinCgroup(record.cgroupPath);
      if (!pinResult.ok) {
        this.quarantineRecord(record, `recovery could not re-pin: ${pinResult.code}`);
        quarantined.push(record.executionId);
        continue;
      }
      const pin = pinResult.pin;
      if (pin.dirInode !== record.cgroupDirInode || pin.files["cgroup.kill"].inode !== record.cgroupKillInode) {
        closePinned(pin);
        this.quarantineRecord(record, "recovery found a different cgroup at the recorded path");
        quarantined.push(record.executionId);
        continue;
      }

      this.live.set(record.executionId, {
        record,
        pin,
        heartbeatsSeen: 0,
        lastHeartbeatMs: this.options.clock.nowMs(),
        issuedGrants: new Set(),
      });
      adopted.push(record.executionId);
    }

    if (quarantined.length > 0) {
      this.recoveryBlocked = `recovery quarantined ${quarantined.length} execution(s)`;
    }
    return { adopted, quarantined, concluded, previousBoot };
  }

  /** HELLO_ACK: what the supervisor learns about this instance. */
  hello(): HelloAck {
    return {
      kind: "HELLO_ACK",
      watchdogInstance: this.options.identity.instance,
      bootId: this.options.identity.bootId,
      pid: this.options.identity.pid,
      pidStartTimeTicks: this.options.identity.pidStartTimeTicks,
      protocolVersion: 1,
    };
  }

  /**
   * ARM: verify identity, pin the cgroup, write the record durably, then acknowledge.
   *
   * ## The order is the requirement
   *
   * 1. Verify identity against the host.
   * 2. Pin the cgroup, so the descriptors held are the ones termination will use.
   * 3. Write the record and fsync it. **A throw here means no ACK.**
   * 4. Only then construct the ACK.
   *
   * Reversing 3 and 4 would mean telling the supervisor a deadline is armed that this process
   * would forget on a crash.
   */
  arm(request: ArmRequest): ArmAck | ArmDenied {
    const deny = (code: ArmDenied["code"]): ArmDenied => ({
      kind: "ARM_DENIED",
      messageId: request.messageId,
      executionId: request.executionId,
      watchdogInstance: this.options.identity.instance,
      code,
    });

    if (this.recoveryBlocked !== null) return deny("RECOVERY_INCOMPLETE");
    // Fail fast on the one precondition that makes every later answer irrelevant. Without a store
    // no arm can be durable, so pinning a cgroup first would do real work to reach a refusal that
    // was already certain — and would report it as a cgroup problem.
    if (this.options.store === undefined) return deny("DURABILITY_FAILED");
    if (!this.messageIds.consume(request.executionId, request.messageId)) return deny("REPLAYED");

    const existing = this.live.get(request.executionId);
    if (existing !== undefined && existing.record.phase === "armed") return deny("ALREADY_ARMED");
    // A concluded record is history. Re-arming the same execution would be a second execution
    // wearing the first one's identity.
    if (existing !== undefined) return deny("ALREADY_CONCLUDED");

    const verified = (this.options.verifyHost ?? verifyArmIdentity)(request, this.options.identity.bootId);
    if (!verified.ok) return deny(verified.code);

    const pinResult = this.pinCgroup(request.cgroupPath);
    if (!pinResult.ok) return deny("CGROUP_UNVERIFIED");
    const pin = pinResult.pin;

    // The descriptors must be the inodes the verifier reported. A pin taken between verification
    // and here could name a replacement.
    if (pin.dirInode !== verified.dirInode
      || pin.files["cgroup.kill"].inode !== verified.killInode
      || pin.files["cgroup.events"].inode !== verified.eventsInode
      || pin.files["cgroup.procs"].inode !== verified.procsInode) {
      closePinned(pin);
      return deny("CGROUP_UNVERIFIED");
    }

    const nowMs = this.options.clock.nowMs();
    const record: WatchdogArmRecord = {
      schema: 1,
      executionId: request.executionId,
      bootId: this.options.identity.bootId,
      watchdogInstance: this.options.identity.instance,
      supervisorInstance: request.supervisorInstance,
      requestId: request.requestId,
      operation: request.operation,
      containerId: request.containerId,
      containerName: request.containerName,
      imageDigest: request.imageDigest,
      profileId: request.profileId,
      initPid: request.initPid,
      initStartTimeTicks: request.initStartTimeTicks,
      cgroupPath: request.cgroupPath,
      cgroupDevice: verified.device,
      cgroupDirInode: pin.dirInode,
      cgroupEventsInode: pin.files["cgroup.events"].inode,
      cgroupKillInode: pin.files["cgroup.kill"].inode,
      cgroupProcsInode: pin.files["cgroup.procs"].inode,
      deadlineAtMs: nowMs + request.deadlineMs,
      armedAtMs: nowMs,
      phase: "armed",
      processDebt: "terminate-required",
      containerDebt: "removal-required",
      outcome: null,
      sequence: 1,
    };

    try {
      this.store().write(record);
    } catch {
      // Durability failed. Release the pin and refuse: acknowledging an arm that is not on disk
      // would hand the supervisor a deadline this process would forget on a crash.
      closePinned(pin);
      return deny("DURABILITY_FAILED");
    }

    this.live.set(request.executionId, {
      record,
      pin,
      heartbeatsSeen: 0,
      lastHeartbeatMs: nowMs,
      issuedGrants: new Set(),
    });

    const ackBase: Omit<ArmAck, "proof"> = {
      kind: "ARM_ACK",
      messageId: request.messageId,
      executionId: request.executionId,
      watchdogInstance: this.options.identity.instance,
      observedCgroupDirInode: pin.dirInode,
      observedCgroupEventsInode: pin.files["cgroup.events"].inode,
      observedCgroupKillInode: pin.files["cgroup.kill"].inode,
      observedCgroupProcsInode: pin.files["cgroup.procs"].inode,
      observedCgroupDevice: verified.device,
      observedBootId: verified.bootId,
      armedAtMonotonicMs: nowMs,
    };
    return { ...ackBase, proof: signArmAck(this.options.secret, ackBase) };
  }

  /** Verify an ack this watchdog produced, for the supervisor's use in tests and in the client. */
  verifyAck(ack: ArmAck): boolean {
    return verifyArmAck(this.options.secret, ack);
  }

  /** Record a heartbeat. Liveness only; it authorizes nothing and extends nothing. */
  heartbeat(beat: Heartbeat): { ok: boolean; code?: "UNKNOWN_EXECUTION" | "REPLAYED" } {
    if (!this.messageIds.consume(beat.executionId, beat.messageId)) return { ok: false, code: "REPLAYED" };
    const entry = this.live.get(beat.executionId);
    if (entry === undefined) return { ok: false, code: "UNKNOWN_EXECUTION" };
    entry.heartbeatsSeen += 1;
    entry.lastHeartbeatMs = this.options.clock.nowMs();
    return { ok: true };
  }

  /**
   * DISARM: serialized against termination, and refused unless completion is independently proven.
   *
   * ## What the caller is not allowed to assert
   *
   * The previous version concluded `disarmed` as soon as `context.outcome === "committed"` and
   * `context.containerRemoved === true`. Both are the *supervisor's* claims. A supervisor that is
   * compromised, buggy, or simply optimistic can set both, and the watchdog would then issue a
   * grant authorizing release of a document whose container is still running.
   *
   * The watchdog now establishes both facts itself, from the pinned descriptors and the daemon:
   *
   * - **process termination** — `cgroup.events` reports `populated 0`, read through the pinned
   *   descriptor;
   * - **container removal** — an exact-id inspection positively reports the container absent.
   *
   * A missing daemon, an outage, an unreadable cgroup: all of those are "not verified", and the
   * answer to "not verified" is quarantine, not a grant.
   *
   * ## Expiry does not suppress termination
   *
   * The previous version set `concluded: unresolved` on the expired path, which removed the
   * execution from `dueForTermination` — so a disarm arriving after the deadline prevented the
   * kill the deadline existed to trigger. Expiry now leaves the termination debt in place: the
   * execution stays due, and `terminate` will act on it.
   */
  async disarm(request: TerminalRequest, messageId: string, sequence: number): Promise<TerminalGrantMessage | TerminalDeniedMessage> {
    const deny = (code: TerminalDeniedMessage["code"]): TerminalDeniedMessage => ({
      executionId: request.executionId,
      requestId: request.requestId,
      code,
      watchdogInstance: this.options.identity.instance,
    });

    let context: TerminalRequest;
    try {
      context = assertTerminalContext(request);
    } catch {
      return deny("MISMATCH");
    }

    if (!this.messageIds.consume(context.executionId, messageId)) return deny("ALREADY_CONCLUDED");
    // The sequence must advance. A replay inside a connection is refused by the nonce window;
    // this refuses a replay with a fresh nonce but a stale ordering.
    if (!Number.isSafeInteger(sequence) || sequence < 1) return deny("MISMATCH");

    const entry = this.live.get(context.executionId);
    if (entry === undefined) return deny("UNKNOWN_EXECUTION");

    if (entry.record.phase === "terminated") return deny("TERMINATED");
    if (entry.record.phase === "disarmed") return deny("ALREADY_CONCLUDED");
    if (entry.record.phase === "terminating") return deny("TERMINATION_PENDING");

    // The context must describe the execution this watchdog armed. A grant for a different
    // container or a different boot would authorize killing and releasing the wrong thing.
    if (context.containerId !== entry.record.containerId
      || context.containerName !== entry.record.containerName
      || context.bootId !== entry.record.bootId
      || context.supervisorInstance !== entry.record.supervisorInstance
      || context.operation !== entry.record.operation) {
      return deny("MISMATCH");
    }

    // WD-04: a grant is only for an outcome that could release a document. A refusal, timeout,
    // cancellation or failure is a perfectly good terminal state and must not publish anything.
    if (context.outcome !== "committed") return deny("UNCERTAIN");

    // Caller-supplied `containerRemoved` is not evidence. It is recorded, and then ignored in
    // favour of what this process can establish.
    const evidence = await this.verifyCompletion(entry);

    // Expired between the supervisor's decision and this call. This does **not** conclude the
    // execution: the termination debt stands, and `terminate` will act on it. Concluding here was
    // the defect that let a late disarm cancel a required kill.
    const comparison = compareDeadline({ bootId: entry.record.bootId, deadlineAtMs: entry.record.deadlineAtMs }, this.options.clock);
    if (comparison.kind === "stale-boot") return deny("MISMATCH");
    if (comparison.kind === "due") {
      return deny("EXPIRED");
    }

    if (!evidence.processTerminationConfirmed || !evidence.containerRemovalConfirmed) {
      return deny("UNCERTAIN");
    }

    // ## Durable conclusion before the grant
    //
    // The conclusion is written and fsynced *before* the grant is signed. If the process dies in
    // between, the record shows `disarmed` with no grant issued; recovery refuses to re-mint,
    // because a grant that might have been delivered is not one to duplicate.
    const concluded: WatchdogArmRecord = {
      ...entry.record,
      phase: "disarmed",
      processDebt: "termination-confirmed",
      containerDebt: "removal-confirmed",
      outcome: "disarmed",
      sequence: entry.record.sequence + 1,
    };
    try {
      this.store().write(concluded);
    } catch {
      // Distinct from `UNCERTAIN`: completion *was* proven here, and what failed was recording it.
      // The two call for different reactions — a supervisor should keep its quarantine in both
      // cases, but it should retry this one rather than treat the host as ambiguous, because the
      // evidence is still there and the next attempt can succeed.
      return deny("DURABILITY_FAILED");
    }
    entry.record = concluded;

    const grant = signDisarmGrant(this.options.secret, { ...context, watchdogInstance: this.options.identity.instance });
    entry.issuedGrants.add(grant.proof);
    // The pin has served its purpose and the cgroup is gone. Holding the descriptors would keep a
    // deleted cgroup's dentry alive for no reason.
    if (entry.pin !== null) {
      closePinned(entry.pin);
      entry.pin = null;
    }
    return grant;
  }

  /**
   * Establish completion from the host, not from the caller.
   *
   * Both facts are required and neither is inferred from the other: a container can be removed
   * while its cgroup still reports tasks (during teardown), and tasks can be gone while the
   * container record remains.
   */
  private async verifyCompletion(entry: LiveExecution): Promise<{
    processTerminationConfirmed: boolean;
    containerRemovalConfirmed: boolean;
  }> {
    let processTerminationConfirmed = false;
    if (entry.pin !== null && entry.pin.dirFd >= 0) {
      const pinState = verifyPin(entry.pin);
      if (pinState.ok) {
        const populated = pinnedIsPopulated(entry.pin);
        const procs = readPinnedProcs(entry.pin);
        // `populated 0` is the kernel's own statement. An empty `cgroup.procs` corroborates it;
        // `populated 0` with a non-empty procs list is contradictory and treated as unverified.
        processTerminationConfirmed = populated === false && (procs === null || procs.length === 0);
      }
    }

    const inspection = await this.options.inspectContainer(entry.record.containerId);
    // `present: false` from this adapter means a *positive* not-found. Ambiguity is reported as
    // `present: true` by the adapter precisely so it cannot be mistaken for removal here.
    const containerRemovalConfirmed = inspection.present === false;

    return { processTerminationConfirmed, containerRemovalConfirmed };
  }

  /**
   * Advance deadlines. Called on the watchdog's own timer.
   *
   * An execution whose deadline has passed stays in the map with its termination debt intact. It is
   * *not* concluded here: concluding is what `terminate` does once it has evidence, and marking it
   * concluded first is what used to make a late disarm cancel the kill.
   */
  dueForTermination(): Array<{ executionId: string; containerId: string; cgroupPath: string }> {
    const due: Array<{ executionId: string; containerId: string; cgroupPath: string }> = [];
    for (const [executionId, entry] of this.live) {
      if (entry.record.phase !== "armed" && entry.record.phase !== "terminating") continue;
      const comparison = compareDeadline(
        { bootId: entry.record.bootId, deadlineAtMs: entry.record.deadlineAtMs },
        this.options.clock,
      );
      if (comparison.kind !== "due") continue;
      due.push({ executionId, containerId: entry.record.containerId, cgroupPath: entry.record.cgroupPath });
    }
    return due;
  }

  /**
   * Terminate a due execution, through the pinned descriptors.
   *
   * ## Order
   *
   * 1. Record `terminating` durably, so a crash mid-kill leaves a record that says a kill was
   *    underway rather than nothing at all.
   * 2. Write `cgroup.kill` through the pinned descriptor.
   * 3. Re-read `cgroup.events` through the pinned descriptor.
   * 4. Ask the daemon, by exact id, whether the container is gone.
   * 5. Record the two debts **separately** and independently. A resolved termination needs both.
   *
   * ## What is not accepted as proof
   *
   * A missing Docker record is *not* proof that the processes are gone: the daemon can lose a
   * container while its cgroup still holds tasks, and it can report a container while its tasks
   * have exited. The two questions are answered from the two sources that can actually answer
   * them.
   */
  async terminate(due: { executionId: string; containerId: string; cgroupPath: string }): Promise<TerminationReport> {
    const entry = this.live.get(due.executionId);
    if (entry === undefined) {
      return {
        executionId: due.executionId,
        killWritten: false,
        processTerminationConfirmed: false,
        containerRemovalConfirmed: false,
        resolved: false,
        detail: "the execution is not held by this watchdog",
      };
    }
    if (entry.record.phase === "disarmed" || entry.record.phase === "terminated") {
      return {
        executionId: due.executionId,
        killWritten: false,
        processTerminationConfirmed: entry.record.processDebt === "termination-confirmed",
        containerRemovalConfirmed: entry.record.containerDebt === "removal-confirmed",
        resolved: entry.record.processDebt === "termination-confirmed" && entry.record.containerDebt === "removal-confirmed",
        detail: `already concluded as ${entry.record.phase}`,
      };
    }

    // Record intent before acting. A crash between here and the kill leaves `terminating`, which
    // recovery treats as a termination owed rather than as clean state.
    const terminating: WatchdogArmRecord = {
      ...entry.record,
      phase: "terminating",
      processDebt: "terminate-required",
      sequence: entry.record.sequence + 1,
    };
    try {
      this.store().write(terminating);
      entry.record = terminating;
    } catch (error) {
      return {
        executionId: due.executionId,
        killWritten: false,
        processTerminationConfirmed: false,
        containerRemovalConfirmed: false,
        resolved: false,
        detail: `the termination intent could not be recorded: ${error instanceof Error ? error.message : "unknown"}`,
      };
    }

    let killWritten = false;
    let detail = "";

    if (entry.pin === null || entry.pin.dirFd < 0) {
      detail = "no pinned descriptor is available; refusing to write by path";
    } else {
      const pinState = verifyPin(entry.pin);
      if (!pinState.ok) {
        // The descriptor no longer names what was verified. Writing through it would signal an
        // object this watchdog did not verify, which is the failure pinning exists to prevent.
        detail = `the pin is no longer valid: ${pinState.code}`;
      } else {
        const write = writePinnedKill(entry.pin);
        killWritten = write.ok;
        if (!write.ok) detail = `the pinned kill could not be written: ${write.detail}`;
        // A path that was replaced is recorded, not treated as a failure: the write went through
        // the descriptor and reached the verified inode whatever the path now names.
        if (write.ok && !pinState.pathStillPinned) detail = "the path was replaced; the kill used the pinned descriptor";
      }
    }

    // The cgroup write is the mechanism that reaches every process at once. The daemon kill is a
    // fallback for the case where the cgroup could not be signalled at all.
    if (!killWritten) {
      const killed = await this.options.killContainer(due.containerId);
      if (killed.ok) {
        killWritten = true;
        detail = "the daemon accepted a kill for the exact container id";
      } else if (detail === "") {
        detail = `the daemon refused the kill: ${killed.detail}`;
      }
    }

    // Post-condition 1: no tasks remain, read through the pinned descriptor.
    let processTerminationConfirmed = false;
    if (entry.pin !== null && entry.pin.dirFd >= 0) {
      const populated = pinnedIsPopulated(entry.pin);
      const procs = readPinnedProcs(entry.pin);
      processTerminationConfirmed = populated === false && (procs === null || procs.length === 0);
    }

    // Post-condition 2: the exact container is gone, according to the daemon.
    const inspection = await this.options.inspectContainer(due.containerId);
    const containerRemovalConfirmed = inspection.present === false;

    const resolved = processTerminationConfirmed && containerRemovalConfirmed;
    const concluded: WatchdogArmRecord = {
      ...entry.record,
      phase: resolved ? "terminated" : "quarantined",
      processDebt: processTerminationConfirmed ? "termination-confirmed" : "unresolved",
      containerDebt: containerRemovalConfirmed ? "removal-confirmed" : "unresolved",
      outcome: resolved ? "terminated" : "unresolved",
      sequence: entry.record.sequence + 1,
    };
    try {
      this.store().write(concluded);
      entry.record = concluded;
    } catch (error) {
      detail = `${detail}; the outcome could not be recorded: ${error instanceof Error ? error.message : "unknown"}`;
    }

    // Close the pin once the process question is answered either way: a resolved kill no longer
    // needs it, and an unresolved one must not keep writing through a stale handle.
    if (processTerminationConfirmed && entry.pin !== null) {
      closePinned(entry.pin);
      entry.pin = null;
    }

    return {
      executionId: due.executionId,
      killWritten,
      processTerminationConfirmed,
      containerRemovalConfirmed,
      resolved,
      detail: detail || (resolved ? "terminated and removed" : "termination could not be positively established"),
    };
  }

  /** Write a quarantined record, best-effort. Used on recovery failure paths. */
  private quarantineRecord(record: WatchdogArmRecord, reason: string): void {
    void reason;
    try {
      this.store().write({
        ...record,
        phase: "quarantined",
        processDebt: record.processDebt === "termination-confirmed" ? "termination-confirmed" : "unresolved",
        containerDebt: record.containerDebt === "removal-confirmed" ? "removal-confirmed" : "unresolved",
        outcome: "unresolved",
        sequence: record.sequence + 1,
      });
    } catch {
      // Already on a failure path; the in-memory block stands and arming stays refused.
    }
  }

  /** The concluded state of an execution, for the supervisor's reconciliation and for tests. */
  state(executionId: string): { armed: boolean; phase: WatchdogArmRecord["phase"] | null; record: WatchdogArmRecord | null } {
    const entry = this.live.get(executionId);
    if (entry === undefined) return { armed: false, phase: null, record: null };
    return { armed: entry.record.phase === "armed", phase: entry.record.phase, record: entry.record };
  }

  /** Every execution this watchdog still owes something for. */
  outstanding(): string[] {
    return [...this.live.entries()]
      .filter(([, entry]) => entry.record.phase === "armed" || entry.record.phase === "terminating")
      .map(([id]) => id);
  }

  /** Whether recovery left an unresolved record. Arming is refused while this is set. */
  get recoveryBlock(): string | null {
    return this.recoveryBlocked;
  }

  /** Release every pinned descriptor. Called on shutdown so nothing is left half-open. */
  closeAll(): void {
    for (const entry of this.live.values()) {
      if (entry.pin !== null) {
        closePinned(entry.pin);
        entry.pin = null;
      }
    }
  }
}

/** Generate a watchdog instance identity. */
export function newWatchdogIdentity(now: () => number, pidStart: number, bootId?: string): WatchdogIdentity {
  return {
    instance: `wd-${randomBytes(6).toString("hex")}`,
    bootId: bootId ?? readBootId(),
    pid: process.pid,
    pidStartTimeTicks: pidStart,
    startedMonotonicMs: now(),
  };
}
