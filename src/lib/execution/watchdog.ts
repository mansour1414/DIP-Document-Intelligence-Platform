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
import {
  actualCgroupPath,
  isExactMembership,
  isInsideDipSubtree,
  provesAbsence,
  provesOwnership,
  type ContainerObservation,
  type ExpectedOwnership,
} from "./container-identity";
import { ExecutionArbiter } from "./execution-arbiter";

/** The watchdog's own identity. A restarted watchdog is a different instance. */
export type WatchdogIdentity = {
  instance: string;
  bootId: string;
  pid: number;
  pidStartTimeTicks: number;
  startedMonotonicMs: number;
};

/** A live execution: the durable record plus the descriptors that pin its cgroup. */
/** How many times an unresolved termination is retried before it needs an operator. */
export const TERMINATION_RETRY_LIMIT = 3;
/** Minimum spacing between retries, so a failing attempt is not repeated every tick. */
export const TERMINATION_RETRY_BACKOFF_MS = 5_000;

type LiveExecution = {
  record: WatchdogArmRecord;
  /**
   * Whether ownership of the target was verified at arm time or by a later observation.
   *
   * WD-F03 gates retries on this: a quarantine with verified ownership may be signalled again, and
   * one without it may not. It is false for a record recovered from disk, because a recovered
   * record is a claim until the host confirms it.
   */
  ownershipVerified: boolean;
  /** Termination attempts made. Bounded so a permanently failing kill is not a busy loop. */
  terminationAttempts: number;
  /** Clock reading of the last attempt, for backoff. */
  lastTerminationAtMs: number | null;
  /** Present only when the cgroup could be pinned. Its absence is why a termination may be owed. */
  pin: PinnedCgroup | null;
  heartbeatsSeen: number;
  lastHeartbeatMs: number;
  /** Proofs already issued, so a replayed disarm cannot mint a second grant. */
  issuedGrants: Set<string>;
};

/**
 * Whether one termination attempt may signal its target, and on what authority.
 *
 * - `terminate` — the target may be signalled. `dockerIndependent` records that the daemon did not
 *   confirm the identity during this attempt, so the authority came from established ownership and
 *   the pinned descriptor alone (D2-F01). A report carrying it is evidence that the kernel carried
 *   the attempt, not the daemon.
 * - `quarantine` — nothing may be signalled. The debt stays owed.
 */
export type TerminationAuthority =
  | { kind: "terminate"; dockerIndependent: boolean; detail: string }
  | { kind: "quarantine"; detail: string };

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

  // ## The layout is the driver's, and only two layouts exist
  //
  // A container's cgroup is created by the daemon, not by this system, so the leaf cannot be
  // dictated — but it *is* predictable from the driver, and accepting exactly the two documented
  // forms is stricter than accepting any leaf that happens to contain a known string.
  //
  //   systemd   <mount>/dip-executor.slice/docker-<container id>.scope
  //   cgroupfs  <mount>/dip-executor.slice/<container id>
  //
  // The container id here is the one already corroborated: it must equal the journal intent's
  // recorded id and the id the daemon was queried by, both checked before this function is reached.
  // A leaf that encodes any other container is foreign, and a leaf that encodes nothing is refused.
  // The container *name* is deliberately not accepted: no driver uses it, so accepting it would
  // only widen what may be signalled.
  if (request.containerName !== `dip-exec-${request.executionId}`) {
    return { ok: false, code: "NOT_DIP_OWNED" };
  }
  const relative = request.cgroupPath.slice(mount.path.length);
  const isSystemdScope = relative === `/${DIP_CGROUP_SUBTREE}/docker-${request.containerId}.scope`;
  const isCgroupfsDir = relative === `/${DIP_CGROUP_SUBTREE}/${request.containerId}`;
  if (!isSystemdScope && !isCgroupfsDir) {
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
  //
  // WD-F04: whole-component comparison, not a substring. The previous `includes` accepted a prefix,
  // so a process in `.../dip-exec-aaa…-sibling` satisfied a claim about `.../dip-exec-aaa…`, which
  // is exactly the unrelated-cgroup signal the requirement forbids.
  const actual = actualCgroupPath(request.initPid, mount.path);
  if (actual === null) return { ok: false, code: "PID_UNVERIFIED" };
  const expectedRelative = request.cgroupPath.slice(mount.path.length) || "/";
  if (!isExactMembership(actual.relative, expectedRelative)) return { ok: false, code: "PID_UNVERIFIED" };
  // The member's cgroup must be the one named, and it must be inside the DIP subtree by whole
  // components — a path that merely begins with the DIP slice's characters is not inside it.
  if (!isInsideDipSubtree(actual.path, mount.path, DIP_CGROUP_SUBTREE)) {
    return { ok: false, code: "NOT_DIP_OWNED" };
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
  /**
   * How the watchdog asks the daemon to kill a container.
   *
   * A kill is a request, never a proof. The proof is a later observation that positively reports
   * the exact id absent.
   */
  killContainer: (containerId: string) => Promise<{ ok: boolean; detail: string }>;
  /**
   * Observe one container by exact id, as the closed `ContainerObservation` vocabulary.
   *
   * This replaces a boolean `{ present }`. The boolean could not distinguish a daemon outage from
   * an existing container, so removal could never be positively confirmed (WD-F01). Only
   * `state: "absent"` discharges a removal debt; only `state: "present"` authorizes signalling.
   */
  observeContainer: (expected: ExpectedOwnership) => Promise<ContainerObservation>;
  /**
   * Remove one container by exact id (D2-F04).
   *
   * Optional, and its absence is not a way to skip the metadata debt: without it a present
   * container simply stays owed. It only ever receives the exact 64-character id recorded at arm
   * time — never a name, a label selector or a prefix — so one execution cannot remove another's
   * container even if it wanted to.
   */
  removeContainer?: (containerId: string) => Promise<{ ok: boolean; detail: string }>;
  /**
   * Read the actual cgroup a PID is in, from the host. Injected so ownership can be tested where
   * no container exists; the production default reads `/proc/<pid>/cgroup`.
   */
  actualCgroupPath?: (pid: number, mountPath: string) => { path: string; relative: string } | null;
  /**
   * The cgroup2 mount to verify against.
   *
   * Injected only so a fixture tree can stand in for a real hierarchy. The production default
   * discovers the mount from `/proc/self/mountinfo`, and there is no option to skip verification.
   */
  cgroupMount?: () => string | null;
  /**
   * Trusted supervisor intent, read from the journal. Used to corroborate ownership against a
   * record this watchdog did not write (WD-F04). Optional: without it, ownership rests on the
   * watchdog's own durable record and live observations alone.
   */
  readIntent?: (executionId: string) => TrustedIntent | null;
};

/**
 * The supervisor's own record of what it intended to create.
 *
 * Deliberately a subset of the journal's `SupervisorRecord`: the watchdog needs the identity, not
 * the outcome. Reading it gives the watchdog a second, independent statement of the same facts, so
 * a container that matches only the watchdog's record but not the supervisor's intent is refused.
 */
export type TrustedIntent = {
  executionId: string;
  bootId: string;
  supervisorInstance: string;
  containerName: string;
  containerId: string | null;
  imageDigest: string;
  profileId: string;
};

/**
 * An execution the watchdog owes a termination attempt.
 *
 * `reason` separates the three debts, because they call for different handling and only one of them
 * may be retried autonomously (WD-F03):
 *
 * - `deadline` — armed and past its deadline. Terminate.
 * - `unresolved-process` — a termination was attempted and positive process termination was never
 *   established, while ownership remains verified. Retry, bounded.
 * - `unresolved-container` — the processes are confirmed gone and only metadata removal is owed.
 *   Removal is attempted by exact id; there is no process to signal.
 */
export type TurnToTerminate = {
  executionId: string;
  containerId: string;
  cgroupPath: string;
  reason: "deadline" | "unresolved-process" | "unresolved-container";
};

/** What one termination attempt established. Everything here is evidence, not intention. */
export type TerminationReport = {
  executionId: string;
  /** The kernel accepted a write to the pinned `cgroup.kill`. Not proof of exit. */
  killWritten: boolean;
  /**
   * True when the target was signalled without the watchdog having proven it owns it.
   *
   * Always false in a correct run; it exists so a regression that signals an unverified target is
   * observable rather than silent. WD-F03 makes it a hard precondition instead of an assertion.
   */
  signalledUnverified?: boolean;
  /**
   * The signal was authorized by established ownership and the pinned descriptor alone, without
   * the daemon confirming the identity during this attempt (D2-F01).
   *
   * Reported so the evidence class of a termination is visible: a Docker-independent termination
   * says the kernel carried it. It is never a weaker result — an unverified target is refused, not
   * signalled independently.
   */
  dockerIndependent?: boolean;
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
  /**
   * WD-F02: one operation at a time per execution, across every await.
   *
   * Without this, `disarm` read the phase, awaited the host, and then wrote a conclusion computed
   * from the pre-await phase — so a concurrent `terminate` or a second `disarm` could be overwritten.
   */
  private readonly arbiter = new ExecutionArbiter();
  /** Set when recovery found something it could not positively resolve. Blocks all arming. */
  private recoveryBlocked: string | null = null;

  constructor(options: WatchdogOptions) {
    this.options = options;
  }

  get identity(): WatchdogIdentity {
    return this.options.identity;
  }

  /** The cgroup2 mount this watchdog verifies against. */
  private cgroupMountPath(): string {
    return this.options.cgroupMount?.() ?? findCgroup2Mount()?.path ?? "/sys/fs/cgroup";
  }

  /** Pin a cgroup through the configured implementation. */
  private pinCgroup(cgroupPath: string): ReturnType<typeof pinCgroup> {
    return (this.options.pin ?? pinCgroup)({ cgroupPath, mountPath: this.cgroupMountPath() });
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
        // A recovered record is a claim until the host confirms it. Termination is still owed —
        // the deadline is real — but a *retry* of an unconfirmed target is not authorized.
        ownershipVerified: false,
        terminationAttempts: 0,
        lastTerminationAtMs: null,
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
  async arm(request: ArmRequest): Promise<ArmAck | ArmDenied> {
    // Arming accepts a termination target, so it is arbitrated like every other mutation: two
    // concurrent arms for one execution must not both persist a record.
    const arbitrated = await this.arbiter.run(request.executionId, () => this.armLocked(request));
    if (!arbitrated.ok) {
      return {
        kind: "ARM_DENIED",
        messageId: request.messageId,
        executionId: request.executionId,
        watchdogInstance: this.options.identity.instance,
        code: "ALREADY_ARMED",
      };
    }
    return arbitrated.value;
  }

  private async armLocked(request: ArmRequest): Promise<ArmAck | ArmDenied> {
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

    // ## WD-F04 / D2-F03: the container must be this execution's, before the target is accepted
    //
    // A matching name, subtree and PID start time are not Docker ownership. The exact container id,
    // all five derived labels, the pinned image and the profile are compared against the daemon,
    // and corroborated against intent the supervisor wrote independently. A container that is
    // merely "present" is not enough; a foreign one is refused outright, and an arm that cannot be
    // corroborated at all is refused rather than trusted.
    const ownership = await this.observeOwnership(request);
    if (ownership !== "verified") {
      closePinned(pin);
      // `NOT_DIP_OWNED` is the denial the arm vocabulary already has for "this is not yours".
      // An unreadable journal or an unavailable daemon is not a proven mismatch, so it is reported
      // as an unverified target rather than as an accusation.
      return deny(ownership === "foreign" ? "NOT_DIP_OWNED" : "OWNERSHIP_UNVERIFIED");
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
      // Verified by `verifyArmIdentity` plus the descriptor cross-check immediately above.
      ownershipVerified: true,
      terminationAttempts: 0,
      lastTerminationAtMs: null,
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
    // The lane is taken before anything is read. A refusal is answered without side effects.
    const arbitrated = await this.arbiter.run(request.executionId, () => this.disarmLocked(request, messageId, sequence));
    if (!arbitrated.ok) {
      return {
        executionId: request.executionId,
        requestId: request.requestId,
        code: "TERMINATION_PENDING",
        watchdogInstance: this.options.identity.instance,
      };
    }
    return arbitrated.value;
  }

  /**
   * The disarm decision, holding the execution's lane for its whole duration.
   *
   * Every read of `entry.record` below happens with no other operation able to change it, so the
   * revalidation after the await cannot be pre-empted between the check and the write.
   */
  private async disarmLocked(request: TerminalRequest, messageId: string, sequence: number): Promise<TerminalGrantMessage | TerminalDeniedMessage> {
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

    // The revision this decision is made against. Compared again after the await.
    const sequenceBase = entry.record.sequence;

    // Expiry is decided from the clock alone, before any host work. An expired disarm must be
    // reported as expired whatever the daemon says: masking it behind an observation would turn
    // "this execution is being terminated" into "the host is uncertain", and the supervisor would
    // retry instead of standing aside.
    const expiredEarly = compareDeadline(
      { bootId: entry.record.bootId, deadlineAtMs: entry.record.deadlineAtMs },
      this.options.clock,
    );
    if (expiredEarly.kind === "stale-boot") return deny("MISMATCH");
    if (expiredEarly.kind === "due") return deny("EXPIRED");

    // WD-F04: a disarm is also an ownership decision, because it authorizes publishing. The
    // container's identity is re-established before any of it counts.
    entry.ownershipVerified = await this.verifyContainerOwnership(entry);

    // ## Revalidation after the await (WD-F02)
    //
    // The lane makes this defence in depth rather than the only guard: if arbitration ever
    // regresses, the write below still cannot overwrite a conclusion reached while the host was
    // being read. State, identity, deadline and sequence are re-checked against the record as it is
    // *now*, not as it was before the await.
    const current = this.live.get(context.executionId);
    if (current === undefined || current !== entry) return deny("UNKNOWN_EXECUTION");
    if (entry.record.executionId !== context.executionId
      || entry.record.containerId !== context.containerId
      || entry.record.bootId !== context.bootId) {
      return deny("MISMATCH");
    }
    // `terminating` and `quarantined` are the transitions that can occur while evidence is being
    // gathered: a deadline tick may have begun a termination, or a previous attempt may have left
    // the execution unresolved. Either way this disarm must not conclude it.
    const phaseNow: string = entry.record.phase;
    if (phaseNow === "terminating") return deny("TERMINATION_PENDING");
    if (phaseNow === "quarantined") return deny("UNCERTAIN");
    // A record that advanced while the evidence was gathered belongs to a later decision.
    if (entry.record.sequence !== sequenceBase) return deny("ALREADY_CONCLUDED");
    // A grant already issued for this execution cannot be issued again, whatever the record says.
    if (entry.issuedGrants.size > 0) return deny("ALREADY_CONCLUDED");

    // Caller-supplied `containerRemoved` is not evidence. It is recorded, and then ignored in
    // favour of what this process can establish.
    const evidence = await this.verifyCompletion(entry);

    if (!evidence.processTerminationConfirmed || !evidence.containerRemovalConfirmed) {
      return deny("UNCERTAIN");
    }

    // ## D2-F02: the deadline is re-decided after every await, immediately before the conclusion
    //
    // The check at the top of this method decided expiry from the clock alone, before any host work.
    // That is not enough on its own: `verifyContainerOwnership` and `verifyCompletion` each talk to
    // the daemon, and a slow or wedged daemon can turn a request that started inside the deadline
    // into one that finishes well outside it. A grant issued then would be a completion granted
    // *after* the deadline — the one outcome that must never happen, because the two authorities
    // (the supervisor finishing, the deadline expiring) would both have won.
    //
    // So expiry is decided again here, from the clock, after everything asynchronous has settled and
    // before anything durable is written. A bounded, non-blocking observation: the deadline must be
    // able to terminate even while this very method is waiting on Docker.
    const expiredLate = compareDeadline(
      { bootId: entry.record.bootId, deadlineAtMs: entry.record.deadlineAtMs },
      this.options.clock,
    );
    if (expiredLate.kind === "stale-boot") return deny("MISMATCH");
    if (expiredLate.kind === "due") return deny("EXPIRED");
    // The record may also have moved while the host was being read — a termination attempt started
    // concurrently would have rewritten it. A conclusion is not written over a later revision.
    if (entry.record.sequence !== sequenceBase) return deny("ALREADY_CONCLUDED");
    if (entry.record.phase !== "armed") return deny("TERMINATION_PENDING");

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
   * Establish Docker ownership for a request that is about to be armed.
   *
   * Returns `foreign` only for a *positive* mismatch: the daemon answered and the container is not
   * this execution's. An unreadable or unavailable daemon is `unverified`, which is a refusal but
   * not an accusation.
   */
  private async observeOwnership(request: ArmRequest): Promise<"verified" | "foreign" | "unverified"> {
    // ## D2-F03: the supervisor's journal is mandatory for a new arm
    //
    // The watchdog's own record is written by the party being checked. A single source cannot
    // corroborate itself, so an arm that has no independent statement of intent is refused: absent
    // an intent, "the container matches what I wrote" only means the two halves of one process agree.
    //
    // The intent must be *readable and valid*, not merely present. A configured journal that cannot
    // be read (permissions, a corrupted file, a record from a different schema) is refused rather
    // than treated as "no corroboration needed", because the failure is indistinguishable from an
    // attacker making the corroborating evidence disappear.
    const readIntent = this.options.readIntent;
    if (readIntent === undefined) return "unverified";
    let intent: TrustedIntent | null;
    try {
      intent = readIntent(request.executionId);
    } catch {
      // Unreadable is not absent. Refused, and not as an accusation of foreignness: nothing is
      // known about the target either way.
      return "unverified";
    }
    if (intent === null) return "unverified";

    if (intent.executionId !== request.executionId
      || intent.bootId !== request.bootId
      || intent.supervisorInstance !== request.supervisorInstance
      || intent.containerName !== request.containerName
      || intent.imageDigest !== request.imageDigest
      || intent.profileId !== request.profileId) {
      return "foreign";
    }
    // The intent names the container id once `docker create` succeeded, and the supervisor arms
    // after that. A null id here means the journal has not recorded creation, so there is nothing
    // to arm against; a different non-null id is a different container.
    if (intent.containerId === null || intent.containerId !== request.containerId) return "foreign";

    const observation = await this.options.observeContainer({
      executionId: request.executionId,
      containerId: request.containerId,
      containerName: request.containerName,
      imageDigest: request.imageDigest,
      profileId: request.profileId,
      bootId: request.bootId,
      supervisorInstance: request.supervisorInstance,
    });

    switch (observation.state) {
      case "present":
        return "verified";
      case "present-foreign":
        return "foreign";
      case "absent":
        // The supervisor claims a container that does not exist. That is a mismatch between the
        // request and the host, not an unavailable daemon.
        return "foreign";
      default:
        return "unverified";
    }
  }

  /** The ownership a record claims, in the shape the observation contract takes. */
  private expectedOwnership(record: WatchdogArmRecord): ExpectedOwnership {
    return {
      executionId: record.executionId,
      containerId: record.containerId,
      containerName: record.containerName,
      imageDigest: record.imageDigest,
      profileId: record.profileId,
      bootId: record.bootId,
      supervisorInstance: record.supervisorInstance,
    };
  }

  /**
   * Establish that the container is still this execution's, from the daemon and the journal.
   *
   * WD-F04: a name, a subtree and a matching PID start time do not prove ownership. The container
   * id, all five derived labels, the pinned image and the profile are compared exactly, and — when
   * the supervisor's journal is readable — corroborated against the intent the supervisor wrote.
   *
   * Returns false for every observation other than a positively matched, currently present
   * container. A foreign container is a *negative* answer, not an ambiguous one.
   */
  private async verifyContainerOwnership(entry: LiveExecution): Promise<boolean> {
    const expected = this.expectedOwnership(entry.record);

    // ## D2-F03: a journal that cannot be read is a refusal to *arm*, not a barrier to *terminating*
    //
    // The journal is mandatory when a new arm is accepted, because a record cannot corroborate
    // itself. It is not a condition on acting on an execution that was already armed from it: if a
    // throwing read were propagated here, deleting or chmod'ing the journal would be a way to keep a
    // container alive past its deadline. An unreadable intent therefore contributes no
    // corroboration and nothing else — the same answer as a mismatch, which is refusal to signal
    // unless authority was established earlier (D2-F01) and verified afresh from the daemon.
    let intent: TrustedIntent | null = null;
    try {
      intent = this.options.readIntent?.(entry.record.executionId) ?? null;
    } catch {
      intent = null;
    }
    if (intent !== null) {
      // Two independent statements of the same facts must agree. A disagreement means one of them
      // is stale or forged, and neither is a basis for signalling.
      if (intent.executionId !== expected.executionId
        || intent.bootId !== expected.bootId
        || intent.supervisorInstance !== expected.supervisorInstance
        || intent.containerName !== expected.containerName
        || intent.imageDigest !== expected.imageDigest
        || intent.profileId !== expected.profileId) {
        return false;
      }
      if (intent.containerId !== null && intent.containerId !== expected.containerId) return false;
    }

    const observation = await this.options.observeContainer(expected);
    if (!provesOwnership(observation)) return false;

    // The recorded cgroup must still be the cgroup this execution's init is actually in. WD-F04:
    // derived from `/proc/<pid>/cgroup`, with whole-component matching, not from a naming scheme.
    //
    // An unreadable mount is a refusal, not a skip: if the hierarchy cannot be found, membership
    // cannot be established, and membership is a precondition for signalling.
    const mount = this.options.cgroupMount?.() ?? (findCgroup2Mount()?.path ?? null);
    if (mount === null) return false;
    const readPath = this.options.actualCgroupPath ?? actualCgroupPath;
    const actual = readPath(entry.record.initPid, mount);
    if (actual === null) return false;
    if (!isInsideDipSubtree(actual.path, mount, DIP_CGROUP_SUBTREE)) return false;
    const expectedRelative = entry.record.cgroupPath.slice(mount.length);
    if (!isExactMembership(actual.relative, expectedRelative)) return false;

    return true;
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
    observation: ContainerObservation;
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

    // WD-F01: only a positively confirmed exact-id absence discharges the removal debt. Every other
    // observation — present, foreign, unavailable, denied, ambiguous — leaves it owed.
    const observation = await this.options.observeContainer(this.expectedOwnership(entry.record));
    const containerRemovalConfirmed = provesAbsence(observation);

    return { processTerminationConfirmed, containerRemovalConfirmed, observation };
  }

  /**
   * Advance deadlines. Called on the watchdog's own timer.
   *
   * An execution whose deadline has passed stays in the map with its termination debt intact. It is
   * *not* concluded here: concluding is what `terminate` does once it has evidence, and marking it
   * concluded first is what used to make a late disarm cancel the kill.
   */
  dueForTermination(): TurnToTerminate[] {
    const due: TurnToTerminate[] = [];
    for (const [executionId, entry] of this.live) {
      const record = entry.record;

      // ## WD-F03: an unresolved debt is not abandoned
      //
      // A quarantined execution was previously excluded here, which meant a positively identified
      // executor whose kill could not be confirmed was never attempted again — the debt was
      // retained on paper and dropped in practice. It is admitted now, but only on the terms below.
      if (record.phase === "quarantined") {
        // Retry only when ownership is still verified. An unverified target is never signalled
        // again: repeating a signal at something that might be a different container is worse than
        // waiting for an operator.
        if (entry.ownershipVerified !== true) continue;
        // Bounded: a retry budget, and a backoff so a failed attempt is not repeated on every tick.
        if (entry.terminationAttempts >= TERMINATION_RETRY_LIMIT) continue;
        const last = entry.lastTerminationAtMs ?? 0;
        if (this.options.clock.nowMs() - last < TERMINATION_RETRY_BACKOFF_MS) continue;
        due.push({
          executionId,
          containerId: record.containerId,
          cgroupPath: record.cgroupPath,
          reason: record.processDebt === "termination-confirmed" ? "unresolved-container" : "unresolved-process",
        });
        continue;
      }

      if (record.phase !== "armed" && record.phase !== "terminating") continue;
      const comparison = compareDeadline(
        { bootId: record.bootId, deadlineAtMs: record.deadlineAtMs },
        this.options.clock,
      );
      if (comparison.kind !== "due") continue;
      due.push({ executionId, containerId: record.containerId, cgroupPath: record.cgroupPath, reason: "deadline" });
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
  async terminate(due: TurnToTerminate): Promise<TerminationReport> {
    // WD-F02: the same lane as disarm. A termination and a disarm for one execution are mutually
    // exclusive, so neither can write a conclusion computed from pre-await state.
    const arbitrated = await this.arbiter.run(due.executionId, () => this.terminateLocked(due));
    if (!arbitrated.ok) {
      return {
        executionId: due.executionId,
        killWritten: false,
        processTerminationConfirmed: false,
        containerRemovalConfirmed: false,
        resolved: false,
        detail: "another operation holds this execution; the deadline is still owed",
      };
    }
    return arbitrated.value;
  }

  private async terminateLocked(due: TurnToTerminate): Promise<TerminationReport> {
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

    // ## D2-F01 / WD-F04 / WD-F03: kernel-first authority before the signal
    //
    // Nothing is signalled until the target is shown to be this execution's. The authority is the
    // kernel's — established ownership plus a still-valid pinned descriptor — and the daemon's
    // present answer can only corroborate it, never withhold it. A target whose ownership was never
    // established (a record recovered from disk, an arm that failed verification) is refused, and a
    // pin that no longer names its inode is refused, exactly as before.
    const authority = await this.terminationAuthority(entry);
    entry.terminationAttempts += 1;
    entry.lastTerminationAtMs = this.options.clock.nowMs();

    // A container-debt-only turn has no process to signal: the processes are already confirmed
    // gone, so writing `cgroup.kill` again would act on an empty cgroup. Removal is attempted
    // below, by exact id, and nothing else.
    const processOwed = entry.record.processDebt !== "termination-confirmed";

    // Record intent before acting, so a crash between here and the kill leaves `terminating`.
    //
    // ## Why a write failure does not stop the termination
    //
    // WD-F03: an already armed execution with verified ownership has a mandatory emergency
    // termination. Refusing to signal because the *journal* is unwritable would trade a durable
    // record for a live container — and the record is the thing that can be reconstructed, while
    // the running processes cannot be recalled. The write is therefore attempted, its failure is
    // reported, and the termination proceeds.
    let durableIntent = true;
    if (processOwed) {
      const terminating: WatchdogArmRecord = {
        ...entry.record,
        phase: "terminating",
        processDebt: "terminate-required",
        sequence: entry.record.sequence + 1,
      };
      try {
        this.store().write(terminating);
        entry.record = terminating;
      } catch {
        // The in-memory record still advances, so the attempt is accounted for and a retry is
        // bounded; only the durable copy is stale, and the report says so.
        durableIntent = false;
        entry.record = { ...terminating };
      }
    }

    let killWritten = false;
    let signalledUnverified = false;
    let detail = "";

    const maySignal = authority.kind === "terminate";
    if (!maySignal) {
      // WD-F03: never signal an unverified target. The debt is retained, the attempt is counted,
      // and an operator resolves it. Repeating a signal at something that might be a different
      // container is worse than waiting.
      detail = authority.detail;
      signalledUnverified = false;
    } else if (!processOwed) {
      detail = "the processes are already confirmed gone; no kill was written";
    } else if (entry.pin === null || entry.pin.dirFd < 0) {
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
    // fallback for the case where the cgroup could not be signalled at all — and only for a target
    // whose ownership is verified and whose processes are actually owed a signal.
    if (!killWritten && maySignal && processOwed) {
      const killed = await this.options.killContainer(due.containerId);
      if (killed.ok) {
        killWritten = true;
        detail = "the daemon accepted a kill for the exact container id";
      } else if (detail === "") {
        detail = `the daemon refused the kill: ${killed.detail}`;
      }
    }

    // Post-condition 1: no tasks remain, read through the pinned descriptor. A prior confirmation
    // is not withdrawn by a later turn that cannot read the cgroup — the fact was established, and
    // re-deriving it from a cgroup that may already have disappeared would retract true evidence.
    let processTerminationConfirmed = !processOwed;
    if (!processTerminationConfirmed && entry.pin !== null && entry.pin.dirFd >= 0) {
      const populated = pinnedIsPopulated(entry.pin);
      const procs = readPinnedProcs(entry.pin);
      processTerminationConfirmed = populated === false && (procs === null || procs.length === 0);
    }

    // ## Post-condition 2: metadata, by exact id, and only after the processes are confirmed gone
    //
    // D2-F04: observing that the container is absent is not the same as having removed it. A
    // positively identified container can be **stopped but still present**, holding its name, its
    // cgroup slot and its writable layer. The metadata debt is owed until the exact id is gone, and
    // a present container is therefore removed here by exact id — never by name, label or prefix.
    //
    // The order matters: metadata removal is attempted only once the process question is answered.
    // Removing a container whose processes are still running would let the daemon tear down the
    // cgroup while tasks remain, which is how a terminated execution leaves orphans behind.
    let observation = await this.options.observeContainer(this.expectedOwnership(entry.record));
    let containerRemovalConfirmed = provesAbsence(observation);

    if (!containerRemovalConfirmed && processTerminationConfirmed && observation.state === "present") {
      // Bounded: one removal attempt per termination turn. `removeContainer` acts on the exact id
      // the record names and cannot reach anything else.
      const removal = await (this.options.removeContainer?.(due.containerId)
        ?? Promise.resolve({ ok: false, detail: "no removal seam is configured" }));
      const after = await this.options.observeContainer(this.expectedOwnership(entry.record));
      observation = after;
      containerRemovalConfirmed = provesAbsence(after);
      detail = removal.ok
        ? `${detail}; the exact container id was removed (${after.state})`
        : `${detail}; the daemon refused the removal: ${removal.detail}`;
    } else if (observation.state === "present" && !processTerminationConfirmed) {
      // Present, and owed processes are still running. Deliberately *not* removed: the metadata is
      // kept so the next attempt still has an addressable container to signal.
      detail = `${detail}; the container is present but its processes are not confirmed gone, so removal is deferred`;
    }

    if (!containerRemovalConfirmed) {
      detail = `${detail}; removal not confirmed (${observation.state})`;
    }

    // `resolved` describes the *durable* conclusion, not the bare observations. If the record could
    // not be written, nothing downstream may treat this execution as safely concluded: a restart
    // would see the pre-attempt state, and a release authorized by memory alone is exactly what the
    // durability requirement forbids.
    const factsEstablished = processTerminationConfirmed && containerRemovalConfirmed;
    const concluded: WatchdogArmRecord = {
      ...entry.record,
      phase: factsEstablished ? "terminated" : "quarantined",
      processDebt: processTerminationConfirmed ? "termination-confirmed" : "unresolved",
      containerDebt: containerRemovalConfirmed ? "removal-confirmed" : "unresolved",
      outcome: factsEstablished ? "terminated" : "unresolved",
      sequence: entry.record.sequence + 1,
    };
    let recorded = false;
    try {
      this.store().write(concluded);
      entry.record = concluded;
      recorded = true;
    } catch {
      // Kept in memory so the attempt is accounted for and a retry is bounded, but the report does
      // not claim resolution.
      entry.record = concluded;
      detail = `${detail}; the outcome could not be recorded durably`;
    }
    const resolved = factsEstablished && recorded;

    // Close the pin once the process question is answered either way: a resolved kill no longer
    // needs it, and an unresolved one must not keep writing through a stale handle.
    if (processTerminationConfirmed && entry.pin !== null) {
      closePinned(entry.pin);
      entry.pin = null;
    }

    if (!durableIntent) {
      // Reported, not swallowed: the in-memory record advanced but the durable copy did not, so a
      // restart will see the state as it was before this attempt.
      detail = `${detail}; the durable intent could not be written, so a restart may not see this attempt`;
    }

    return {
      executionId: due.executionId,
      killWritten,
      signalledUnverified,
      dockerIndependent: authority.kind === "terminate" && authority.dockerIndependent,
      processTerminationConfirmed,
      containerRemovalConfirmed,
      resolved,
      detail: detail || (resolved ? "terminated and removed" : "termination could not be positively established"),
    };
  }

  /**
   * Termination authority for a target whose process identity was positively established.
   *
   * ## D2-F01: kernel-first, and Docker-independent
   *
   * Docker is not the authority on whether this execution's processes are alive; the kernel is,
   * through the cgroup that was pinned when ownership was proved. Requiring a *live* Docker answer
   * at every termination attempt made the daemon a gate on terminating its own container. Three
   * situations followed, all of them wrong:
   *
   * - the daemon becomes unavailable mid-execution, so a container that is plainly running — its
   *   identity established, its descriptors pinned — is never signalled;
   * - the container's init exits while descendants remain in the cgroup, and the daemon reports the
   *   container gone while `cgroup.procs` is not empty;
   * - the daemon's metadata disappears (a pruned record, a restarted daemon) and the watchdog reads
   *   "I cannot see it" as "it is not mine".
   *
   * The safe rule is not "Docker must confirm". It is: **previously established ownership plus a
   * still-valid pinned descriptor authorizes the kernel signal; anything else authorizes nothing.**
   * A daemon observation can *add* authority — it can establish absence and discharge the metadata
   * debt — but it can never *remove* authority the kernel already carries.
   *
   * This deliberately does not weaken arming or restart recovery. Arming still requires a positive
   * ownership observation, and a record recovered from disk starts with `ownershipVerified: false`,
   * so it takes the `requires-observation` branch below and must be confirmed by the host before a
   * signal. Only an execution that was verified while this process was running, or verified by an
   * observation in this attempt, can reach `terminate`.
   */
  private async terminationAuthority(entry: LiveExecution): Promise<TerminationAuthority> {
    // A descriptor that no longer names the inode it was pinned from is not a descriptor for this
    // execution's cgroup. That is the one condition under which a pinned target is refused.
    if (entry.pin !== null && entry.pin.dirFd >= 0) {
      const pinState = verifyPin(entry.pin);
      if (!pinState.ok) {
        return { kind: "quarantine", detail: `the pin is no longer valid: ${pinState.code}` };
      }
    }

    const confirmedNow = await this.verifyContainerOwnership(entry);
    if (confirmedNow) entry.ownershipVerified = true;

    if (entry.ownershipVerified) {
      // Ownership was established — now, or earlier in this process's life. The kernel signal is
      // authorized whatever the daemon says at this instant.
      return { kind: "terminate", dockerIndependent: !confirmedNow, detail: "" };
    }

    // Never confirmed while this process was running. The record is a claim, and a claim is not a
    // target. Refused, with the debt retained for an operator.
    return { kind: "quarantine", detail: "ownership is not verified; the target was not signalled" };
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
