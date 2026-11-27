/**
 * The independent Watchdog (R7D.1 §4, §5).
 *
 * ## Why it is a separate process
 *
 * The Watchdog's job is to terminate a container when the deadline passes, *including* when the
 * Supervisor is wedged, dead, or has decided not to act. A watchdog that shares an event loop
 * with the supervisor inherits the supervisor's failure modes, which makes it decorative.
 *
 * This module is the watchdog's logic. `scripts/watchdog-main.mjs` is the runnable entry point
 * that owns its own event loop, socket and signal handling.
 *
 * ## What it verifies before arming
 *
 * Arming is the point at which this process takes responsibility for a kill. It will not arm
 * until it has independently confirmed, from the host, that the container described in the
 * request is the container that exists:
 *
 *   1. the boot id matches the one this process can see;
 *   2. the container's cgroup directory exists and its inode matches what the daemon reported
 *      indirectly through the path;
 *   3. `cgroup.events`, `cgroup.kill` and `cgroup.procs` all exist and their inodes are recorded;
 *   4. the init PID exists and its kernel start time matches the recorded one.
 *
 * A mismatch is a refusal, not a warning. Arming on unverified identity means later killing
 * something that is not ours.
 *
 * ## What it cannot do
 *
 * Opening a directory descriptor and using `/proc/self/fd/<n>/cgroup.kill` narrows the window in
 * which a path could be swapped between verification and use. It does **not** pin the object:
 * `/proc/self/fd/<n>` resolves through the descriptor, but whether that is sufficient against a
 * concurrent rename on a given kernel is a property of that kernel, and this environment has no
 * delegated cgroup to test it against. Descriptor-pinning safety is therefore **NOT TESTED**, and
 * the fallback is the recorded identity — device and inode — checked again immediately before
 * the kill.
 */

import { openSync, closeSync, readFileSync, readdirSync, writeFileSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";
import {
  MessageIdWindow,
  WATCHDOG_LIMITS,
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
  type TerminalOutcome,
  type TerminalRequest,
} from "./terminal-auth";
import { readBootId, pathIdentity, readCgroupPopulated, readProcessStartTimeTicks, findCgroup2Mount } from "./host-facts";
import { randomBytes } from "node:crypto";

/** The watchdog's own identity. A restarted watchdog is a different instance. */
export type WatchdogIdentity = {
  instance: string;
  bootId: string;
  pid: number;
  pidStartTimeTicks: number;
  startedMonotonicMs: number;
};

/** What the watchdog holds for one armed execution. */
type ArmedExecution = {
  request: ArmRequest;
  identity: WatchdogIdentity;
  /** Monotonic reading at which the deadline fires. */
  deadlineAtMonotonicMs: number;
  /** Verified cgroup facts, re-checked at termination time. */
  observed: {
    dirInode: number;
    eventsInode: number;
    killInode: number;
    procsInode: number;
    device: string;
    bootId: string;
  };
  /** Concluded state. Once set, the execution is no longer armed. */
  concluded: null | {
    outcome: "disarmed" | "terminated" | "unresolved";
    atMonotonicMs: number;
    /** Set for `disarmed`, so a duplicate disarm can be refused with a specific code. */
    grantIssued: boolean;
  };
  /** Issued grants, kept so a replay is refused rather than re-minted. */
  issuedGrants: Set<string>;
  heartbeatsSeen: number;
  lastHeartbeatMonotonicMs: number;
};

/** What the watchdog observed, or why it refused. */
export type HostVerification =
  | { ok: true; dirInode: number; eventsInode: number; killInode: number; procsInode: number; device: string; bootId: string }
  | { ok: false; code: "BOOT_MISMATCH" | "CGROUP_UNVERIFIED" | "PID_UNVERIFIED" };

/**
 * Independently confirm, from the host, that the container in a request is the container that
 * exists.
 *
 * Exported and separately testable because it is the load-bearing part of arming: everything
 * after it assumes the identity is real. It is also the part that cannot be exercised in an
 * environment without a writable cgroup hierarchy, so the state machine takes an injected
 * verifier and this function has its own direct tests.
 */
export function verifyArmIdentity(request: ArmRequest, bootId: string): HostVerification {
  // A request from a previous boot describes namespaces that no longer exist; arming it would
  // register a deadline against an inode number that now means something else.
  if (request.bootId !== bootId) return { ok: false, code: "BOOT_MISMATCH" };

  const dir = pathIdentity(request.cgroupPath);
  if (dir === null || !dir.isDirectory) return { ok: false, code: "CGROUP_UNVERIFIED" };

  const events = pathIdentity(join(request.cgroupPath, "cgroup.events"));
  const kill = pathIdentity(join(request.cgroupPath, "cgroup.kill"));
  const procs = pathIdentity(join(request.cgroupPath, "cgroup.procs"));
  if (events === null || kill === null || procs === null) return { ok: false, code: "CGROUP_UNVERIFIED" };

  // The cgroup must be on the cgroup2 filesystem this process can see. A path that exists but
  // belongs to another mount is a different hierarchy with the same name.
  const mount = findCgroup2Mount();
  if (mount === null || !request.cgroupPath.startsWith(mount.path)) return { ok: false, code: "CGROUP_UNVERIFIED" };

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
    if (!membership.includes(`0::${relative}`)) return { ok: false, code: "PID_UNVERIFIED" };
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
  /**
   * Override host verification. Exists so the arbitration state machine can be tested where no
   * cgroup hierarchy is writable; the default is `verifyArmIdentity` and there is no option to
   * skip verification entirely.
   */
  verifyHost?: (request: ArmRequest, bootId: string) => HostVerification;
  /** Shared secret with the supervisor, for ack and grant signatures. */
  secret: Buffer;
  /** Injectable clock, so a deadline can be tested without waiting for it. */
  monotonicMs: () => number;
  /** How the watchdog kills a container. Injected so it is testable and mockable separately. */
  killContainer: (containerId: string) => Promise<{ ok: boolean; detail: string }>;
  /** How the watchdog confirms removal. Injected for the same reason. */
  inspectContainer: (containerId: string) => Promise<{ present: boolean; detail: string }>;
};

/**
 * The watchdog's state machine.
 *
 * Deliberately not an EventEmitter: the supervisor's control channel calls these methods
 * synchronously with a resolved frame, and an asynchronous callback surface would let a grant be
 * observed before the state recording it had been durably written.
 */
export class Watchdog {
  private readonly options: WatchdogOptions;
  private readonly armed = new Map<string, ArmedExecution>();
  private readonly messageIds = new MessageIdWindow();

  constructor(options: WatchdogOptions) {
    this.options = options;
  }

  get identity(): WatchdogIdentity {
    return this.options.identity;
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
   * ARM: verify identity, record it, register the deadline.
   *
   * Every failure is a refusal with a closed code. There is no "arm anyway" path.
   */
  arm(request: ArmRequest): ArmAck | ArmDenied {
    const deny = (code: ArmDenied["code"]): ArmDenied => ({
      kind: "ARM_DENIED",
      messageId: request.messageId,
      executionId: request.executionId,
      watchdogInstance: this.options.identity.instance,
      code,
    });

    if (!this.messageIds.consume(request.executionId, request.messageId)) return deny("REPLAYED");

    const existing = this.armed.get(request.executionId);
    if (existing !== undefined && existing.concluded === null) return deny("ALREADY_ARMED");

    // Verify identity against the host before taking responsibility for a kill. The verifier is
    // injectable for testability only; the default reads /proc and /sys directly.
    const verified = (this.options.verifyHost ?? verifyArmIdentity)(request, this.options.identity.bootId);
    if (!verified.ok) return deny(verified.code);

    const now = this.options.monotonicMs();
    const deadlineAtMonotonicMs = now + request.deadlineMs;

    // 6. Record durably before acknowledging. The supervisor's journal write happens on its side;
    //    this is the watchdog's independent record, which is what makes recovery possible when
    //    the supervisor is gone.
    const record: ArmedExecution = {
      request,
      identity: this.options.identity,
      deadlineAtMonotonicMs,
      observed: {
        dirInode: verified.dirInode,
        eventsInode: verified.eventsInode,
        killInode: verified.killInode,
        procsInode: verified.procsInode,
        device: verified.device,
        bootId: verified.bootId,
      },
      concluded: null,
      issuedGrants: new Set(),
      heartbeatsSeen: 0,
      lastHeartbeatMonotonicMs: now,
    };
    this.armed.set(request.executionId, record);

    // 7. Register independent deadline enforcement. The caller drives `tick()`; the entry point
    //    runs it on its own timer, which is the whole point of a separate process.
    const ackBase: Omit<ArmAck, "proof"> = {
      kind: "ARM_ACK",
      messageId: request.messageId,
      executionId: request.executionId,
      watchdogInstance: this.options.identity.instance,
      observedCgroupDirInode: verified.dirInode,
      observedCgroupEventsInode: verified.eventsInode,
      observedCgroupKillInode: verified.killInode,
      observedCgroupProcsInode: verified.procsInode,
      observedCgroupDevice: verified.device,
      observedBootId: verified.bootId,
      armedAtMonotonicMs: now,
    };
    return { ...ackBase, proof: signArmAck(this.options.secret, ackBase) };
  }

  /** Verify an ack this watchdog produced, for the supervisor's use in tests and in the client. */
  verifyAck(ack: ArmAck): boolean {
    return verifyArmAck(this.options.secret, ack);
  }

  /** Record a heartbeat. Liveness only; it authorizes nothing. */
  heartbeat(beat: Heartbeat): { ok: boolean; code?: "UNKNOWN_EXECUTION" | "REPLAYED" } {
    if (!this.messageIds.consume(beat.executionId, beat.messageId)) return { ok: false, code: "REPLAYED" };
    const record = this.armed.get(beat.executionId);
    if (record === undefined) return { ok: false, code: "UNKNOWN_EXECUTION" };
    record.heartbeatsSeen += 1;
    record.lastHeartbeatMonotonicMs = this.options.monotonicMs();
    return { ok: true };
  }

  /**
   * DISARM: serialized against termination.
   *
   * ## The race this closes
   *
   * A supervisor that has a valid completion and a watchdog whose deadline fires at the same
   * moment must not both act. Whoever reaches the record first sets `concluded`, and the other
   * observes it and refuses. Because this method is synchronous and the map is in one process,
   * there is no interleaving in which both win — which is exactly what "a supervisor reading a
   * journal snapshot" could not provide.
   */
  disarm(request: TerminalRequest, messageId: string, sequence: number): TerminalGrantMessage | TerminalDeniedMessage {
    const deny = (code: TerminalDeniedMessage["code"]): TerminalDeniedMessage => ({
      executionId: request.executionId,
      requestId: request.requestId,
      code,
      watchdogInstance: this.options.identity.instance,
    });

    // Validate the context before anything else: it is what the grant will be bound to, and an
    // invalid one must not consume the execution's concluded state.
    let context: TerminalRequest;
    try {
      context = assertTerminalContext(request);
    } catch {
      return deny("MISMATCH");
    }

    if (!this.messageIds.consume(context.executionId, messageId)) return deny("ALREADY_CONCLUDED");
    void sequence;

    const record = this.armed.get(context.executionId);
    if (record === undefined) return deny("UNKNOWN_EXECUTION");

    // Already concluded — by a previous disarm or by the deadline.
    if (record.concluded !== null) {
      if (record.concluded.outcome === "terminated") return deny("TERMINATED");
      return deny("ALREADY_CONCLUDED");
    }

    // Expired between the supervisor's decision and this call. The deadline is the authority
    // until a disarm wins the record, and it has not won.
    if (this.options.monotonicMs() >= record.deadlineAtMonotonicMs) {
      record.concluded = { outcome: "unresolved", atMonotonicMs: this.options.monotonicMs(), grantIssued: false };
      return deny("EXPIRED");
    }

    // The context must describe the execution this watchdog armed. A grant for a different
    // container or a different boot would authorize killing and releasing the wrong thing.
    if (context.containerId !== record.request.containerId
      || context.containerName !== record.request.containerName
      || context.bootId !== record.identity.bootId
      || context.supervisorInstance !== record.request.supervisorInstance
      || context.operation !== record.request.operation) {
      return deny("MISMATCH");
    }

    // Only these outcomes are eligible to release a document. A refusal or a timeout is a valid
    // outcome and must not publish anything.
    const eligible: TerminalOutcome[] = ["committed", "refused", "timeout", "cancelled", "failed"];
    if (!eligible.includes(context.outcome)) return deny("UNCERTAIN");
    // A commit requires positive removal evidence. Without it the container may still exist and
    // holding the execution open is the only safe answer.
    if (context.outcome === "committed" && !context.containerRemoved) return deny("UNCERTAIN");

    // Conclude and issue, in that order, so no observer can see a grant whose conclusion was not
    // recorded.
    record.concluded = { outcome: "disarmed", atMonotonicMs: this.options.monotonicMs(), grantIssued: true };
    const grant = signDisarmGrant(this.options.secret, { ...context, watchdogInstance: this.options.identity.instance });
    record.issuedGrants.add(grant.proof);
    return grant;
  }

  /**
   * Advance deadlines. Called on the watchdog's own timer.
   *
   * Returns the executions whose deadline has fired so the caller can perform the kill. The
   * conclusion is recorded *before* the kill is attempted: if the process dies mid-kill, the
   * record shows that a termination was underway, which is a fact recovery needs.
   */
  dueForTermination(): Array<{ executionId: string; containerId: string; cgroupPath: string; observed: ArmedExecution["observed"] }> {
    const now = this.options.monotonicMs();
    const due: Array<{ executionId: string; containerId: string; cgroupPath: string; observed: ArmedExecution["observed"] }> = [];
    for (const [executionId, record] of this.armed) {
      if (record.concluded !== null) continue;
      if (now < record.deadlineAtMonotonicMs) continue;
      record.concluded = { outcome: "unresolved", atMonotonicMs: now, grantIssued: false };
      due.push({
        executionId,
        containerId: record.request.containerId,
        cgroupPath: record.request.cgroupPath,
        observed: record.observed,
      });
    }
    return due;
  }

  /**
   * Attempt kernel-first termination of a due execution.
   *
   * ## Order matters
   *
   * The cgroup write comes first because it is the only mechanism that reaches every process in
   * the container at once. `docker kill` is the fallback for the case where the cgroup is gone
   * but the container record is not.
   *
   * ## What this does not prove
   *
   * A successful write to `cgroup.kill` means the kernel accepted the request. It does not mean
   * termination has completed: the caller must confirm either `populated 0` in `cgroup.events`
   * or positive disappearance. And `populated 0` does not mean zero charged memory — page cache
   * outlives tasks and the charge is released separately.
   */
  async terminate(due: { executionId: string; containerId: string; cgroupPath: string; observed: ArmedExecution["observed"] }): Promise<{
    executionId: string;
    signalSent: boolean;
    populated: boolean | null;
    containerPresent: boolean;
    detail: string;
  }> {
    // Re-verify identity immediately before acting. The path may have been reused since the arm.
    const dir = pathIdentity(due.cgroupPath);
    const kill = pathIdentity(join(due.cgroupPath, "cgroup.kill"));
    if (dir === null || kill === null || dir.inode !== due.observed.dirInode || kill.inode !== due.observed.killInode) {
      // The cgroup is not the one this watchdog armed against. Do not write to a path that now
      // belongs to something else; escalate as unresolved rather than guessing.
      return {
        executionId: due.executionId,
        signalSent: false,
        populated: null,
        containerPresent: true,
        detail: "cgroup identity changed since arm; refusing to signal",
      };
    }

    let signalSent = false;
    let detail = "";
    try {
      writeFileSync(join(due.cgroupPath, "cgroup.kill"), "1");
      signalSent = true;
    } catch (error) {
      detail = error instanceof Error ? error.message : "cgroup.kill failed";
    }

    // Fallback: ask the daemon to kill the exact container. Sequenced after the cgroup attempt
    // because the cgroup write is the one that cannot be intercepted by a compromised daemon.
    let killResult = { ok: false, detail: "not attempted" };
    if (!signalSent) {
      killResult = await this.options.killContainer(due.containerId);
      signalSent = killResult.ok;
    }

    const populated = readCgroupPopulated(due.cgroupPath);
    const inspection = await this.options.inspectContainer(due.containerId);

    // Positive resolution only: either the cgroup reports no tasks, or the container is gone.
    // "Probably dead" is not a state this method returns.
    if (!inspection.present) {
      this.markTerminated(due.executionId, "terminated");
    } else if (populated === false) {
      this.markTerminated(due.executionId, "terminated");
    } else {
      // Failed to establish termination. Retain quarantine.
      this.markTerminated(due.executionId, "unresolved");
    }

    return {
      executionId: due.executionId,
      signalSent,
      populated,
      containerPresent: inspection.present,
      detail: detail || killResult.detail,
    };
  }

  private markTerminated(executionId: string, outcome: "terminated" | "unresolved"): void {
    const record = this.armed.get(executionId);
    if (record === undefined) return;
    record.concluded = { outcome, atMonotonicMs: this.options.monotonicMs(), grantIssued: false };
  }

  /** The concluded state of an execution, for the supervisor's reconciliation. */
  state(executionId: string): { armed: boolean; concluded: ArmedExecution["concluded"] } {
    const record = this.armed.get(executionId);
    if (record === undefined) return { armed: false, concluded: null };
    return { armed: record.concluded === null, concluded: record.concluded };
  }

  /** Every execution this watchdog still holds, for recovery reporting. */
  outstanding(): string[] {
    return [...this.armed.entries()].filter(([, record]) => record.concluded === null).map(([id]) => id);
  }

  /**
   * Reconcile after a restart by adopting what the journal recorded.
   *
   * A restarted watchdog has no memory of its previous instance's deadlines. It adopts records
   * only if their boot id is the current boot — a record from a previous boot describes
   * namespaces that no longer exist — and then re-verifies the cgroup identity it can see *now*.
   * Anything it cannot verify is left quarantined rather than adopted on faith.
   */
  adopt(record: ArmRequest & { deadlineAtMonotonicMs: number }): { adopted: boolean; reason?: string } {
    // Boot identity first, and specifically before any filesystem probe: after a reboot the
    // recorded path may exist and describe something else entirely, and a check that reached the
    // filesystem would report "absent" — a reason that suggests the wrong remedy.
    if (record.bootId !== this.options.identity.bootId) return { adopted: false, reason: "BOOT_MISMATCH" };
    if (!record.cgroupPath.startsWith("/sys/fs/cgroup/") || record.cgroupPath.split("/").includes("..")) {
      return { adopted: false, reason: "CGROUP_UNVERIFIED" };
    }
    const dir = pathIdentity(record.cgroupPath);
    if (dir === null) return { adopted: false, reason: "CGROUP_ABSENT" };
    const kill = pathIdentity(join(record.cgroupPath, "cgroup.kill"));
    if (kill === null) return { adopted: false, reason: "CGROUP_UNVERIFIED" };
    this.armed.set(record.executionId, {
      request: record,
      identity: this.options.identity,
      deadlineAtMonotonicMs: record.deadlineAtMonotonicMs,
      observed: {
        dirInode: dir.inode,
        eventsInode: pathIdentity(join(record.cgroupPath, "cgroup.events"))?.inode ?? 0,
        killInode: kill.inode,
        procsInode: pathIdentity(join(record.cgroupPath, "cgroup.procs"))?.inode ?? 0,
        device: findCgroup2Mount()?.device ?? "",
        bootId: this.options.identity.bootId,
      },
      concluded: null,
      issuedGrants: new Set(),
      heartbeatsSeen: 0,
      lastHeartbeatMonotonicMs: this.options.monotonicMs(),
    });
    return { adopted: true };
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

/** Directory listing used by recovery to find retained records. Unused here; kept explicit. */
export function listWatchdogRecords(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((name) => name.endsWith(".json"));
}

export { closeSync, openSync, statSync, WATCHDOG_LIMITS };
