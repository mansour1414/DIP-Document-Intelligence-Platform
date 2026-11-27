/**
 * The Supervisor ↔ Watchdog control protocol (R7D.1 §4).
 *
 * ## Why this is a separate protocol
 *
 * The Watchdog is an independent process with its own event loop, because its entire reason to
 * exist is to enforce a deadline when the Supervisor's event loop is wedged, dead, or lying. If
 * it shared a loop, or trusted shared memory, it would fail exactly when it is needed.
 *
 * ## Sequence
 *
 * ```
 *   supervisor                              watchdog
 *   ──────────                              ────────
 *   HELLO  ─────────────────────────────▶
 *          ◀─────────────────────────  HELLO_ACK   (instance, boot, pid/starttime)
 *   ARM_REQ (full termination identity) ▶
 *          ◀─────────────────────────  ARM_ACK     (or ARM_DENIED with a code)
 *   HEARTBEAT ─────────────────────────▶            (bounded liveness, not authorization)
 *   DISARM_REQ (terminal context) ─────▶
 *          ◀─────────────────────────  DISARM_GRANTED (signed) | DISARM_DENIED
 * ```
 *
 * ## What ARM_ACK means and does not mean
 *
 * `ARM_ACK` means the Watchdog independently confirmed the container's identity against the
 * host — boot id, cgroup membership, directory and control-file inodes, init PID and start time
 * — durably recorded it, and registered an armed deadline. It does **not** mean the container is
 * isolated; that is preflight's claim, with its own evidence.
 *
 * ## Consumption
 *
 * Every request carries a sequence number that must strictly increase per execution, and a
 * message id that is remembered until it is used. A replayed `ARM_REQ` must not extend a
 * deadline, and a replayed `DISARM_REQ` must not mint a second grant.
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import {
  assertTerminalContext,
  computeTerminalProof,
  verifyTerminalProof,
  type TerminalContext,
  type TerminalDeniedMessage,
  type TerminalGrantMessage,
  type TerminalRequest,
} from "./terminal-auth";

/** Domain separation for the control channel itself, distinct from the terminal transcripts. */
export const WATCHDOG_DOMAIN = "dip-watchdog-control-v1";

/** Bounds for the control channel. Small on purpose: the messages are fixed-size identities. */
export const WATCHDOG_LIMITS = Object.freeze({
  /** Largest frame either direction may carry. */
  frameBytes: 16 * 1024,
  /** How long a peer may take to answer one request. */
  requestTimeoutMs: 2_000,
  /**
   * How often the supervisor must prove liveness.
   *
   * A heartbeat is *not* an authorization: missing heartbeats do not cancel anything and
   * receiving them does not authorize anything. It exists so the watchdog can distinguish "the
   * supervisor is still working" from "the supervisor is gone" while deciding whether a disarm
   * is plausible or whether the deadline has become the only authority left.
   */
  heartbeatIntervalMs: 1_000,
  /** Consecutive missed heartbeats after which the watchdog treats the supervisor as gone. */
  missedHeartbeatsBeforeOrphan: 3,
  /** Distinct message ids remembered per execution for replay rejection. */
  maxRememberedMessageIds: 64,
});

export type WatchdogPhase = "HELLO" | "ARMED" | "DISARMED" | "TERMINATED" | "DENIED";

/** The identity the watchdog verifies before it will arm. */
export type ArmRequest = {
  kind: "ARM_REQ";
  messageId: string;
  sequence: number;
  executionId: string;
  requestId: string;
  operation: "inspect" | "fill" | "verify";
  supervisorInstance: string;
  bootId: string;
  containerId: string;
  containerName: string;
  imageDigest: string;
  profileId: string;
  /** Container init PID and its kernel start time, as the daemon reported them. */
  initPid: number;
  initStartTimeTicks: number;
  cgroupPath: string;
  deadlineMs: number;
  startedMonotonicMs: number;
};

export type ArmAck = {
  kind: "ARM_ACK";
  messageId: string;
  executionId: string;
  watchdogInstance: string;
  /** Identity the watchdog itself observed, so the supervisor can compare. */
  observedCgroupDirInode: number;
  observedCgroupEventsInode: number;
  observedCgroupKillInode: number;
  observedCgroupProcsInode: number;
  observedCgroupDevice: string;
  observedBootId: string;
  /** The monotonic reading at which the watchdog considers the deadline armed. */
  armedAtMonotonicMs: number;
  /** Proof over the arm context, so the supervisor knows this ack is genuine. */
  proof: string;
};

export type ArmDenied = {
  kind: "ARM_DENIED";
  messageId: string;
  executionId: string;
  watchdogInstance: string;
  code:
    | "OWNERSHIP_UNVERIFIED"
    | "BOOT_MISMATCH"
    | "CGROUP_UNVERIFIED"
    | "PID_UNVERIFIED"
    | "ALREADY_ARMED"
    | "REPLAYED"
    | "INVALID"
    /**
     * The cgroup is not in the dedicated DIP subtree, or its leaf does not derive from the
     * execution id. Nothing outside that subtree belongs to this control plane.
     */
    | "NOT_DIP_OWNED"
    /**
     * The watchdog could not write the arm record durably.
     *
     * A refusal, not a degraded mode: an arm that exists only in memory would be forgotten by a
     * crash, and the supervisor would be told a deadline was armed that no process is enforcing.
     */
    | "DURABILITY_FAILED"
    /**
     * Startup recovery found a record it could not positively resolve.
     *
     * Arming is refused until an operator clears it: with an unresolved execution, the watchdog
     * does not know whether a container it is responsible for is still running.
     */
    | "RECOVERY_INCOMPLETE"
    /**
     * This execution already reached a terminal phase. Re-arming would be a second execution
     * wearing the first one's identity.
     */
    | "ALREADY_CONCLUDED";
};

export type DisarmRequest = {
  kind: "DISARM_REQ";
  messageId: string;
  sequence: number;
  /** The complete terminal context, so the grant can be bound to exact bytes. */
  context: TerminalRequest;
};

export type Heartbeat = {
  kind: "HEARTBEAT";
  messageId: string;
  executionId: string;
  supervisorInstance: string;
  monotonicMs: number;
};

export type HelloAck = {
  kind: "HELLO_ACK";
  watchdogInstance: string;
  bootId: string;
  pid: number;
  /** The watchdog's own process start time, so a restarted watchdog is distinguishable. */
  pidStartTimeTicks: number;
  protocolVersion: number;
};

/**
 * Encode a control frame: `[u32 length][JSON]`.
 *
 * Length-prefixed like every other frame in this system, so a reader can find the boundary
 * without parsing, and a frame larger than the bound is refused before it is read.
 */
export function encodeWatchdogFrame(message: unknown): Buffer {
  const json = Buffer.from(JSON.stringify(message), "utf8");
  if (json.byteLength > WATCHDOG_LIMITS.frameBytes) {
    throw new Error(`watchdog frame of ${json.byteLength} bytes exceeds the ${WATCHDOG_LIMITS.frameBytes} byte bound`);
  }
  const header = Buffer.alloc(4);
  header.writeUInt32BE(json.byteLength, 0);
  return Buffer.concat([header, json]);
}

/** Decode a control frame, rejecting an oversized or truncated one. */
export function decodeWatchdogFrame(buffer: Buffer): unknown {
  if (buffer.byteLength < 4) throw new Error("watchdog frame is truncated");
  const length = buffer.readUInt32BE(0);
  if (length === 0) throw new Error("watchdog frame declares an empty body");
  if (length > WATCHDOG_LIMITS.frameBytes) throw new Error("watchdog frame declares more than the bound");
  if (4 + length > buffer.byteLength) throw new Error("watchdog frame is truncated");
  return JSON.parse(buffer.subarray(4, 4 + length).toString("utf8"));
}

/**
 * The context an `ARM_ACK` proof covers.
 *
 * An ack is not a terminal object, so it is signed over its own transcript rather than reusing
 * the terminal one. Reusing it would mean an ack and a grant could be confused for each other,
 * and the direction field is there precisely to stop that.
 */
function armAckTranscript(ack: ArmAck): Buffer {
  const parts: Buffer[] = [Buffer.from(`${WATCHDOG_DOMAIN}\0arm-ack\0`, "utf8")];
  const push = (value: string | number): void => {
    const bytes = Buffer.from(String(value), "utf8");
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.byteLength, 0);
    parts.push(length, bytes);
  };
  push(ack.messageId);
  push(ack.executionId);
  push(ack.watchdogInstance);
  push(ack.observedCgroupDirInode);
  push(ack.observedCgroupEventsInode);
  push(ack.observedCgroupKillInode);
  push(ack.observedCgroupProcsInode);
  push(ack.observedCgroupDevice);
  push(ack.observedBootId);
  push(ack.armedAtMonotonicMs);
  return Buffer.concat(parts);
}

/** Sign an `ARM_ACK`. */
export function signArmAck(secret: Buffer, ack: Omit<ArmAck, "proof">): string {
  return createHmac("sha256", secret).update(armAckTranscript(ack as ArmAck)).digest("hex");
}

/** Verify an `ARM_ACK` proof in constant time. */
export function verifyArmAck(secret: Buffer, ack: ArmAck): boolean {
  if (!/^[a-f0-9]{64}$/u.test(ack.proof)) return false;
  const { proof, ...rest } = ack;
  const expected = createHmac("sha256", secret).update(armAckTranscript(rest as ArmAck)).digest();
  const presented = Buffer.from(proof, "hex");
  if (expected.byteLength !== presented.byteLength) return false;
  return timingSafeEqual(expected, presented);
}

/**
 * Build the context a disarm grant will be signed over.
 *
 * Kept as a function so the supervisor and the watchdog cannot construct subtly different
 * contexts for the same exchange — which would produce a grant that verifies on one side and
 * not the other, and look like a signature failure.
 */
export function disarmContext(request: TerminalRequest, direction: TerminalContext["direction"]): TerminalContext {
  return { ...assertTerminalContext(request), direction };
}

/** Sign a disarm grant. */
export function signDisarmGrant(secret: Buffer, request: TerminalRequest): TerminalGrantMessage {
  const context = disarmContext(request, "watchdog-to-supervisor");
  return {
    context: request,
    proof: computeTerminalProof(secret, context),
    watchdogInstance: request.watchdogInstance,
  };
}

/** Verify a disarm grant. */
export function verifyDisarmGrant(secret: Buffer, grant: TerminalGrantMessage): boolean {
  const context = disarmContext(grant.context, "watchdog-to-supervisor");
  return verifyTerminalProof(secret, context, grant.proof);
}

/**
 * Replay protection.
 *
 * Remembers consumed message ids per execution with a bounded window. The bound is per execution
 * and small, because an execution has a handful of control messages; an unbounded set would be
 * memory an attacker controls.
 */
export class MessageIdWindow {
  private readonly seen = new Map<string, number>();
  private readonly capacity: number;

  constructor(capacity: number = WATCHDOG_LIMITS.maxRememberedMessageIds) {
    this.capacity = capacity;
  }

  /**
   * Consume an id, returning false if it was already used.
   *
   * Consumption is unconditional on first sight, so a message that fails for another reason
   * still cannot be replayed.
   */
  consume(executionId: string, messageId: string): boolean {
    const key = `${executionId}\0${messageId}`;
    if (this.seen.has(key)) return false;
    this.seen.set(key, Date.now());
    if (this.seen.size > this.capacity) {
      const oldest = this.seen.keys().next();
      if (!oldest.done) this.seen.delete(oldest.value);
    }
    return true;
  }

  get size(): number {
    return this.seen.size;
  }
}

/** Validate an arm request's shape. Every field is checked; several become kill targets. */
export function assertArmRequest(value: unknown): ArmRequest {
  const fail = (detail: string): never => {
    throw new Error(`arm request is invalid: ${detail}`);
  };
  if (typeof value !== "object" || value === null) fail("not an object");
  const record = value as Record<string, unknown>;
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
  if (record.kind !== "ARM_REQ") fail("kind is not ARM_REQ");
  // No component may climb: the path is joined into filesystem reads and a `..` would escape the
  // cgroup it claims to name.
  const rawPath = record.cgroupPath;
  if (typeof rawPath === "string" && rawPath.split("/").includes("..")) fail("cgroupPath may not traverse");
  const executionId = text("executionId", /^[a-f0-9]{32}$/u);
  const containerName = text("containerName", /^dip-exec-[a-f0-9]{32}$/u);
  if (containerName !== `dip-exec-${executionId}`) fail("containerName does not derive from executionId");
  const operation = record.operation;
  if (operation !== "inspect" && operation !== "fill" && operation !== "verify") fail("operation is not supported");
  return {
    kind: "ARM_REQ",
    messageId: text("messageId", /^[a-f0-9]{16,64}$/u),
    sequence: int("sequence", 1),
    executionId,
    requestId: text("requestId", /^[a-f0-9]{16,64}$/u),
    operation: operation as ArmRequest["operation"],
    supervisorInstance: text("supervisorInstance", /^[a-z0-9-]{4,64}$/u),
    bootId: text("bootId", /^[a-z0-9-]{4,64}$/u),
    containerId: text("containerId", /^[a-f0-9]{64}$/u),
    containerName,
    imageDigest: text("imageDigest", /^sha256:[a-f0-9]{64}$/u),
    profileId: text("profileId", /^[a-z0-9-]{4,64}$/u),
    initPid: int("initPid", 2),
    initStartTimeTicks: int("initStartTimeTicks", 0),
    cgroupPath: text("cgroupPath", /^\/sys\/fs\/cgroup\/[A-Za-z0-9._/-]+$/u),
    deadlineMs: int("deadlineMs", 1),
    startedMonotonicMs: int("startedMonotonicMs", 0),
  };
}

export type { TerminalDeniedMessage, TerminalGrantMessage };
