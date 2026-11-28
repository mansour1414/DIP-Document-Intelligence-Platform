/**
 * Authenticated role sockets (R7D.1 §5; Continuation D2).
 *
 * ## The defect this replaces
 *
 * `startSupervisorServer` dispatched a request from a newline-terminated JSON preamble read off an
 * unauthenticated socket, and released admission when the *handler* finished. Both are wrong in ways
 * that are invisible in a passing test:
 *
 * - **The preamble was unauthenticated.** Any process that could `connect()` could claim to be a
 *   worker, name an execution id, and be admitted. The `role` came from which socket was opened,
 *   which is a real control, but nothing proved the peer was the process the deployment intended.
 * - **Admission was released on handler completion.** A handler that returned while a container was
 *   still being terminated released the single-executor slot, so the next caller could be admitted
 *   alongside an execution that had not resolved its lifecycle. Admission must be released on
 *   *positively established resolution*, and on nothing else.
 *
 * ## What this implements
 *
 * ```
 *   client ── HELLO { clientNonce, role, operation, requestId, reservationId } ────────────▶
 *   client ◀── CHALLENGE { serverNonce, teacherNonce, supervisorInstance, bootId } ────────
 *   client ── AUTH { proof over the transcript, direction client-to-server } ──────────────▶
 *   client ◀── AUTH_OK { proof over the same transcript, direction server-to-client } ─────
 *   client ◀── ADMITTED { executionId } ─────────────────────────────────────────────────
 *   client ◀── READY_FOR_BODY { nonce } ─────────────────────────────────────────────────
 *   client ── BEGIN_BODY, then exactly bodyLength raw bytes ────────────────────────────▶
 *   client ◀── result bytes … STREAM_END ────────────────────────────────────────────────
 *   client ◀── TERMINAL_COMMIT { message } ──────────────────────────────────────────────
 * ```
 *
 * Every element of the handshake is there for a reason the earlier version could not give:
 *
 * - **Both sides contribute a nonce**, so neither can force a transcript it has seen before.
 * - **The transcript binds the role, the operation, the request id, the reservation, and both the
 *   control and body digests.** A proof for one request cannot authorize another, and the body the
 *   caller declared is the body the supervisor reconciles against.
 * - **Direction separation.** A `client-to-server` proof cannot be reflected as `server-to-client`.
 * - **Separate credentials per role.** `app` and `worker` do not share a key, so compromising the
 *   web process does not yield the worker's authority.
 * - **Length-prefixed framing with a bounded frame.** A peer announcing a 4 GiB frame is refused on
 *   the header, before anything is allocated.
 * - **Replay rejection.** Each connection's nonce is consumed from a registry, and each request id is
 *   remembered, so a captured handshake cannot be replayed.
 * - **Finite deadlines.** A handshake has 2 s; an idle connection has 5 s; a bounded number of
 *   unauthenticated connections may be open per role.
 *
 * ## Admission
 *
 * One executor globally. Queueing is refused rather than deferred: a caller waiting for a slot holds
 * a connection and a body it has not sent. Release happens only through `releaseResolved`, which the
 * supervisor calls once a lifecycle has reached a terminal, positively established state — never
 * when a handler returns.
 */

import { createServer, type Server, type Socket } from "node:net";
import { chmodSync, existsSync, unlinkSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import {
  ChallengeRegistry,
  IPC_LIMITS,
  IPC_PROTOCOL_VERSION,
  buildTranscript,
  computeProof,
  isOperationAllowed,
  parseDigest,
  parseOperation,
  parseRequestId,
  parseRole,
  verifyProof,
  type IpcOperation,
  type IpcRole,
} from "./ipc-auth";

/** A refusal code the peer may branch on. Closed, and carries no peer-supplied text. */
export type RoleRefusal =
  | "BAD_REQUEST"
  | "OPERATION_NOT_PERMITTED"
  | "ROLE_NOT_PERMITTED"
  | "TOO_MANY_CONNECTIONS"
  | "RESERVATION_REQUIRED"
  | "RESERVATION_INVALID"
  | "BUSY"
  | "AUTH_FAILED"
  | "INSTANCE_MISMATCH"
  | "REPLAYED"
  | "FRAMING"
  | "TIMEOUT"
  | "REJECTED"
  | "QUARANTINED";

/**
 * One issued reservation.
 *
 * ## Why every field is here
 *
 * A reservation is an *authorization to ask* — it does not admit anything by itself and cannot
 * occupy the executor slot. That limited authority is still authority, so it is bounded on every
 * axis that could otherwise be turned into a resource:
 *
 * - `role` — a worker reservation is not an app reservation, so a captured one cannot cross roles.
 * - `operation` — the specific operation in the sequence this reservation authorizes. A fill
 *   reservation does not authorize a verify.
 * - `callerIdentity` — the authenticated `clientInstance` that asked. Presenting the id from a
 *   different connection is a refusal, so a leaked id is not a transferable capability.
 * - `expiresAt` — the total lifetime. Bounds the window in which a captured id is useful at all.
 * - `idleExpiresAt` — a shorter lifetime that is *not* extended by use. Bounds the queue of
 *   reservations a caller can accumulate and then abandon.
 * - `sequence` — the position in the operation chain, so issuance is ordered and auditable.
 */
export type Reservation = {
  role: IpcRole;
  operation: IpcOperation;
  callerIdentity: string;
  expiresAt: number;
  idleExpiresAt: number;
  sequence: number;
};

/** What admission knows about the one executor it may admit. */
export type AdmissionState = {
  activeExecution: string | null;
  activeSince: number | null;
  connections: Map<IpcRole, number>;
  reservations: Map<string, Reservation>;
  /** Monotonic issuance counter. Never reused, so a sequence number identifies one issuance. */
  reservationSequence: number;
  /**
   * How far each authenticated caller has advanced through the worker sequence.
   *
   * Keyed by `clientInstance`, which the transcript proved. Bounded implicitly: only identities that
   * have actually completed a handshake appear, and entries are reset when a reservation is issued
   * for `inspect` (the start of a new pipeline).
   */
  callerSequence: Map<string, { level: number; updatedAt: number }>;
  /** Largest number of caller sequence entries the map may hold. */
  callerSequenceCap: number;
  /** Age after which a caller sequence entry expires and is swept. */
  callerSequenceTtlMs: number;
  /** Global ceiling on live reservations across all callers. */
  maxReservations: number;
  /** Execution ids whose lifecycle has not positively resolved. Nothing is admitted while non-empty. */
  unresolved: Set<string>;
};

export function newAdmissionState(): AdmissionState {
  return {
    activeExecution: null,
    activeSince: null,
    connections: new Map(),
    reservations: new Map(),
    reservationSequence: 0,
    callerSequence: new Map(),
    callerSequenceCap: DEFAULT_CALLER_SEQUENCE_CAP,
    callerSequenceTtlMs: DEFAULT_CALLER_SEQUENCE_TTL_MS,
    maxReservations: DEFAULT_MAX_RESERVATIONS,
    unresolved: new Set(),
  };
}

/**
 * The authorized operation sequence a worker may walk.
 *
 * ## Why a sequence and not a set
 *
 * Inspect → Fill → Verify is a pipeline, not three interchangeable powers. Fill without a preceding
 * inspect means filling fields the worker never enumerated; verify without a fill means attesting to
 * a document that was never produced. Encoding the order server-side means a worker cannot skip a
 * step by requesting the later operation first, even with a valid credential.
 *
 * A worker may repeat an operation (inspect twice is meaningful, as is fill then fill) but may not
 * *reverse* one: after a fill, an inspect would be inspecting a different document than the one the
 * pipeline is committed to.
 */
export const WORKER_OPERATION_SEQUENCE = Object.freeze(["inspect", "fill", "verify"] as const);

/** How far a worker's operations may advance between reservations. */
export type SequencePosition = { last: number };

/** Default ceiling on the number of distinct callers tracked in the caller sequence map. */
export const DEFAULT_CALLER_SEQUENCE_CAP = 1024;
/** Default age after which a caller sequence entry expires and is swept. */
export const DEFAULT_CALLER_SEQUENCE_TTL_MS = 5 * 60 * 1000;
/** Default global ceiling on live reservations across all callers. */
export const DEFAULT_MAX_RESERVATIONS = 256;

/**
 * Why a reservation was refused.
 *
 * Separate from `RoleRefusal` because these are *issuance* outcomes, reported to the caller before
 * admission, not admission refusals for a request that was otherwise well-formed.
 */
export type ReservationRefusal =
  /** The worker asked for an operation before the one its sequence has reached. */
  | "OUT_OF_SEQUENCE"
  /** The worker already holds as many reservations as it may. */
  | "RESERVATION_LIMIT"
  /** The supervisor is at its global reservation ceiling; no slot can be promised right now. */
  | "RESERVATION_GLOBAL_LIMIT"
  /** The supervisor is at capacity; a reservation would promise a slot it cannot deliver. */
  | "BUSY";

export type ReservationGrant =
  | { ok: true; reservationId: string; expiresAt: number; idleExpiresAt: number; operation: IpcOperation }
  | { ok: false; code: ReservationRefusal };

/**
 * Issue one worker reservation.
 *
 * ## What this does *not* do
 *
 * It does not admit anything. A reservation authorizes a future admission request; the executor
 * slot is still decided by `admit`, which enforces one global active execution and holds the slot
 * while any lifecycle is unresolved. A worker holding three reservations cannot run three
 * executions, and this function does not create a second slot.
 *
 * ## The bounds, and what each prevents
 *
 * - **Count** (`maxPerCaller`) bounds what one caller can accumulate, so a caller that requests in a
 *   loop without connecting cannot make the supervisor hold unbounded state.
 * - **Total TTL** (`ttlMs`) bounds the window a captured id is useful in.
 * - **Idle TTL** (`idleMs`, shorter) bounds an abandoned reservation. It is *not* extended by use,
 *   so reconnecting does not let a caller keep a reservation alive forever.
 * - **Caller identity** makes an id non-transferable: another connection presenting it is refused.
 * - **Single use** is enforced in `admit`, which deletes on acceptance.
 */
export function reserveForWorker(
  state: AdmissionState,
  input: {
    callerIdentity: string;
    operation: IpcOperation;
    sequence: SequencePosition;
    now: number;
    ttlMs: number;
    idleMs: number;
    maxPerCaller: number;
    maxReservations: number;
  },
): ReservationGrant {
  // Sweep first, so an expired reservation does not consume the caller's allowance. Sweeping on
  // every issuance is what keeps the map bounded without a timer: nothing else has to run for this
  // state to stay finite.
  for (const [id, record] of state.reservations) {
    if (record.expiresAt <= input.now || record.idleExpiresAt <= input.now) state.reservations.delete(id);
  }

  const target = WORKER_OPERATION_SEQUENCE.indexOf(input.operation);
  if (target < 0) return { ok: false, code: "OUT_OF_SEQUENCE" };
  // A worker may repeat the operation the sequence has reached, or advance one step. It may not
  // jump ahead: requesting `verify` before any `fill` is a pipeline that skipped the work.
  if (target > input.sequence.last + 1) return { ok: false, code: "OUT_OF_SEQUENCE" };
  if (target < input.sequence.last) return { ok: false, code: "OUT_OF_SEQUENCE" };

  // A reservation is a promise that a slot can be offered. Issuing one while the executor is
  // occupied would let a worker queue up authority it cannot exercise, and would make "BUSY" arrive
  // at admission time, after the caller had already prepared a document.
  if (state.activeExecution !== null || state.unresolved.size > 0) return { ok: false, code: "BUSY" };

  // Global ceiling: a flood of distinct callers must not exhaust the reservation map. Swept,
  // expired entries no longer count, so the bound is on live reservations only.
  if (state.reservations.size >= state.maxReservations) {
    return { ok: false, code: "RESERVATION_GLOBAL_LIMIT" };
  }

  let held = 0;
  for (const record of state.reservations.values()) {
    if (record.callerIdentity === input.callerIdentity) held += 1;
  }
  if (held >= input.maxPerCaller) return { ok: false, code: "RESERVATION_LIMIT" };

  const reservationId = randomBytes(24).toString("hex");
  const expiresAt = input.now + input.ttlMs;
  // Shorter than the total, and independent of it: an idle reservation dies sooner, and using one
  // does not extend either clock.
  const idleExpiresAt = input.now + Math.min(input.idleMs, input.ttlMs);
  state.reservationSequence += 1;
  state.reservations.set(reservationId, {
    role: "worker",
    operation: input.operation,
    callerIdentity: input.callerIdentity,
    expiresAt,
    idleExpiresAt,
    sequence: state.reservationSequence,
  });
  return { ok: true, reservationId, expiresAt, idleExpiresAt, operation: input.operation };
}

/**
 * The sequence position for a caller.
 *
 * Absent means "-1": nothing has been issued yet, so the caller may ask for `inspect` (position 0)
 * but not `fill`. A caller that has never inspected has no pipeline to continue.
 */
export function sequenceFor(
  state: AdmissionState,
  callerIdentity: string,
  now: () => number = () => Date.now(),
): SequencePosition {
  sweepCallerSequence(state, now);
  return { last: state.callerSequence.get(callerIdentity)?.level ?? -1 };
}

/**
 * Record that a reservation was issued for an operation.
 *
 * Only advances. Issuing `inspect` again resets to 0, because that is what starting a new pipeline
 * looks like — a worker that finished one document and begins another. Anything else moves forward
 * by one, so the index always names the step actually reached.
 *
 * The map is globally bounded: adding a new caller at cap evicts the oldest entry first. Entries
 * expire by TTL and are swept on every read and write.
 */
export function advanceSequence(
  state: AdmissionState,
  callerIdentity: string,
  operation: IpcOperation,
  now: () => number = () => Date.now(),
): void {
  sweepCallerSequence(state, now);
  const target = WORKER_OPERATION_SEQUENCE.indexOf(operation);
  const current = state.callerSequence.get(callerIdentity)?.level ?? -1;
  const level = operation === "inspect" ? 0 : Math.max(current, target);
  if (!state.callerSequence.has(callerIdentity) && state.callerSequence.size >= state.callerSequenceCap) {
    let oldest: string | null = null;
    let oldestTime = Infinity;
    for (const [identity, entry] of state.callerSequence) {
      if (entry.updatedAt < oldestTime) {
        oldestTime = entry.updatedAt;
        oldest = identity;
      }
    }
    if (oldest !== null) state.callerSequence.delete(oldest);
  }
  state.callerSequence.set(callerIdentity, { level, updatedAt: now() });
}

/** Remove expired caller-sequence entries so the map stays bounded without explicit removals. */
function sweepCallerSequence(state: AdmissionState, now: () => number): void {
  const deadline = now() - state.callerSequenceTtlMs;
  for (const [identity, entry] of state.callerSequence) {
    if (entry.updatedAt <= deadline) state.callerSequence.delete(identity);
  }
}

/**
 * A general reservation for a non-worker role.
 *
 * Kept separate rather than offered as a parameter, because "which role may be reserved" is a policy
 * question and a boolean argument invites the wrong answer. `app` cannot fill, so it needs no
 * reservation at all; this exists for tests and for a future role that does.
 */
export function reserve(state: AdmissionState, role: IpcRole, now: number, ttlMs: number): { reservationId: string; expiresAt: number } {
  const reservationId = randomBytes(24).toString("hex");
  const expiresAt = now + ttlMs;
  state.reservationSequence += 1;
  state.reservations.set(reservationId, {
    role,
    operation: "inspect",
    callerIdentity: "",
    expiresAt,
    idleExpiresAt: expiresAt,
    sequence: state.reservationSequence,
  });
  return { reservationId, expiresAt };
}

export type AdmissionRequest = {
  role: unknown;
  operation: unknown;
  requestId: unknown;
  reservationId?: unknown;
  executionId?: unknown;
  /**
   * The authenticated `clientInstance`, from the HELLO that the transcript bound.
   *
   * Required for a worker, because a reservation is issued to one caller and accepting it from
   * another would make the id a transferable capability. Optional for `app`, which presents none.
   */
  callerIdentity?: unknown;
};

export type AdmissionDecision = { ok: true; executionId: string } | { ok: false; code: RoleRefusal };

/**
 * Decide whether to admit a request.
 *
 * Every input is validated before any state is consulted: a malformed request must not be able to
 * occupy the single executor slot. The reservation is single-use — it is deleted on acceptance, so
 * a captured one cannot be presented twice.
 */
export function admit(
  state: AdmissionState,
  request: AdmissionRequest,
  now: number,
  options: { reservationTtlMs: number; maxConnections: number },
): AdmissionDecision {
  let role: IpcRole;
  let operation: IpcOperation;
  try {
    role = parseRole(request.role);
    // Shape-checked only: which operations a role may invoke is the server's decision, made after
    // authentication, so that a policy refusal is never reported as a handshake failure.
    //
    // Retained rather than discarded, because the reservation names one operation and the binding
    // has to be compared, not assumed.
    operation = parseOperation(request.operation);
    // Validated for shape, and then deliberately not used as the execution id: an execution id is
    // minted here, never taken from the wire, so a peer cannot choose the id it is recorded under.
    parseRequestId(request.requestId);
  } catch {
    return { ok: false, code: "BAD_REQUEST" };
  }

  // Authorization is enforced by the server *after* it has authenticated the caller, so that a
  // policy refusal is never mistaken for a handshake failure. `admit` therefore does not repeat it;
  // a direct caller of this function is trusted code, and every socket path goes through the check.
  const connectionCount = state.connections.get(role) ?? 0;
  if (connectionCount >= options.maxConnections) return { ok: false, code: "TOO_MANY_CONNECTIONS" };

  const callerIdentity = typeof request.callerIdentity === "string" ? request.callerIdentity : "";

  // ## Capacity is decided before the reservation is spent
  //
  // The ordering is deliberate, and it was wrong the other way round. Consuming the reservation
  // first meant a caller refused for `BUSY` had burned its single-use authorization on a request
  // that never had a chance: a worker that simply retried was then refused forever with
  // `RESERVATION_REQUIRED`, and the real reason was never reported. Nothing is admitted either way,
  // so refusing earlier is also the cheaper answer.
  //
  // This is stricter than "no active execution". An execution that finished its handler but whose
  // container has not been positively removed is still using the single executor slot, and admitting
  // a second one alongside it is two containers under one profile.
  if (state.unresolved.size > 0) return { ok: false, code: "BUSY" };
  if (state.activeExecution !== null) return { ok: false, code: "BUSY" };

  // A worker must present a live reservation for the worker role. The reservation is what makes
  // "who may fill" a server-side fact rather than a claim on the wire.
  if (role === "worker") {
    const reservationId = typeof request.reservationId === "string" ? request.reservationId : "";
    const reservation = state.reservations.get(reservationId);
    if (reservation === undefined) return { ok: false, code: "RESERVATION_REQUIRED" };
    // ## Every binding is checked, in the order that costs least
    //
    // Expiry first: an expired record is deleted whatever else is wrong with the request, so a
    // caller cannot probe the other predicates with a stale id.
    if (reservation.expiresAt <= now || reservation.idleExpiresAt <= now) {
      state.reservations.delete(reservationId);
      return { ok: false, code: "RESERVATION_INVALID" };
    }
    if (reservation.role !== role) {
      state.reservations.delete(reservationId);
      return { ok: false, code: "RESERVATION_INVALID" };
    }
    // The operation must be the one this reservation names. Checking only the role would let a
    // reservation issued for `inspect` authorize a `fill`, which is the whole pipeline bypass the
    // sequence exists to prevent.
    if (reservation.operation !== operation) {
      state.reservations.delete(reservationId);
      return { ok: false, code: "RESERVATION_INVALID" };
    }
    // Revalidate sequence authority at admission: the sequence may have advanced since the
    // reservation was issued (another execution for this caller resolved), which would supersede
    // this reservation. An expired or superseded sequence must not authorize an execution.
    const target = WORKER_OPERATION_SEQUENCE.indexOf(reservation.operation);
    const position = sequenceFor(state, callerIdentity, () => now);
    if (target < position.last) {
      state.reservations.delete(reservationId);
      return { ok: false, code: "RESERVATION_INVALID" };
    }
    // The reservation belongs to the caller it was issued to. Without this, an id observed on the
    // wire is a capability any authenticated worker could present.
    if (reservation.callerIdentity === "" || reservation.callerIdentity !== callerIdentity) {
      state.reservations.delete(reservationId);
      return { ok: false, code: "RESERVATION_INVALID" };
    }
    // Single use, and consumed only now that every other check has passed: a refusal for a binding
    // failure is a probe, and a refusal for capacity is not the caller's mistake.
    state.reservations.delete(reservationId);
  }

  const executionId = typeof request.executionId === "string" && /^[a-f0-9]{32}$/u.test(request.executionId)
    ? request.executionId
    : randomBytes(16).toString("hex");

  state.activeExecution = executionId;
  state.activeSince = now;
  return { ok: true, executionId };
}

/**
 * Release the executor slot.
 *
 * ## Only on positively established resolution
 *
 * Called by the supervisor when a lifecycle reaches a terminal state it can *evidence*: committed
 * after confirmed removal, or refused after the container was shown gone. It is deliberately not
 * called from a `finally` block. A handler that failed in a way that left a container running must
 * leave the slot held, so the next caller is refused rather than admitted next to an orphan.
 */
export function releaseResolved(state: AdmissionState, executionId: string, resolved: boolean): void {
  if (state.activeExecution !== executionId) return;
  if (!resolved) {
    // Held, and recorded as an unresolved debt so the reason survives the connection closing.
    state.unresolved.add(executionId);
    return;
  }
  state.activeExecution = null;
  state.activeSince = null;
  state.unresolved.delete(executionId);
}

/** Frames on the authenticated channel. Every one carries its own length prefix. */
export type ClientHello = {
  kind: "HELLO";
  protocolVersion: number;
  clientNonce: string;
  clientInstance: string;
  role: IpcRole;
  operation: IpcOperation;
  requestId: string;
  reservationId: string | null;
  controlLength: number;
  controlSha256: string;
  bodyLength: number;
  bodySha256: string;
  executionId?: string;
};

export type ServerChallenge = {
  kind: "CHALLENGE";
  protocolVersion: number;
  serverNonce: string;
  /** Echoed so the client can confirm the server saw *its* hello, not a replayed one. */
  clientNonce: string;
  supervisorInstance: string;
  bootId: string;
};

export type ClientAuth = { kind: "AUTH"; proof: string };
/**
 * Ask for a worker reservation, after authenticating.
 *
 * ## Why a distinct verb rather than a field on HELLO
 *
 * A reservation is authority granted by the supervisor, and the HELLO is the caller's claim. Putting
 * the request in the HELLO would mean the handshake both asks for and consumes authority in one
 * round trip, with no point at which the supervisor can decide independently. As a post-auth verb it
 * is a answered request with a refusal vocabulary of its own.
 *
 * It travels on a connection that has completed authentication, so the identity the reservation is
 * bound to is the one the transcript already proved.
 */
export type ClientReserve = { kind: "RESERVE"; operation: IpcOperation };
export type ServerReserved = {
  kind: "RESERVED";
  reservationId: string;
  operation: IpcOperation;
  /** Total lifetime. The reservation dies at this instant regardless of use. */
  expiresAt: number;
  /** Idle lifetime, always <= `expiresAt`. Using the reservation does not extend either. */
  idleExpiresAt: number;
};
export type ServerReservationRefused = { kind: "RESERVATION_REFUSED"; code: ReservationRefusal };
export type ServerAuthOk = { kind: "AUTH_OK"; proof: string; supervisorInstance: string; bootId: string };
export type ServerAdmitted = { kind: "ADMITTED"; executionId: string };
export type ServerReady = { kind: "READY_FOR_BODY"; nonce: string };
export type ServerRefusal = { kind: "REFUSED"; code: RoleRefusal };
export type ServerStreamEnd = { kind: "STREAM_END"; bytes: number; digest: string };
export type ServerTerminalCommit = { kind: "TERMINAL_COMMIT"; message: unknown };

/** Encode a control frame: `[u32 length][JSON]`. Bounded before it is written. */
export function encodeControlFrame(message: unknown): Buffer {
  const json = Buffer.from(JSON.stringify(message), "utf8");
  if (json.byteLength > IPC_LIMITS.controlFrameBytes) {
    throw new Error(`control frame of ${json.byteLength} bytes exceeds the ${IPC_LIMITS.controlFrameBytes} byte bound`);
  }
  const header = Buffer.alloc(4);
  header.writeUInt32BE(json.byteLength, 0);
  return Buffer.concat([header, json]);
}

/** Decode one control frame, refusing an oversized or truncated one. */
export function decodeControlFrame(buffer: Buffer): unknown {
  if (buffer.byteLength < 4) throw new Error("control frame is truncated");
  const length = buffer.readUInt32BE(0);
  if (length === 0) throw new Error("control frame declares an empty body");
  if (length > IPC_LIMITS.controlFrameBytes) throw new Error("control frame declares more than the bound");
  if (4 + length > buffer.byteLength) throw new Error("control frame is truncated");
  return JSON.parse(buffer.subarray(4, 4 + length).toString("utf8"));
}

/** Buffer control frames until a whole one has arrived. */
class FrameBuffer {
  private pending: Buffer = Buffer.alloc(0);

  append(chunk: Buffer): void {
    this.pending = Buffer.concat([this.pending, chunk]);
    if (this.pending.byteLength > IPC_LIMITS.controlFrameBytes + 4) {
      throw new Error("the control stream exceeded the frame bound");
    }
  }

  /** The next complete frame, or `null` if one has not arrived. */
  next(): { message: unknown; leftover: Buffer } | null {
    if (this.pending.byteLength < 4) return null;
    const declared = this.pending.readUInt32BE(0);
    if (declared === 0 || declared > IPC_LIMITS.controlFrameBytes) {
      throw new Error("the control frame declared an unacceptable length");
    }
    if (this.pending.byteLength < 4 + declared) return null;
    const frame = this.pending.subarray(0, 4 + declared);
    const leftover = this.pending.subarray(4 + declared);
    return { message: decodeControlFrame(frame), leftover };
  }

  clear(leftover: Buffer): void {
    this.pending = leftover;
  }

  get buffered(): number {
    return this.pending.byteLength;
  }
}

/** What the server needs to know about itself and its peers. */
export type RoleServerOptions = {
  /** One path per role. The role is the socket inode, never a field the peer chooses. */
  socketPaths: Record<IpcRole, string>;
  /** One credential per role, so compromising one role does not yield another's authority. */
  secrets: Record<IpcRole, Buffer>;
  supervisorInstance: string;
  bootId: string;
  /**
   * Handles one admitted execution.
   *
   * The handler owns the lifecycle from admission to resolution. It must call `release` exactly
   * once, and only when it can evidence a terminal resolution.
   */
  handle: (session: AdmittedSession) => Promise<void>;
  now?: () => number;
  reservationTtlMs?: number;
  /**
   * Idle lifetime for a reservation.
   *
   * Shorter than the total, and deliberately not extended by use: it bounds an abandoned
   * reservation, which is the state a caller leaves behind when it asks and then gives up.
   */
  reservationIdleMs?: number;
  /** How many live reservations one authenticated caller may hold. */
  maxReservationsPerCaller?: number;
  /** Global ceiling on live reservations across all callers, so a flood cannot exhaust the map. */
  maxReservations?: number;
  /** Largest number of caller-sequence entries the admission state may track. */
  maxCallerSequenceEntries?: number;
  /** Age after which a caller-sequence entry expires and is swept. */
  callerSequenceTtlMs?: number;
  maxConnectionsPerRole?: number;
  log?: (line: string) => void;
};

/** One admitted execution, as the handler sees it. */
export type AdmittedSession = {
  role: IpcRole;
  operation: IpcOperation;
  /** The caller's request id, bound into the authenticated HELLO transcript. The terminal commit
   * echoes it so the caller can confirm the commit is for the request it actually sent. */
  requestId: string;
  executionId: string;
  socket: Socket;
  /**
   * Write one control frame, resolving when the socket has taken it.
   *
   * ## Why this is a promise now
   *
   * It returned `void`, so a caller streaming a document had no way to know whether the peer was
   * keeping up. `socket.write()` returns `false` once the kernel buffer is full, and the previous
   * implementation discarded that boolean; a fast producer then queued the entire result in
   * userspace while the event loop rotated, which is the same unbounded growth the streaming
   * contract exists to prevent, one layer down.
   *
   * The promise resolves on `drain` when the write buffer is full, and rejects if the socket is
   * closed or errors first. A caller that ignores the rejection cannot silently continue: the
   * stream is already torn down.
   */
  send: (message: unknown) => Promise<void>;
  /**
   * Resolve admission. Called exactly once by the handler, with evidence.
   *
   * `committed` releases the slot and advances the caller's sequence. `refused` releases capacity
   * (nothing was created) without advancing the sequence. `unresolved` retains the slot because a
   * container may exist that this process cannot prove is gone.
   */
  release: (outcome: "committed" | "refused" | "unresolved") => void;
  /** Control messages after the handshake, in order. */
  control: AsyncIterable<Record<string, unknown>>;
  /**
   * The body, as a stream.
   *
   * The reader never buffers the whole document: each chunk is handed to the consumer as it
   * arrives, and the consumer's backpressure stops the socket from being read. This is the property
   * that lets a 512 MiB document through a control plane with a 384 MiB profile.
   */
  body: AsyncIterable<Buffer>;
  /** The declared body length and digest, which the supervisor reconciles. */
  declared: { bodyBytes: number; bodySha256: string };
  /**
   * The nonce issued with `READY_FOR_BODY`.
   *
   * The terminal commit must echo a value the caller can correlate with the invitation it received,
   * so that a commit minted for a different execution cannot be replayed into this one. It is issued
   * by the server, at the gate, and never chosen by the peer.
   */
  readyNonce: () => string;
  /**
   * The authenticated control block the caller declared in its HELLO.
   *
   * ## Why it is opaque here
   *
   * The socket layer authenticates these fields — they are bound into the transcript — but it does
   * not interpret them. Whether an image spec is digest-pinned, or a cgroup parent is a dedicated
   * slice, are questions for the execution plane. Keeping them as opaque strings means the
   * transport cannot acquire an opinion about container policy, and the plane cannot weaken the
   * binding by re-reading them from somewhere unauthenticated.
   */
  controlBlock: () => Record<string, unknown>;
};

export type RoleServer = {
  servers: Server[];
  state: AdmissionState;
  stop: () => Promise<void>;
};

/** A single-use nonce, hex. */
export function newNonce(): string {
  return randomBytes(32).toString("hex");
}

/**
 * Start the role sockets.
 *
 * Sockets are created in a directory whose mode the caller controls and chmod'd to 0600 before they
 * listen. The cross-role separation is a filesystem property — separate owners or groups — and this
 * code cannot prove it; the deployment's socket units do, and that gap is documented rather than
 * papered over.
 */
export async function startRoleSockets(options: RoleServerOptions): Promise<RoleServer> {
  const state = newAdmissionState();
  const now = options.now ?? (() => Date.now());
  state.callerSequenceCap = options.maxCallerSequenceEntries ?? DEFAULT_CALLER_SEQUENCE_CAP;
  state.callerSequenceTtlMs = options.callerSequenceTtlMs ?? DEFAULT_CALLER_SEQUENCE_TTL_MS;
  state.maxReservations = options.maxReservations ?? DEFAULT_MAX_RESERVATIONS;
  const challenges = new ChallengeRegistry({ now });
  const servers: Server[] = [];
  /**
   * Every accepted connection.
   *
   * Tracked so `stop()` can end them. `net.Server.close()` stops accepting but leaves established
   * connections open, so a server with one peer that has not sent FIN never finishes closing — the
   * shutdown would hang behind a peer that already went away.
   */
  const live = new Set<Socket>();

  for (const role of Object.keys(options.socketPaths) as IpcRole[]) {
    const socketPath = options.socketPaths[role];
    if (existsSync(socketPath)) unlinkSync(socketPath);

    const server = createServer((socket) => {
      live.add(socket);
      socket.once("close", () => live.delete(socket));
      const frames = new FrameBuffer();
      let hello: ClientHello | null = null;
      /** The nonce this connection issued in its CHALLENGE. Exactly one, per connection. */
      let serverNonce: string | null = null;
      let authenticated = false;
      let attempts = 0;
      let closed = false;
      // The authenticated caller identity and operation, captured at admission (when `hello` is
      // provably non-null) so `session.release` can advance the caller's sequence on positive
      // resolution without re-reading the possibly-null hello.
      let admitted: {
        executionId: string;
        released: boolean;
        callerIdentity: string;
        operation: IpcOperation;
        role: IpcRole;
      } | null = null;
      /** The nonce sent with READY_FOR_BODY. Empty until the gate opens. */
      let readyNonce = "";
      /** The authenticated control fields, as declared in the HELLO. */
      let controlBlock: Record<string, unknown> = {};
      /** The exact bytes whose digest the transcript bound. */
      let controlBlockBytes: Buffer = Buffer.alloc(0);

      // Session queues. The consumer is the handler; the producer is the socket.
      const controlQueue: Record<string, unknown>[] = [];
      const bodyQueue: Buffer[] = [];
      let bodyStarted = false;
      let bodyEnded = false;
      let notifyControl: (() => void) | null = null;
      let notifyBody: (() => void) | null = null;

      const handshakeTimer = setTimeout(() => {
        if (!authenticated) socket.destroy();
      }, IPC_LIMITS.authTimeoutMs);
      handshakeTimer.unref();

      /**
       * Write one frame, honouring the socket's own backpressure.
       *
       * `socket.write()` is synchronous only in the sense that it hands bytes to the kernel. Once
       * the kernel buffer is full it returns `false` and buffers the remainder *in Node*, so a
       * loop that ignores the return value converts a bounded pipe into an unbounded queue. The
       * awaiting here is what makes `STREAM_CHUNK` pacing real: the next chunk is not read from the
       * executor until this one has been accepted.
       *
       * Rejection, not silence, on a dead peer. A caller must not interpret "the socket went away"
       * as "the frame was delivered", and the commit path in particular depends on knowing that
       * the terminal message actually left this process.
       */
      const send = (message: unknown): Promise<void> => {
        // ## A write to a closed connection is a no-op, not a rejection
        //
        // The handler's own teardown calls `release`, which ends the socket, and then finishes its
        // `finally` block. A message composed after that point was never going anywhere, and
        // reporting it as a failure would surface as an unhandled rejection in every normal
        // shutdown. Rejection is reserved for the case that matters: a write *attempted on a live
        // connection* whose peer then disappeared before the frame was accepted.
        if (closed) return Promise.resolve();
        let frame: Buffer;
        try {
          frame = encodeControlFrame(message);
        } catch (error) {
          return Promise.reject(error instanceof Error ? error : new Error("the frame could not be encoded"));
        }
        // A peer that accepts bytes but never drains them must not be able to make this process
        // grow a queue. The ceiling is per connection and shared by every frame type, because the
        // sum is what is charged to memory, not any one message.
        if (socket.writableLength > IPC_LIMITS.maxSendBufferBytes) {
          closed = true;
          socket.destroy();
          return Promise.reject(new Error("the peer is not draining the connection"));
        }
        return new Promise<void>((resolve, reject) => {
          const onDrain = (): void => { cleanup(); resolve(); };
          const onClose = (): void => { cleanup(); reject(new Error("the connection closed before the frame was written")); };
          const cleanup = (): void => {
            socket.off("drain", onDrain);
            socket.off("close", onClose);
            socket.off("error", onClose);
          };
          socket.once("drain", onDrain);
          socket.once("close", onClose);
          socket.once("error", onClose);
          try {
            // `true` means the kernel buffer is below its high-water mark: it is safe to write
            // again immediately, and no event will follow. `false` means "buffered", and `drain`
            // is the only correct way to learn when to pace again — waiting on anything else,
            // including `writableLength`, can hang, because `drain` does not fire when the buffer
            // empties on its own after a write that was already accepted.
            const accepted = socket.write(frame);
            if (accepted) { cleanup(); resolve(); }
          } catch (error) {
            cleanup();
            closed = true;
            socket.destroy();
            reject(error instanceof Error ? error : new Error("the frame could not be written"));
          }
        });
      };

      /**
       * Send a handshake frame without awaiting delivery.
       *
       * The handshake is a synchronous state machine: each frame is followed immediately by a state
       * change that depends on the frame having been *composed*, not on the peer having read it.
       * Awaiting here would make the frame parser re-entrant for no benefit, and the reply's
       * ordering is already guaranteed because `socket.write` preserves it.
       *
       * The rejection is still handled — `send` rejects on a dead peer, and an unhandled rejection
       * would take down the process over a connection that has already gone.
       */
      const post = (message: unknown): void => {
        void send(message).catch(() => {
          closed = true;
          socket.destroy();
          notifyControl?.();
          notifyBody?.();
        });
      };

      const refuse = (code: RoleRefusal): void => {
        // The refusal frame is best-effort by definition: the connection is ended immediately
        // afterwards, so a peer that has already gone cannot be told anything. The rejection is
        // swallowed rather than left unhandled, which would crash the process on a dead socket.
        void send({ kind: "REFUSED", code } satisfies ServerRefusal).catch(() => {});
        // Ended rather than destroyed: the peer is owed the refusal frame before the connection goes.
        closed = true;
        socket.end();
        notifyControl?.();
        notifyBody?.();
      };

      /**
       * Hand bytes to the session stream, or to the frame reader.
       *
       * ## Why the body is a counted region and not an unbounded stream
       *
       * Body bytes carry no framing of their own — that is what lets a document through without
       * base64 inflation or a length prefix per chunk. But a protocol where "everything after
       * BEGIN_BODY is body" cannot tell a body byte from a control frame, so the region is bounded
       * by the length the peer declared in its HELLO: exactly that many raw bytes follow, and the
       * stream returns to framed control afterwards. A peer that sends more is refused, and a peer
       * that sends less is caught by reconciliation, which compares the received digest.
       */
      let bodyRemaining = 0;
      const deliverSessionData = (chunk: Buffer): void => {
        if (chunk.byteLength === 0) return;

        if (bodyStarted && !bodyEnded && bodyRemaining > 0) {
          const take = Math.min(bodyRemaining, chunk.byteLength);
          bodyQueue.push(chunk.subarray(0, take));
          notifyBody?.();
          bodyRemaining -= take;
          if (bodyRemaining === 0) bodyEnded = true;
          if (take === chunk.byteLength) return;
          // The remainder belongs to the control stream again.
          chunk = chunk.subarray(take);
        }

        try {
          frames.append(chunk);
        } catch {
          refuse("FRAMING");
          return;
        }
        for (;;) {
          let step: ReturnType<FrameBuffer["next"]>;
          try {
            step = frames.next();
          } catch {
            refuse("FRAMING");
            return;
          }
          if (step === null) return;
          frames.clear(step.leftover);
          const message = step.message;
          if (!isRecord(message)) {
            refuse("FRAMING");
            return;
          }
          if (message.kind === "BEGIN_BODY") {
            if (bodyStarted) {
              // A second BEGIN_BODY would redefine the region the digest is reconciled against.
              refuse("FRAMING");
              return;
            }
            bodyStarted = true;
            if (hello === null) {
              refuse("FRAMING");
              return;
            }
            bodyRemaining = hello.bodyLength;
            bodyEnded = bodyRemaining === 0;
            if (bodyEnded) notifyBody?.();
            if (step.leftover.byteLength > 0) {
              deliverSessionData(step.leftover);
              return;
            }
            continue;
          }
          controlQueue.push(message);
          notifyControl?.();
        }
      };

      const onData = (chunk: Buffer): void => {
        if (closed) return;
        if (authenticated) {
          deliverSessionData(chunk);
          return;
        }

        try {
          frames.append(chunk);
        } catch {
          refuse("FRAMING");
          return;
        }
        for (;;) {
          let step: ReturnType<FrameBuffer["next"]>;
          try {
            step = frames.next();
          } catch {
            refuse("FRAMING");
            return;
          }
          if (step === null) return;
          frames.clear(step.leftover);
          const message = step.message;
          if (!isRecord(message)) {
            refuse("BAD_REQUEST");
            return;
          }

          if (message.kind === "HELLO") {
            // One HELLO per connection. A second would replace the nonce the first challenge was
            // bound to, which is the shape of a downgrade.
            if (hello !== null) {
              refuse("BAD_REQUEST");
              return;
            }
            try {
              hello = parseHello(message, role);
            } catch {
              refuse("BAD_REQUEST");
              return;
            }
            controlBlock = isRecord(message.control) ? message.control : {};
            // ## The control block is authenticated by its digest, not its position
            //
            // `controlLength` and `controlSha256` are already bound into the transcript, so a peer
            // that alters the block after proving itself produces a digest the server never agreed
            // to. Recomputing it here is what makes that check real rather than decorative: without
            // it the declared digest would be a number the peer chose and nothing compared.
            controlBlockBytes = isRecord(message.control) ? Buffer.from(JSON.stringify(message.control), "utf8") : Buffer.alloc(0);
            serverNonce = newNonce();
            challenges.issue(Buffer.from(serverNonce, "hex"));
            post({
              kind: "CHALLENGE",
              protocolVersion: IPC_PROTOCOL_VERSION,
              serverNonce,
              // Echoed so the client can confirm the server answered *its* hello.
              clientNonce: hello.clientNonce,
              supervisorInstance: options.supervisorInstance,
              bootId: options.bootId,
            } satisfies ServerChallenge);
            continue;
          }

          if (message.kind === "AUTH") {
            attempts += 1;
            if (attempts > IPC_LIMITS.maxAuthAttempts) {
              refuse("AUTH_FAILED");
              return;
            }
            if (hello === null || serverNonce === null) {
              refuse("AUTH_FAILED");
              return;
            }
            // Consumed before verification: a wrong proof must still burn the challenge, or an
            // attacker could retry proofs against one nonce inside the attempt budget.
            if (!challenges.consume(Buffer.from(serverNonce, "hex"), IPC_LIMITS.authTimeoutMs)) {
              refuse("REPLAYED");
              return;
            }
            const transcriptFor = (direction: "client-to-server" | "server-to-client"): Buffer => buildTranscript({
              direction,
              protocolVersion: IPC_PROTOCOL_VERSION,
              supervisorInstance: options.supervisorInstance,
              bootId: options.bootId,
              serverNonce: Buffer.from(serverNonce!, "hex"),
              clientNonce: Buffer.from(hello!.clientNonce, "hex"),
              role,
              requestId: hello!.requestId,
              operation: hello!.operation,
              clientInstance: hello!.clientInstance,
              reservationId: hello!.reservationId,
              controlLength: hello!.controlLength,
              controlSha256: hello!.controlSha256,
              bodyLength: hello!.bodyLength,
              bodySha256: hello!.bodySha256,
            });
            const presented = typeof message.proof === "string" ? Buffer.from(message.proof, "hex") : Buffer.alloc(0);
            if (!verifyProof(options.secrets[role], transcriptFor("client-to-server"), presented)) {
              refuse("AUTH_FAILED");
              return;
            }
            // The control block must be exactly what the transcript bound. A peer that proved itself
            // and then supplied a different block is refused before any executor is considered.
            if (controlBlockBytes.byteLength !== hello.controlLength
              || createHash("sha256").update(controlBlockBytes).digest("hex") !== hello.controlSha256) {
              refuse("BAD_REQUEST");
              return;
            }
            const serverProof = computeProof(options.secrets[role], transcriptFor("server-to-client"));

            // Authentication is acknowledged *before* admission is decided.
            //
            // The order matters to a caller: `AUTH_OK` proves the server's identity, while a
            // `REFUSED` after it reports that the server was reachable and authentic and would not
            // admit this execution. Refusing before proving itself would leave a caller unable to
            // distinguish "busy" from "wrong process answered the inode", which are different
            // incidents with different responses.
            post({
              kind: "AUTH_OK",
              proof: serverProof.toString("hex"),
              supervisorInstance: options.supervisorInstance,
              bootId: options.bootId,
            } satisfies ServerAuthOk);
            authenticated = true;
            clearTimeout(handshakeTimer);

            // Authorization, checked after authentication and before admission. An authenticated
            // `app` asking for `fill` is a policy refusal, not a handshake failure: the caller proved
            // who it is and the server proved who it is, and the answer is still no.
            if (!isOperationAllowed(role, hello.operation)) {
              refuse("OPERATION_NOT_PERMITTED");
              return;
            }

            // ## Issuance happens here, on the authenticated connection, and then the frame continues
            //
            // A worker arriving to *ask* for a reservation (rather than to present one) is a
            // distinct exchange: it authenticates, asks, is answered, and disconnects. The request
            // travels in the authenticated `control` block as `reserve: true`, so it is covered by
            // `controlLength`/`controlSha256` and cannot be altered after the proof.
            //
            // It is answered on this socket and the connection ends. There is no admission of an
            // execution, so nothing occupies the executor slot while a worker negotiates.
            if (role === "worker" && controlBlock.reserve === true && (hello.reservationId ?? null) === null) {
              const grant = reserveForWorker(state, {
                callerIdentity: hello.clientInstance,
                operation: hello.operation,
                // A fresh worker has done nothing yet; the sequence is per caller and held below.
                sequence: sequenceFor(state, hello.clientInstance),
                now: now(),
                ttlMs: options.reservationTtlMs ?? 30_000,
                idleMs: options.reservationIdleMs ?? 10_000,
                maxPerCaller: options.maxReservationsPerCaller ?? 2,
                maxReservations: state.maxReservations,
              });
              if (!grant.ok) {
                post({ kind: "RESERVATION_REFUSED", code: grant.code } satisfies ServerReservationRefused);
              } else {
                // The sequence is NOT advanced here: issuing a reservation must not, by itself,
                // authorize the next operation. A sequence transition depends on the required
                // positively validated execution outcome, which advances the sequence when the
                // session is released with `resolved === true` (see `session.release` below).
                // An issued-but-unused reservation therefore never authorizes `fill` or `verify`.
                post({
                  kind: "RESERVED",
                  reservationId: grant.reservationId,
                  operation: grant.operation,
                  expiresAt: grant.expiresAt,
                  idleExpiresAt: grant.idleExpiresAt,
                } satisfies ServerReserved);
              }
              // No admission, no body, no executor: the asked-for reservation is the whole exchange.
              closed = true;
              socket.end();
              notifyControl?.();
              notifyBody?.();
              return;
            }

            const decision = admit(state, {
              role,
              operation: hello.operation,
              requestId: hello.requestId,
              reservationId: hello.reservationId ?? undefined,
              executionId: hello.executionId,
              // The authenticated identity, which a worker's reservation is bound to.
              callerIdentity: hello.clientInstance,
            }, now(), {
              reservationTtlMs: options.reservationTtlMs ?? 30_000,
              maxConnections: options.maxConnectionsPerRole ?? IPC_LIMITS.maxConnectionsPerRole,
            });
            if (!decision.ok) {
              refuse(decision.code);
              return;
            }

            admitted = {
              executionId: decision.executionId,
              released: false,
              callerIdentity: hello.clientInstance,
              operation: hello.operation,
              role,
            };
            state.connections.set(role, (state.connections.get(role) ?? 0) + 1);

            post({ kind: "ADMITTED", executionId: decision.executionId } satisfies ServerAdmitted);
            // The body region follows the invitation, not the admission: the caller may not write a
            // document byte until preflight has passed and the watchdog is armed, and `READY_FOR_BODY`
            // is the supervisor's evidence that both happened.
            readyNonce = newNonce();
            post({ kind: "READY_FOR_BODY", nonce: readyNonce } satisfies ServerReady);
            startSession();
            // Bytes that arrived with the AUTH frame are the session's from here.
            if (step.leftover.byteLength > 0) deliverSessionData(step.leftover);
            return;
          }

          // Anything else before authentication is not part of the handshake.
          refuse("BAD_REQUEST");
          return;
        }
      };

      // ── the session, started once admission succeeds ────────────────────────────────────────
      let sessionStarted = false;
      const startSession = (): void => {
        if (sessionStarted || hello === null || admitted === null) return;
        sessionStarted = true;

        const session: AdmittedSession = {
          role,
          operation: hello.operation,
          requestId: hello.requestId,
          executionId: admitted.executionId,
          socket,
          send: (message) => send(message),
          release: (outcome) => {
            if (admitted === null || admitted.released) return;
            admitted.released = true;
            if (outcome === "committed") {
              // A successful execution releases the slot and advances the caller's sequence:
              // completing `inspect` authorizes `fill`, completing `fill` authorizes `verify`.
              // Only a worker may advance the sequence: an app that successfully inspects must
              // never authorize a worker to fill. Reservation issuance alone does not advance.
              releaseResolved(state, admitted.executionId, true);
              if (admitted.role === "worker") {
                advanceSequence(state, admitted.callerIdentity, admitted.operation);
              }
            } else if (outcome === "refused") {
              // A refusal had no positive outcome, so the sequence does not advance. But nothing
              // was created, so there is no orphan container to hold the slot for: release capacity.
              releaseResolved(state, admitted.executionId, true);
            } else {
              // Unresolved or quarantined: a container may exist that this process cannot prove is
              // gone, so the slot stays held and the id is recorded as an unresolved debt.
              releaseResolved(state, admitted.executionId, false);
            }
            // The session is over once admission is resolved: the handler has read what it needs and
            // written what it owes. Closing here is what lets the handler's `finally` mean something
            // — otherwise it would end the socket underneath a response still being flushed.
            closed = true;
            socket.end();
          },
          control: controlStream(),
          body: bodyStream(),
          declared: { bodyBytes: hello.bodyLength, bodySha256: hello.bodySha256 },
          readyNonce: () => readyNonce,
          controlBlock: () => ({ ...controlBlock }),
        };

        void options.handle(session)
          .catch((error: unknown) => {
            options.log?.(`handler failed: ${error instanceof Error ? error.message : "unknown"}`);
          })
          .finally(() => {
            // The *connection* count is a per-connection fact and is released when the handler ends.
            // The *executor slot* is not: it is released by `session.release`, on evidence.
            state.connections.set(role, Math.max(0, (state.connections.get(role) ?? 1) - 1));
            if (admitted !== null && !admitted.released) {
              // The handler returned without resolving. That lifecycle has not positively resolved,
              // so the slot stays held and the id is recorded as an unresolved debt.
              releaseResolved(state, admitted.executionId, false);
            }
            closed = true;
            socket.end();
          });
      };

      async function* controlStream(): AsyncIterable<Record<string, unknown>> {
        for (;;) {
          const next = controlQueue.shift();
          if (next !== undefined) {
            yield next;
            continue;
          }
          if (closed) return;
          await new Promise<void>((resolve) => { notifyControl = resolve; });
          notifyControl = null;
        }
      }

      async function* bodyStream(): AsyncIterable<Buffer> {
        for (;;) {
          const chunk = bodyQueue.shift();
          if (chunk !== undefined) {
            yield chunk;
            continue;
          }
          if (closed || bodyEnded) return;
          await new Promise<void>((resolve) => { notifyBody = resolve; });
          notifyBody = null;
        }
      }

      socket.on("data", onData);
      socket.on("error", () => {
        // An error ends the connection; the handler observes the closed streams and decides.
      });
      socket.on("close", () => {
        closed = true;
        notifyControl?.();
        notifyBody?.();
        if (admitted !== null && !admitted.released) {
          releaseResolved(state, admitted.executionId, false);
        }
      });
    });

    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(socketPath, () => {
        server.removeListener("error", reject);
        chmodSync(socketPath, 0o600);
        resolve();
      });
    });
    servers.push(server);
  }

  return {
    servers,
    state,
    stop: async () => {
      // Destroy first: `close()` alone waits for peers that may never send FIN.
      for (const socket of live) socket.destroy();
      live.clear();
      await Promise.all(servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
      for (const socketPath of Object.values(options.socketPaths)) {
        if (existsSync(socketPath)) unlinkSync(socketPath);
      }
    },
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Parse a `HELLO`.
 *
 * Every field is validated, and the declared lengths and digests are checked for shape here rather
 * than at the point of use: a HELLO with a malformed digest cannot participate in a transcript, so
 * refusing it before a challenge is issued keeps a bad message from consuming challenge state.
 */
export function parseHello(message: Record<string, unknown>, role: IpcRole): ClientHello {
  if (message.kind !== "HELLO") throw new Error("not a HELLO");
  if (message.protocolVersion !== IPC_PROTOCOL_VERSION) throw new Error("unsupported protocol version");
  if (typeof message.clientNonce !== "string" || !/^[a-f0-9]{64}$/u.test(message.clientNonce)) {
    throw new Error("the HELLO nonce is not acceptable");
  }
  // The role is the socket, never a field: a peer cannot claim a role it did not connect to.
  parseRole(role);
  const operation = parseOperation(message.operation);
  const requestId = parseRequestId(message.requestId);
  const reservationId = typeof message.reservationId === "string" ? message.reservationId : null;
  if (reservationId !== null && !/^[a-f0-9]{16,64}$/u.test(reservationId)) throw new Error("the reservation id is not acceptable");
  const controlLength = Number(message.controlLength);
  const bodyLength = Number(message.bodyLength);
  if (!Number.isSafeInteger(controlLength) || controlLength < 0) throw new Error("the control length is not acceptable");
  if (!Number.isSafeInteger(bodyLength) || bodyLength < 0) throw new Error("the body length is not acceptable");
  return {
    kind: "HELLO",
    protocolVersion: IPC_PROTOCOL_VERSION,
    clientNonce: message.clientNonce,
    clientInstance: typeof message.clientInstance === "string" ? message.clientInstance : "",
    role,
    operation,
    requestId,
    reservationId,
    controlLength,
    controlSha256: parseDigest(message.controlSha256),
    bodyLength,
    bodySha256: parseDigest(message.bodySha256),
    executionId: typeof message.executionId === "string" ? message.executionId : undefined,
  };
}
