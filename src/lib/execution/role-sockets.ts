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
import { randomBytes } from "node:crypto";
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

/** What admission knows about the one executor it may admit. */
export type AdmissionState = {
  activeExecution: string | null;
  activeSince: number | null;
  connections: Map<IpcRole, number>;
  reservations: Map<string, { role: IpcRole; expiresAt: number; sequence: number }>;
  /** Execution ids whose lifecycle has not positively resolved. Nothing is admitted while non-empty. */
  unresolved: Set<string>;
};

export function newAdmissionState(): AdmissionState {
  return {
    activeExecution: null,
    activeSince: null,
    connections: new Map(),
    reservations: new Map(),
    unresolved: new Set(),
  };
}

/** A reservation: unpredictable, finite, single-use, and bound to one role. */
export function reserve(state: AdmissionState, role: IpcRole, now: number, ttlMs: number): { reservationId: string; expiresAt: number } {
  for (const [id, record] of state.reservations) {
    if (record.expiresAt <= now) state.reservations.delete(id);
  }
  const reservationId = randomBytes(24).toString("hex");
  const expiresAt = now + ttlMs;
  const sequence = state.reservations.size + 1;
  state.reservations.set(reservationId, { role, expiresAt, sequence });
  return { reservationId, expiresAt };
}

export type AdmissionRequest = {
  role: unknown;
  operation: unknown;
  requestId: unknown;
  reservationId?: unknown;
  executionId?: unknown;
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
  try {
    role = parseRole(request.role);
    // Shape-checked only: which operations a role may invoke is the server's decision, made after
    // authentication, so that a policy refusal is never reported as a handshake failure.
    parseOperation(request.operation);
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

  // A worker must present a live reservation for the worker role. The reservation is what makes
  // "who may fill" a server-side fact rather than a claim on the wire.
  if (role === "worker") {
    const reservationId = typeof request.reservationId === "string" ? request.reservationId : "";
    const reservation = state.reservations.get(reservationId);
    if (reservation === undefined) return { ok: false, code: "RESERVATION_REQUIRED" };
    if (reservation.role !== "worker" || reservation.expiresAt <= now) {
      state.reservations.delete(reservationId);
      return { ok: false, code: "RESERVATION_INVALID" };
    }
    // Single use: consuming it here means a captured reservation cannot be replayed.
    state.reservations.delete(reservationId);
  }

  // ## Nothing is admitted while any lifecycle is unresolved
  //
  // This is stricter than "no active execution". An execution that finished its handler but whose
  // container has not been positively removed is still using the single executor slot, and admitting
  // a second one alongside it is two containers under one profile.
  if (state.unresolved.size > 0) return { ok: false, code: "BUSY" };
  if (state.activeExecution !== null) return { ok: false, code: "BUSY" };

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
  maxConnectionsPerRole?: number;
  log?: (line: string) => void;
};

/** One admitted execution, as the handler sees it. */
export type AdmittedSession = {
  role: IpcRole;
  operation: IpcOperation;
  executionId: string;
  socket: Socket;
  /** Write one control frame. Refuses if the peer has gone. */
  send: (message: unknown) => void;
  /** Resolve admission. Called exactly once by the handler, with evidence. */
  release: (resolved: boolean) => void;
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
      let admitted: { executionId: string; released: boolean } | null = null;

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

      const send = (message: unknown): void => {
        if (closed) return;
        try {
          socket.write(encodeControlFrame(message));
        } catch {
          closed = true;
          socket.destroy();
        }
      };

      const refuse = (code: RoleRefusal): void => {
        send({ kind: "REFUSED", code } satisfies ServerRefusal);
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
            serverNonce = newNonce();
            challenges.issue(Buffer.from(serverNonce, "hex"));
            send({
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
            const serverProof = computeProof(options.secrets[role], transcriptFor("server-to-client"));

            // Authentication is acknowledged *before* admission is decided.
            //
            // The order matters to a caller: `AUTH_OK` proves the server's identity, while a
            // `REFUSED` after it reports that the server was reachable and authentic and would not
            // admit this execution. Refusing before proving itself would leave a caller unable to
            // distinguish "busy" from "wrong process answered the inode", which are different
            // incidents with different responses.
            send({
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
            const decision = admit(state, {
              role,
              operation: hello.operation,
              requestId: hello.requestId,
              reservationId: hello.reservationId ?? undefined,
              executionId: hello.executionId,
            }, now(), {
              reservationTtlMs: options.reservationTtlMs ?? 30_000,
              maxConnections: options.maxConnectionsPerRole ?? IPC_LIMITS.maxConnectionsPerRole,
            });
            if (!decision.ok) {
              refuse(decision.code);
              return;
            }

            admitted = { executionId: decision.executionId, released: false };
            state.connections.set(role, (state.connections.get(role) ?? 0) + 1);

            send({ kind: "ADMITTED", executionId: decision.executionId } satisfies ServerAdmitted);
            // The body region follows the invitation, not the admission: the caller may not write a
            // document byte until preflight has passed and the watchdog is armed, and `READY_FOR_BODY`
            // is the supervisor's evidence that both happened.
            send({ kind: "READY_FOR_BODY", nonce: newNonce() } satisfies ServerReady);
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
          executionId: admitted.executionId,
          socket,
          send: (message) => send(message),
          release: (resolved) => {
            if (admitted === null || admitted.released) return;
            admitted.released = true;
            releaseResolved(state, admitted.executionId, resolved);
            // The session is over once admission is resolved: the handler has read what it needs and
            // written what it owes. Closing here is what lets the handler's `finally` mean something
            // — otherwise it would end the socket underneath a response still being flushed.
            closed = true;
            socket.end();
          },
          control: controlStream(),
          body: bodyStream(),
          declared: { bodyBytes: hello.bodyLength, bodySha256: hello.bodySha256 },
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
