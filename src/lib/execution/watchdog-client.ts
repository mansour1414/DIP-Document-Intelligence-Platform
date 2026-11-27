/**
 * The Supervisor's authenticated client for the Watchdog's control channel (R7D.1 D2).
 *
 * ## What this replaces
 *
 * `caller.ts` and `supervisor.ts` both described a `SupervisorChannel`-shaped watchdog seam, and
 * nothing ever connected one. The seam was injectable in tests, which made every supervisor test
 * that needed an arm work against a fake and left the real wire unexercised: no handshake, no
 * proof, no framing, no timeout.
 *
 * This is the real transport. It speaks the protocol the watchdog server enforces:
 *
 * ```
 *   client ── HELLO { clientNonce, clientInstance, protocolVersion: 2 } ────────────▶
 *   client ◀── CHALLENGE { serverNonce, serverInstance, bootId, pid } ──────────────
 *   client ── AUTH { proof("client-to-watchdog" over both nonces + instances) } ───▶
 *   client ◀── AUTH_OK { proof("watchdog-to-client" over the same transcript) } ────
 *   client ── ARM_REQ / DISARM_REQ / HEARTBEAT / STATE_REQ, each with its own nonce ─▶
 * ```
 *
 * ## What is verified here, and why each check exists
 *
 * - **The server's proof.** A peer that accepts `AUTH` has proven nothing; it may be any process
 *   that can `connect()` to the socket. The `AUTH_OK` proof is verified before any authenticated
 *   request is sent, so the client learns it is talking to the process holding the secret.
 * - **Fresh nonces, both directions.** 32 bytes each, generated per connection. A replayed
 *   `CHALLENGE` cannot be answered, because the client's own nonce is in the transcript.
 * - **Instance and boot binding.** The watchdog's reported instance and boot id are checked
 *   against what the supervisor expects. A restarted watchdog is a different enforcer, and a
 *   control channel to the wrong one would arm a deadline in a process that does not hold the
 *   pinned descriptors.
 * - **Per-request nonce plus payload digest.** Every request carries a fresh nonce and a proof over
 *   a canonical digest of its exact payload. A captured request cannot be replayed (the nonce is
 *   consumed server-side) and cannot be altered (the digest would change).
 * - **Bounded frames.** The 4-byte length prefix is validated *before* the body is read, so a peer
 *   declaring a 4 GiB frame costs this process nothing but the header read.
 * - **Finite deadlines.** Every exchange has one. A control plane that can wait forever on a peer
 *   turns that peer into a denial of service against every execution on the host.
 *
 * ## What this deliberately does not do
 *
 * It does not retry. A transport failure is reported as a closed-vocabulary refusal so the caller
 * can decide: reconnecting is the caller's policy, and a client that reconnects behind its caller's
 * back would defeat the deadline the caller set.
 */

import { connect, type Socket } from "node:net";
import { randomBytes } from "node:crypto";
import {
  assertArmRequest,
  decodeWatchdogFrame,
  encodeWatchdogFrame,
  verifyArmAck,
  WATCHDOG_LIMITS,
  type ArmAck,
  type ArmDenied,
  type ArmRequest,
} from "./watchdog-protocol";
import {
  assertAuth,
  assertAuthenticatedRequest,
  assertHello,
  computeAuthProof,
  newAuthNonce,
  payloadDigest,
  verifyAuthProof,
  type AuthenticatedKind,
  type ChallengeMessage,
  type ClientSession,
} from "./watchdog-auth";
import { assertTerminalContext, type TerminalDeniedMessage, type TerminalGrantMessage, type TerminalRequest } from "./terminal-auth";
import { verifyDisarmGrant } from "./watchdog-protocol";

/** A refusal from the control channel. Closed, because the caller branches on every member. */
export type WatchdogClientError =
  /** The socket could not be reached. Nothing was sent. */
  | "UNREACHABLE"
  /** The peer answered, but not with a handshake this client can accept. */
  | "HANDSHAKE_REFUSED"
  /** The peer's `AUTH_OK` proof did not verify: this is not the process holding the secret. */
  | "SERVER_PROOF_INVALID"
  /** The peer named a different watchdog instance or boot than the one the supervisor expects. */
  | "INSTANCE_MISMATCH"
  /** The exchange did not complete inside its deadline. */
  | "TIMEOUT"
  /** A frame was oversized, truncated or unparseable. */
  | "FRAMING"
  /** The connection closed mid-exchange. */
  | "CLOSED";

/**
 * The refusal codes the watchdog may answer with.
 *
 * Enumerated here so the supervisor can branch on them exhaustively rather than treating any
 * non-grant as "retry". They mean different things, and conflating them is how a lost grant gets
 * re-minted:
 *
 * - `DURABILITY_FAILED` — the watchdog could not record the decision. **Never** retry the request:
 *   the watchdog may have acted, and a second request is a second authoritative outcome.
 * - `UNCERTAIN` — the watchdog cannot tell whether the execution is still live. Terminate, do not
 *   commit.
 * - `TERMINATION_PENDING` — a kill was signalled and descendants remain. Wait for the watchdog's
 *   own confirmation; the supervisor does not signal again on its own authority here.
 * - `NOT_DIP_OWNED` — the container does not match the recorded identity. Quarantine, never signal.
 * - `CGROUP_UNVERIFIED` — the container is running outside the pinned cgroup, so the watchdog's
 *   start-time authority does not cover it. Quarantine.
 * - `EXPIRED` — the deadline passed. The outcome is expiry; there is no grant to recover.
 * - `INSTANCE_MISMATCH` — the request named a different instance or boot.
 */
export type WatchdogRefusalCode =
  | "DURABILITY_FAILED"
  | "UNCERTAIN"
  | "TERMINATION_PENDING"
  | "NOT_DIP_OWNED"
  | "CGROUP_UNVERIFIED"
  | "EXPIRED"
  | "INSTANCE_MISMATCH";

/**
 * Whether a refusal permits asking again.
 *
 * Only `TERMINATION_PENDING` does, and only because the watchdog itself is still working: it has
 * signalled, descendants remain, and it will report again. Every other refusal is terminal for this
 * execution. In particular a refusal that says the durable record could not be written is *not*
 * retried, because the watchdog's decision may already have taken effect.
 */
export function refusalIsRetryable(code: WatchdogRefusalCode): boolean {
  return code === "TERMINATION_PENDING";
}

export class WatchdogChannelError extends Error {
  constructor(readonly code: WatchdogClientError, message: string) {
    super(message);
    this.name = "WatchdogChannelError";
  }
}

/** What the client needs to know about the watchdog it is talking to. */
export type WatchdogClientOptions = {
  socketPath: string;
  /** The shared control secret. At least 32 bytes; a shorter one is a configuration error. */
  secret: Buffer;
  /** This supervisor's instance identity, which the handshake binds the connection to. */
  supervisorInstance: string;
  /** The boot id the supervisor believes it is running on. Checked against the watchdog's. */
  bootId: string;
  /** How long one complete exchange may take. */
  requestTimeoutMs?: number;
  /** How long the handshake may take. Separate, because it is the unauthenticated phase. */
  handshakeTimeoutMs?: number;
};

/** The seam `SupervisorExecution` consumes. Structurally identical to its `watchdog` option. */
export type WatchdogChannel = {
  arm: (request: ArmRequest) => Promise<ArmAck | ArmDenied>;
  disarm: (
    request: TerminalRequest,
    messageId: string,
    sequence: number,
  ) => Promise<{ proof: string } | { code: string }>;
  /** Ask the watchdog what it holds for one execution. Used by reconciliation. */
  state: (executionId: string) => Promise<WatchdogStateReply>;
  heartbeat: (executionId: string, messageId: string) => Promise<boolean>;
  close: () => void;
};

/** The watchdog's own account of one execution. Identity only; no paths, no PIDs. */
export type WatchdogStateReply = {
  armed: boolean;
  phase: string | null;
  outcome: string | null;
  processDebt: string | null;
  containerDebt: string | null;
};

/**
 * One authenticated connection.
 *
 * Deliberately not pooled or reused across executions: a connection carries the identity that
 * authenticated it, and the watchdog binds requests to that identity for the connection's life.
 * Reconnecting per execution keeps "which supervisor is this" a per-exchange fact rather than a
 * per-process one, and costs one `connect()` per document.
 */
export class AuthenticatedWatchdogClient implements WatchdogChannel {
  private readonly options: WatchdogClientOptions;
  private socket: Socket | null = null;
  private session: ClientSession | null = null;
  private buffer: Buffer = Buffer.alloc(0);
  /** Frames received but not yet claimed by a waiter, in order. */
  private readonly inbox: unknown[] = [];
  private waiter: { resolve: (value: unknown) => void; reject: (error: Error) => void } | null = null;
  private closed: Error | null = null;

  constructor(options: WatchdogClientOptions) {
    if (options.secret.byteLength < 32) throw new Error("the watchdog control secret must be at least 32 bytes");
    this.options = options;
  }

  /** Whether a handshake has completed on the current connection. */
  get authenticated(): boolean {
    return this.session?.authenticated === true;
  }

  /** The watchdog instance this connection authenticated against, once known. */
  get watchdogInstance(): string | null {
    return this.session?.serverInstance ?? null;
  }

  /**
   * Connect and complete the handshake.
   *
   * Exposed because a caller may want to know the channel is live before it issues an arm, and
   * because `INSTANCE_MISMATCH` should be discovered before a deadline is owed rather than after.
   */
  async connect(): Promise<{ watchdogInstance: string; bootId: string }> {
    if (this.socket !== null) throw new WatchdogChannelError("HANDSHAKE_REFUSED", "this client is already connected");
    const socket = await this.open();
    this.socket = socket;
    try {
      return await this.handshake(socket);
    } catch (error) {
      this.destroy(error instanceof Error ? error : new Error("handshake failed"));
      throw error;
    }
  }

  // ── the seam ────────────────────────────────────────────────────────────────────────────────

  async arm(request: ArmRequest): Promise<ArmAck | ArmDenied> {
    // Validated before it is signed: a malformed request would otherwise be authenticated, sent,
    // and refused remotely, which reports a request-shape bug as a watchdog decision.
    const payload = assertArmRequest(request) as unknown as Record<string, unknown>;
    const answer = await this.request("ARM_REQ", payload);

    if (isRecord(answer) && answer.kind === "ARM_DENIED") {
      return answer as unknown as ArmDenied;
    }
    if (!isRecord(answer) || answer.kind !== "ARM_ACK") {
      throw new WatchdogChannelError("FRAMING", `the watchdog answered an ARM with ${describeKind(answer)}`);
    }
    const ack = answer as unknown as ArmAck;
    // The ack's own proof is verified against *this* request's identity. Without this an on-path
    // peer could return a well-formed ack for a different execution and the supervisor would invite
    // a caller to stream into a container whose deadline nobody armed.
    if (ack.executionId !== request.executionId || ack.messageId !== request.messageId) {
      throw new WatchdogChannelError("SERVER_PROOF_INVALID", "the arm ack names a different exchange");
    }
    if (ack.watchdogInstance !== this.session?.serverInstance) {
      throw new WatchdogChannelError("SERVER_PROOF_INVALID", "the arm ack names a different watchdog instance");
    }
    if (!verifyArmAck(this.options.secret, ack)) {
      throw new WatchdogChannelError("SERVER_PROOF_INVALID", "the arm ack proof did not verify");
    }
    return ack;
  }

  async disarm(
    request: TerminalRequest,
    messageId: string,
    sequence: number,
  ): Promise<{ proof: string } | { code: string }> {
    const context = assertTerminalContext(request, "disarm context");
    const answer = await this.request("DISARM_REQ", { messageId, sequence, context: context as unknown as Record<string, unknown> });

    if (!isRecord(answer)) throw new WatchdogChannelError("FRAMING", "the watchdog sent an empty disarm reply");

    // ## The reply is discriminated by shape, not by a `kind` field
    //
    // `TerminalGrantMessage` and `TerminalDeniedMessage` are the terminal vocabulary shared with the
    // caller, and neither carries a `kind`. A grant is the only reply with a `proof`; a denial is the
    // only one with a `code`. Discriminating on those two fields means a frame cannot be made to look
    // like both, and an `ERROR` from the server still surfaces with its own code rather than being
    // mistaken for the watchdog declining to mint a grant.
    if (typeof answer.proof === "string") {
      const grant = answer as unknown as TerminalGrantMessage;
      if (!isRecord(grant.context)) {
        throw new WatchdogChannelError("FRAMING", "the disarm grant carries no context");
      }
      // Verified before it is handed on. `verifyDisarmGrant` covers the terminal transcript, including
      // the direction tag, so an echoed request cannot be presented as a grant.
      if (!verifyDisarmGrant(this.options.secret, grant)) {
        throw new WatchdogChannelError("SERVER_PROOF_INVALID", "the disarm grant proof did not verify");
      }
      // The grant must describe the exchange that asked for it.
      if (grant.context.executionId !== request.executionId
        || grant.context.containerId !== request.containerId
        || grant.context.requestId !== request.requestId) {
        throw new WatchdogChannelError("SERVER_PROOF_INVALID", "the disarm grant describes a different exchange");
      }
      return { proof: grant.proof };
    }

    if (typeof answer.code === "string") {
      // A denial from the watchdog, or an error from the server. Both are decisions the caller
      // branches on; neither is a transport failure.
      const denied = answer as unknown as TerminalDeniedMessage;
      return { code: denied.code };
    }

    throw new WatchdogChannelError("FRAMING", `the watchdog answered a DISARM with ${describeKind(answer)}`);
  }

  async state(executionId: string): Promise<WatchdogStateReply> {
    const answer = await this.request("STATE_REQ", { executionId });
    if (!isRecord(answer) || answer.kind !== "STATE_ACK") {
      throw new WatchdogChannelError("FRAMING", `the watchdog answered a STATE with ${describeKind(answer)}`);
    }
    return {
      armed: answer.armed === true,
      phase: typeof answer.phase === "string" ? answer.phase : null,
      outcome: typeof answer.outcome === "string" ? answer.outcome : null,
      processDebt: typeof answer.processDebt === "string" ? answer.processDebt : null,
      containerDebt: typeof answer.containerDebt === "string" ? answer.containerDebt : null,
    };
  }

  async heartbeat(executionId: string, messageId: string): Promise<boolean> {
    const answer = await this.request("HEARTBEAT", {
      kind: "HEARTBEAT",
      messageId,
      executionId,
      supervisorInstance: this.options.supervisorInstance,
      monotonicMs: Math.round(performance.now()),
    });
    return isRecord(answer) && answer.kind === "HEARTBEAT_ACK";
  }

  /** Close the connection. Idempotent, and never throws. */
  close(): void {
    const socket = this.socket;
    this.socket = null;
    this.session = null;
    if (socket !== null) {
      socket.removeAllListeners();
      socket.destroy();
    }
    this.rejectWaiter(new WatchdogChannelError("CLOSED", "the channel was closed"));
  }

  // ── transport ───────────────────────────────────────────────────────────────────────────────

  private open(): Promise<Socket> {
    return new Promise((resolve, reject) => {
      const socket = connect(this.options.socketPath);
      const timer = setTimeout(() => {
        socket.destroy();
        reject(new WatchdogChannelError("TIMEOUT", "the watchdog socket could not be reached in time"));
      }, this.options.handshakeTimeoutMs ?? WATCHDOG_LIMITS.requestTimeoutMs);
      timer.unref();
      socket.once("connect", () => {
        clearTimeout(timer);
        socket.removeAllListeners("error");
        resolve(socket);
      });
      socket.once("error", (error: Error) => {
        clearTimeout(timer);
        reject(new WatchdogChannelError("UNREACHABLE", `the watchdog socket could not be reached: ${error.message}`));
      });
    });
  }

  private async handshake(socket: Socket): Promise<{ watchdogInstance: string; bootId: string }> {
    const clientNonce = newAuthNonce();
    const clientInstance = this.options.supervisorInstance;
    const session: ClientSession = {
      clientNonce,
      serverNonce: "",
      clientInstance,
      serverInstance: "",
      bootId: "",
      authenticated: false,
      issuedNonces: new Set(),
    };
    this.attach(socket);

    this.write(socket, { kind: "HELLO", clientNonce, clientInstance, protocolVersion: 2 } satisfies ReturnType<typeof assertHello>);
    const challengeMessage = await this.next(this.options.handshakeTimeoutMs ?? WATCHDOG_LIMITS.requestTimeoutMs);
    if (!isRecord(challengeMessage) || challengeMessage.kind !== "CHALLENGE") {
      throw new WatchdogChannelError("HANDSHAKE_REFUSED", `the watchdog answered HELLO with ${describeKind(challengeMessage)}`);
    }
    const challenge = challengeMessage as unknown as ChallengeMessage;
    // The challenge must answer *this* HELLO. A different client nonce is either a confused peer or
    // a replayed frame from another connection's handshake.
    if (challenge.clientNonce !== clientNonce) {
      throw new WatchdogChannelError("HANDSHAKE_REFUSED", "the challenge answers a different HELLO");
    }
    if (typeof challenge.serverNonce !== "string" || !/^[a-f0-9]{64}$/u.test(challenge.serverNonce)) {
      throw new WatchdogChannelError("HANDSHAKE_REFUSED", "the challenge carries no usable nonce");
    }
    if (challenge.protocolVersion !== 2) {
      throw new WatchdogChannelError("HANDSHAKE_REFUSED", "the watchdog speaks an unsupported protocol version");
    }
    session.serverNonce = challenge.serverNonce;
    session.serverInstance = String(challenge.serverInstance ?? "");
    session.bootId = String(challenge.bootId ?? "");

    // Bound before the connection is used: a channel to a different boot's watchdog would arm a
    // deadline in a process whose pinned descriptors refer to a container namespace that is gone.
    if (session.bootId !== this.options.bootId) {
      throw new WatchdogChannelError("INSTANCE_MISMATCH", `the watchdog is running on boot ${session.bootId}`);
    }

    const proof = computeAuthProof(this.options.secret, {
      direction: "client-to-watchdog",
      kind: "AUTH",
      clientNonce: session.clientNonce,
      serverNonce: session.serverNonce,
      clientInstance: session.clientInstance,
      serverInstance: session.serverInstance,
      bootId: session.bootId,
      requestNonce: "",
      payloadSha256: payloadDigest({ kind: "AUTH" }),
    });
    this.write(socket, { kind: "AUTH", clientNonce, serverNonce: session.serverNonce, proof } satisfies ReturnType<typeof assertAuth>);

    const authOkMessage = await this.next(this.options.handshakeTimeoutMs ?? WATCHDOG_LIMITS.requestTimeoutMs);
    if (!isRecord(authOkMessage) || authOkMessage.kind !== "AUTH_OK") {
      throw new WatchdogChannelError("HANDSHAKE_REFUSED", `the watchdog answered AUTH with ${describeKind(authOkMessage)}`);
    }
    // The server's half of the proof. This is the check that makes the channel mutual: a peer that
    // merely accepted our proof has shown nothing about itself.
    const serverProofOk = verifyAuthProof(this.options.secret, {
      direction: "watchdog-to-client",
      kind: "AUTH_OK",
      clientNonce: session.clientNonce,
      serverNonce: session.serverNonce,
      clientInstance: session.clientInstance,
      serverInstance: session.serverInstance,
      bootId: session.bootId,
      requestNonce: "",
      payloadSha256: payloadDigest({ kind: "AUTH_OK" }),
    }, String(authOkMessage.proof ?? ""));
    if (!serverProofOk) {
      throw new WatchdogChannelError("SERVER_PROOF_INVALID", "the watchdog's AUTH_OK proof did not verify");
    }
    // The instance is only trustworthy once its proof has verified, so it is compared afterwards.
    if (String(authOkMessage.watchdogInstance ?? "") !== session.serverInstance
      || String(authOkMessage.bootId ?? "") !== session.bootId) {
      throw new WatchdogChannelError("SERVER_PROOF_INVALID", "the AUTH_OK identity disagrees with the challenge");
    }

    session.authenticated = true;
    this.session = session;
    return { watchdogInstance: session.serverInstance, bootId: session.bootId };
  }

  /**
   * Send one authenticated request and wait for its reply.
   *
   * The reply is *not* correlated to the request by a field in the frame: the protocol is
   * one-request-at-a-time on a connection, and the client enforces that by refusing a second
   * concurrent exchange. Concurrency here would need request ids in every reply, and a wrong
   * correlation is a document-level error.
   */
  private async request(kind: AuthenticatedKind, payload: Record<string, unknown>): Promise<unknown> {
    const socket = this.socket;
    const session = this.session;
    if (socket === null || session === null || !session.authenticated) {
      throw new WatchdogChannelError("CLOSED", "the channel is not authenticated");
    }
    if (this.waiter !== null) throw new WatchdogChannelError("CLOSED", "an exchange is already in flight on this channel");

    const requestNonce = newAuthNonce();
    if (session.issuedNonces.has(requestNonce)) throw new WatchdogChannelError("CLOSED", "nonce collision");
    session.issuedNonces.add(requestNonce);

    const proof = computeAuthProof(this.options.secret, {
      direction: "client-to-watchdog",
      kind,
      clientNonce: session.clientNonce,
      serverNonce: session.serverNonce,
      clientInstance: session.clientInstance,
      serverInstance: session.serverInstance,
      bootId: session.bootId,
      requestNonce,
      payloadSha256: payloadDigest(payload),
    });

    const envelope = { kind, requestNonce, payload, proof };
    // Validated by the same assertion the server uses, so a client that can build a request will
    // never be refused for its shape.
    assertAuthenticatedRequest(envelope);

    this.write(socket, envelope);
    return await this.next(this.options.requestTimeoutMs ?? WATCHDOG_LIMITS.requestTimeoutMs);
  }

  private write(socket: Socket, message: unknown): void {
    const frame = encodeWatchdogFrame(message);
    socket.write(frame);
  }

  /** Wait for the next frame, or fail on the deadline. */
  private next(timeoutMs: number): Promise<unknown> {
    const queued = this.inbox.shift();
    if (queued !== undefined) return Promise.resolve(queued);
    if (this.closed !== null) return Promise.reject(this.closed);
    return new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiter = null;
        reject(new WatchdogChannelError("TIMEOUT", "the watchdog did not answer in time"));
      }, timeoutMs);
      timer.unref();
      this.waiter = {
        resolve: (value) => { clearTimeout(timer); resolve(value); },
        reject: (error) => { clearTimeout(timer); reject(error); },
      };
    });
  }

  private attach(socket: Socket): void {
    socket.on("data", (chunk: Buffer) => this.onData(chunk));
    socket.on("error", (error: Error) => {
      this.destroy(new WatchdogChannelError("CLOSED", `the channel failed: ${error.message}`));
    });
    socket.on("close", () => {
      this.destroy(new WatchdogChannelError("CLOSED", "the watchdog closed the connection"));
    });
  }

  private onData(chunk: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    for (;;) {
      if (this.buffer.byteLength < 4) return;
      const declared = this.buffer.readUInt32BE(0);
      // The declared length is checked before the body is waited for. A peer that announces an
      // enormous frame is refused on the header, not after allocating it.
      if (declared === 0 || declared > WATCHDOG_LIMITS.frameBytes) {
        this.destroy(new WatchdogChannelError("FRAMING", `the watchdog declared a ${declared} byte frame`));
        return;
      }
      if (this.buffer.byteLength < 4 + declared) return;
      const frame = this.buffer.subarray(0, 4 + declared);
      this.buffer = this.buffer.subarray(4 + declared);
      let message: unknown;
      try {
        message = decodeWatchdogFrame(frame);
      } catch (error) {
        this.destroy(new WatchdogChannelError("FRAMING", error instanceof Error ? error.message : "unparseable frame"));
        return;
      }
      if (this.waiter !== null) {
        const waiter = this.waiter;
        this.waiter = null;
        waiter.resolve(message);
      } else {
        // A frame nobody asked for. Queued rather than discarded, because the reply to a request may
        // arrive before the waiter is registered in a pipelined exchange; the queue is bounded so a
        // peer cannot grow it without limit.
        if (this.inbox.length >= 8) {
          this.destroy(new WatchdogChannelError("FRAMING", "the watchdog sent more frames than were asked for"));
          return;
        }
        this.inbox.push(message);
      }
    }
  }

  private destroy(error: Error): void {
    if (this.closed !== null) return;
    this.closed = error;
    const socket = this.socket;
    this.socket = null;
    if (socket !== null) {
      socket.removeAllListeners();
      socket.destroy();
    }
    this.rejectWaiter(error);
  }

  private rejectWaiter(error: Error): void {
    const waiter = this.waiter;
    this.waiter = null;
    waiter?.reject(error);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** A frame kind, for a diagnostic that carries no peer-supplied text. */
function describeKind(value: unknown): string {
  if (!isRecord(value)) return "a non-object";
  const kind = value.kind;
  return typeof kind === "string" && /^[A-Z_]{3,24}$/u.test(kind) ? kind : "an unrecognised frame";
}

/** A fresh control message id, as the protocol's 16-hex form. */
export function newMessageId(): string {
  return randomBytes(8).toString("hex");
}
