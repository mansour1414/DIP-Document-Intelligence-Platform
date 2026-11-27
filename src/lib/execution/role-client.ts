/**
 * The connecting caller transport (R7D.1 §9; Continuation D2).
 *
 * ## What was missing
 *
 * `executeRequest` drives a `SupervisorChannel`: an interface that describes *what* a caller does
 * once it has a channel, and says nothing about where the channel comes from. Until now nothing
 * implemented it against a socket, so the "trusted caller" half of the execution plane was a type
 * with no producer. This module is the producer.
 *
 * ## What the connection does, in order
 *
 * 1. **Connect** to the role socket. The role is the inode; no field on the wire can claim it.
 * 2. **HELLO**, declaring the operation, the request id, the reservation, and — importantly — the
 *    body's *length and digest*, which the supervisor binds into the transcript and reconciles
 *    against what it actually received. A caller that lies about the body fails at the handshake,
 *    not after the bytes are written.
 * 3. **Verify the CHALLENGE** answers *this* hello — the echoed client nonce must match, and the
 *    server instance and boot id must be the ones the caller expects. A caller that skipped this
 *    would accept a transcript from any process that could bind the socket.
 * 4. **AUTH** with a proof over the full transcript.
 * 5. **Verify `AUTH_OK`'s server proof.** This is mutual authentication: the caller proves who it
 *    is *and* requires the supervisor to prove who it is, over the same transcript. Verifying it is
 *    not optional and has no boolean to disable it, because a channel that skips the server proof
 *    is a channel that will hand back a result from whoever answered.
 * 6. **Wait for `READY_FOR_BODY`.** The body is not written a byte early: the supervisor releases
 *    the body only after preflight passed and the watchdog reported armed.
 * 7. **Stream**, hashing as it goes, and check the declared length and digest against what was
 *    actually sent before ending the body. A caller whose body did not match its own declaration
 *    cancels rather than letting the supervisor discover it.
 *
 * ## What it refuses
 *
 * Every refusal is a `CallerError` with a closed code. There is no retry-with-looser-checks path, no
 * "accept anyway" flag, and no way to ask the supervisor for more time.
 */

import { connect, type Socket } from "node:net";
import { createHash, randomBytes } from "node:crypto";
import type { Readable } from "node:stream";
import { PassThrough } from "node:stream";
import {
  IPC_PROTOCOL_VERSION,
  buildTranscript,
  computeProof,
  verifyProof,
  type IpcOperation,
  type IpcRole,
} from "./ipc-auth";
import { CallerError, executeRequest, type CallerLimits, type CallerResult, type RequestSpec, type SupervisorChannel } from "./caller";
import { decodeControlFrame, encodeControlFrame, newNonce } from "./role-sockets";
import type { TerminalCommitMessage } from "./terminal-auth";

/** What the caller must know before it connects. Supplied by the deployment, not by the peer. */
export type RoleClientOptions = {
  socketPath: string;
  role: IpcRole;
  operation: IpcOperation;
  /** The credential for *this role only*. An `app` caller has no `worker` secret to leak. */
  secret: Buffer;
  /** The instance the caller expects to be talking to. A different one is refused, not accepted. */
  supervisorInstance: string;
  bootId: string;
  /** Unpredictable, and unique per request; the supervisor remembers it, so replay is detectable. */
  requestId?: string;
  /** Required for `worker`: minted by the supervisor, single-use. */
  reservationId?: string;
  /**
   * The authenticated control block: which image, which profile, which cgroup parent.
   *
   * ## Why it travels here and not in the body
   *
   * It is bound into the handshake transcript by `controlLength`/`controlSha256`, so the supervisor
   * knows the image *before* it creates anything and knows the caller cannot change it afterwards.
   * Carrying it in the body would mean the container already exists by the time anyone could read
   * which container it should be.
   */
  control?: Record<string, unknown>;
  /** How long to wait for a connection and for the handshake. */
  connectTimeoutMs?: number;
};

export type RoleClientSession = {
  channel: SupervisorChannel;
  /** The execution id the supervisor minted at admission. */
  executionId: Promise<string>;
  /** The declared control length and digest, which the caller sends in its HELLO. */
  declaredControl: { length: number; sha256: string };
  /** Close everything. Idempotent. */
  destroy: () => void;
};

/**
 * Open an authenticated channel to a role socket.
 *
 * Returns a `SupervisorChannel` that `executeRequest` can drive. The handshake is awaited by the
 * caller under its own deadline: a supervisor that never answers must be a `NOT_READY`, not a hang.
 */
export async function openRoleChannel(options: RoleClientOptions): Promise<RoleClientSession> {
  if (options.reservationId === undefined && options.role === "worker") {
    // Fail here rather than at the server: a worker with no reservation is refused anyway, and a
    // client-side refusal names the mistake instead of reporting a server `REFUSED`.
    throw new CallerError("NOT_READY", "a worker caller must present a reservation");
  }

  const socket = await dial(options.socketPath, options.connectTimeoutMs ?? 5_000).catch(() => {
    throw new CallerError("TRANSPORT_CLOSED", `could not connect to ${options.socketPath}`);
  });

  const requestId = options.requestId ?? randomBytes(16).toString("hex");
  const clientNonce = newNonce();
  // The control block, as exact bytes. An absent block is the empty block, and its digest of the
  // empty string is honest rather than a zero the server skips.
  const control = Buffer.from(JSON.stringify(options.control ?? {}), "utf8");
  const declaredControl = { length: control.byteLength, sha256: createHash("sha256").update(control).digest("hex") };

  const frames = new FrameBufferLite();
  const controlMessages: Record<string, unknown>[] = [];
  let notifyControl: (() => void) | null = null;
  let serverNonce: string | null = null;
  let closed = false;
  let executionId: string | null = null;
  let resolveExecution: (id: string) => void = () => {};
  const executionPromise = new Promise<string>((resolve) => { resolveExecution = resolve; });

  // The handshake is driven explicitly below, so the message queue exists to hand AUTH frames to it.
  /** Wakes a handshake step; the frame itself is taken from the queue. */
  let resolveHandshakeMessage: (() => void) | null = null;

  const fail = (code: CallerError): never => {
    destroy();
    throw code;
  };

  const destroy = (): void => {
    if (closed) return;
    closed = true;
    resolveHandshakeMessage?.();
    notifyControl?.();
    socket.destroy();
  };

  socket.on("data", (chunk: Buffer) => {
    try {
      frames.append(chunk);
    } catch {
      destroy();
      return;
    }
    for (;;) {
      let step: ReturnType<FrameBufferLite["next"]>;
      try {
        step = frames.next();
      } catch {
        destroy();
        return;
      }
      if (step === null) break;
      frames.clear(step.leftover);
      const message = asRecord(step.message);
      if (message === null) continue;
      controlMessages.push(message);
      // A frame completes a handshake step if one is waiting, otherwise it belongs to the pump.
      resolveHandshakeMessage?.();
      notifyControl?.();
    }
  });
  socket.on("error", () => { closed = true; resolveHandshakeMessage?.(); notifyControl?.(); });
  socket.on("close", () => { closed = true; resolveHandshakeMessage?.(); notifyControl?.(); });

  /**
   * The next handshake frame.
   *
   * Written as a wake-and-drain loop rather than "register a resolver and wait", because a frame can
   * arrive in the microtask window between one `await` resolving and the next resolver being
   * registered. The earlier version dropped exactly such a frame — it was read, found no waiter, and
   * was pushed onto the post-handshake queue that the pump owned, where the handshake then waited
   * for it forever. A lost frame must never be silent, so the loop always re-checks the queue.
   */
  const nextHandshakeMessage = async (): Promise<Record<string, unknown>> => {
    for (;;) {
      const queued = controlMessages.shift();
      if (queued !== undefined) return queued;
      if (closed) return { kind: "__CLOSED__" };
      await new Promise<void>((resolve) => { resolveHandshakeMessage = resolve; });
      resolveHandshakeMessage = null;
    }
  };

  // ── 1. HELLO ────────────────────────────────────────────────────────────────────────────────
  socket.write(encodeControlFrame({
    kind: "HELLO",
    protocolVersion: IPC_PROTOCOL_VERSION,
    clientNonce,
    clientInstance: options.role === "app" ? "app-client" : "worker-client",
    role: options.role,
    operation: options.operation,
    requestId,
    reservationId: options.reservationId ?? null,
    controlLength: declaredControl.length,
    controlSha256: declaredControl.sha256,
    bodyLength: optionsBodyLength(options),
    bodySha256: optionsBodyDigest(options),
    control: options.control ?? {},
  }));
  void requestId;

  // ── 2. CHALLENGE ────────────────────────────────────────────────────────────────────────────
  const challenge = await nextHandshakeMessage();
  if (challenge.kind === "REFUSED") {
    return fail(new CallerError("NOT_READY", `the supervisor refused the request: ${String(challenge.code)}`));
  }
  if (challenge.kind !== "CHALLENGE") {
    return fail(new CallerError("TRANSPORT_CLOSED", "the supervisor did not send a challenge"));
  }
  if (challenge.protocolVersion !== IPC_PROTOCOL_VERSION) {
    return fail(new CallerError("NOT_READY", "the supervisor spoke a different protocol version"));
  }
  // The echoed nonce proves this challenge answers *our* hello. Without this check a replayed
  // challenge would be accepted and the caller would prove itself into someone else's transcript.
  if (challenge.clientNonce !== clientNonce) {
    return fail(new CallerError("NOT_READY", "the challenge did not answer this hello"));
  }
  if (challenge.supervisorInstance !== options.supervisorInstance) {
    return fail(new CallerError("NOT_READY", "the challenge came from a different supervisor instance"));
  }
  if (challenge.bootId !== options.bootId) {
    return fail(new CallerError("NOT_READY", "the challenge came from a different boot"));
  }
  serverNonce = typeof challenge.serverNonce === "string" ? challenge.serverNonce : null;
  if (serverNonce === null || !/^[a-f0-9]{64}$/u.test(serverNonce)) {
    return fail(new CallerError("NOT_READY", "the challenge nonce is not acceptable"));
  }

  const transcriptFor = (direction: "client-to-server" | "server-to-client"): Buffer => buildTranscript({
    direction,
    protocolVersion: IPC_PROTOCOL_VERSION,
    supervisorInstance: options.supervisorInstance,
    bootId: options.bootId,
    serverNonce: Buffer.from(serverNonce!, "hex"),
    clientNonce: Buffer.from(clientNonce, "hex"),
    role: options.role,
    requestId,
    operation: options.operation,
    reservationId: options.reservationId ?? null,
    controlLength: declaredControl.length,
    controlSha256: declaredControl.sha256,
    bodyLength: optionsBodyLength(options),
    bodySha256: optionsBodyDigest(options),
  });

  // ── 3. AUTH ─────────────────────────────────────────────────────────────────────────────────
  socket.write(encodeControlFrame({
    kind: "AUTH",
    proof: computeProof(options.secret, transcriptFor("client-to-server")).toString("hex"),
  }));

  // ── 4. AUTH_OK ──────────────────────────────────────────────────────────────────────────────
  const authOk = await nextHandshakeMessage();
  if (authOk.kind === "REFUSED") {
    return fail(new CallerError("NOT_READY", `the supervisor refused the request: ${String(authOk.code)}`));
  }
  if (authOk.kind !== "AUTH_OK") {
    return fail(new CallerError("TRANSPORT_CLOSED", "the supervisor did not acknowledge authentication"));
  }
  if (authOk.supervisorInstance !== options.supervisorInstance || authOk.bootId !== options.bootId) {
    return fail(new CallerError("NOT_READY", "authentication completed against a different supervisor"));
  }
  const serverProof = typeof authOk.proof === "string" ? Buffer.from(authOk.proof, "hex") : Buffer.alloc(0);
  if (!verifyProof(options.secret, transcriptFor("server-to-client"), serverProof)) {
    // Mutual authentication. A caller that accepted this would hand its document to whatever
    // process happened to answer on the inode.
    return fail(new CallerError("NOT_READY", "the supervisor failed to prove itself"));
  }
  // ── 5. ADMITTED ─────────────────────────────────────────────────────────────────────────────
  const admitted = await nextHandshakeMessage();
  if (admitted.kind === "REFUSED") {
    return fail(new CallerError("NOT_READY", `the supervisor refused admission: ${String(admitted.code)}`));
  }
  if (admitted.kind !== "ADMITTED" || typeof admitted.executionId !== "string") {
    return fail(new CallerError("TRANSPORT_CLOSED", "the supervisor did not admit the request"));
  }
  executionId = admitted.executionId;
  // Resolved here, during the handshake, and *not* from the control pump: the pump is the sole
  // consumer of the frame queue after the handshake, so anything it is responsible for must not
  // also be awaited by a second reader. This was a real hang — the caller waited on a promise the
  // pump had already answered to nobody.
  resolveExecution(executionId);

  // ── 6. READY_FOR_BODY, and the result stream ────────────────────────────────────────────────
  //
  // One consumer, one queue. An earlier draft had the handshake wait for READY_FOR_BODY on one
  // promise while a pump drained the same array for result frames; whichever got there first ate
  // the other's message, and the failure was a silent hang rather than a refusal. The pump is now
  // the sole reader, and everything — readiness, the stream, the commit — is routed from it.
  let resolveReady: () => void = () => {};
  const readyPromise = new Promise<void>((resolve) => { resolveReady = resolve; });
  let ready = false;
  const resultStream = new PassThrough();
  let commitResolver: ((message: TerminalCommitMessage | null) => void) | null = null;
  const commitPromise = new Promise<TerminalCommitMessage | null>((resolve) => { commitResolver = resolve; });
  let settled = false;
  const settle = (): void => {
    if (settled) return;
    settled = true;
    resultStream.end();
    commitResolver?.(null);
  };

  const pump = async (): Promise<void> => {
    try {
      for (;;) {
        if (closed) break;
        const message = controlMessages.shift();
        if (message === undefined) {
          await new Promise<void>((resolve) => { notifyControl = resolve; });
          notifyControl = null;
          continue;
        }
        switch (message.kind) {
          case "READY_FOR_BODY":
            // The one gate that releases the body. Set before the body can be written.
            if (!ready) {
              ready = true;
              resolveReady();
            }
            break;
          case "STREAM_CHUNK": {
            const bytes = Buffer.from(String(message.data), "base64");
            if (!resultStream.write(bytes)) {
              // Backpressure: the caller's reader decides how fast the supervisor may speak.
              await new Promise<void>((resolve) => resultStream.once("drain", resolve));
            }
            break;
          }
          case "STREAM_END":
            settle();
            break;
          case "TERMINAL_COMMIT":
            commitResolver?.(message.message as TerminalCommitMessage);
            break;
          case "REFUSED": {
            const error = new CallerError("NOT_READY", `the supervisor refused: ${String(message.code)}`);
            resultStream.destroy(error);
            commitResolver?.(null);
            break;
          }
          default:
            break;
        }
      }
    } catch {
      settle();
    } finally {
      settle();
    }
  };
  void pump();

  let bodyOpened = false;
  const channel: SupervisorChannel = {
    ready: readyPromise,
    write: async (chunk: Buffer): Promise<void> => {
      if (closed) throw new CallerError("TRANSPORT_CLOSED", "the supervisor closed the connection");
      if (!bodyOpened) {
        // The body is a counted region that begins at a frame boundary. Opening it with the first
        // chunk rather than at READY_FOR_BODY means a caller that never writes still leaves the
        // control stream usable, which is what a cancellation needs.
        bodyOpened = true;
        socket.write(encodeControlFrame({ kind: "BEGIN_BODY" }));
      }
      if (!socket.write(chunk)) await new Promise<void>((resolve) => socket.once("drain", resolve));
    },
    // The body region is counted, not terminated: the supervisor knows how many raw bytes follow
    // from the length declared in the HELLO, so there is no end-of-body message to send.
    endInput: () => { /* the declared length is the terminator */ },
    result: resultStream,
    commitMessage: () => commitPromise,
    cancel: () => {
      if (!closed) socket.write(encodeControlFrame({ kind: "REJECTED_BY_PEER" }));
      destroy();
    },
    nonce: clientNonce,
  };

  return { channel, executionId: executionPromise, declaredControl, destroy };
}

/** Minimal frame reader for the client. Mirrors the server's, with the same bound. */
class FrameBufferLite {
  private pending: Buffer = Buffer.alloc(0);

  append(chunk: Buffer): void {
    this.pending = Buffer.concat([this.pending, chunk]);
    // The same bound the server enforces. A supervisor that sent more is not one to trust.
    if (this.pending.byteLength > 8 * 1024 * 1024) throw new Error("the control stream exceeded the bound");
  }

  next(): { message: unknown; leftover: Buffer } | null {
    if (this.pending.byteLength < 4) return null;
    const declared = this.pending.readUInt32BE(0);
    if (declared === 0 || declared > 256 * 1024) throw new Error("the control frame declared an unacceptable length");
    if (this.pending.byteLength < 4 + declared) return null;
    const frame = this.pending.subarray(0, 4 + declared);
    const leftover = this.pending.subarray(4 + declared);
    return { message: decodeControlFrame(frame), leftover };
  }

  clear(leftover: Buffer): void {
    this.pending = leftover;
  }
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

/** Open a Unix socket, or fail. Bounded, because an unreachable socket must not hang a worker. */
async function dial(path: string, timeoutMs: number): Promise<Socket> {
  return new Promise<Socket>((resolve, reject) => {
    const socket = connect({ path });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("the connect deadline passed"));
    }, timeoutMs);
    timer.unref();
    socket.once("connect", () => {
      clearTimeout(timer);
      resolve(socket);
    });
    socket.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

/**
 * The declared body length and digest.
 *
 * These are supplied out of band rather than derived from the stream, because the supervisor binds
 * them into the transcript *before* a byte is written. A caller that cannot say how large its body
 * is must materialize it, which is exactly what the streaming design exists to avoid — so the
 * declaration is a required input, and `executeRequest` checks that what it streamed agrees.
 */
const declaredBodies = new WeakMap<RoleClientOptions, { length: number; sha256: string }>();

/** Declare the body this caller will send. Must be called before `openRoleChannel`. */
export function declareBody(options: RoleClientOptions, body: { length: number; sha256: string }): void {
  declaredBodies.set(options, body);
}

function optionsBodyLength(options: RoleClientOptions): number {
  return declaredBodies.get(options)?.length ?? 0;
}

function optionsBodyDigest(options: RoleClientOptions): string {
  return declaredBodies.get(options)?.sha256 ?? createHash("sha256").digest("hex");
}

/**
 * One call, end to end: connect, authenticate, stream, verify the commit, return verified bytes.
 *
 * This is the function a worker calls. Everything above it is the machinery that makes it safe to
 * call; nothing above it is needed to use it.
 */
export async function callSupervisor(options: RoleClientOptions & {
  spec: Omit<RequestSpec, "executionId">;
  body: Readable;
  bodyBytes: number;
  bodyDigest: string;
  limits?: Partial<CallerLimits>;
}): Promise<CallerResult> {
  declareBody(options, { length: options.bodyBytes, sha256: options.bodyDigest });
  const session = await openRoleChannel(options);
  try {
    const executionId = await session.executionId;
    return await executeRequest(
      session.channel,
      {
        requestId: options.requestId ?? newNonce().slice(0, 32),
        operation: options.operation,
        role: options.role,
        bodyBytes: options.bodyBytes,
        bodyDigest: options.bodyDigest,
        metaBytes: 0,
        executionId,
      },
      options.body,
      options.secret,
      { limits: options.limits },
    );
  } finally {
    session.destroy();
  }
}
