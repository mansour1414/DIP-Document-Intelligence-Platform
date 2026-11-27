/**
 * The Watchdog's socket server (R7D.1 §4; Continuation D1 WD-02).
 *
 * Runs in the watchdog's own process, on its own event loop, with its own timer.
 *
 * ## What changed in Continuation D1, and why
 *
 * The previous server dispatched `ARM_REQ`, `HEARTBEAT` and `DISARM_REQ` straight from the decoded
 * frame. Signing the *reply* is not authentication of the *request*: any local process that could
 * open the socket could arm a deadline, disarm a live execution, or read execution state, and the
 * only thing standing in the way was the file mode.
 *
 * Every message now goes through the handshake in `watchdog-auth.ts` and every request carries its
 * own proof bound to the connection transcript, the request kind, a per-request nonce and the exact
 * payload. A connection that has not authenticated can send nothing that mutates state — `HELLO`
 * and `AUTH` are the only messages it can usefully send, and neither touches an execution.
 *
 * ## Bounds
 *
 * Frame size, connection count, frames per connection, response buffer, handshake time and idle
 * time are all bounded. They were bounded before; the difference is that a connection now also
 * costs a handshake before it can consume anything expensive.
 */

import { createServer, type Server, type Socket } from "node:net";
import { chmodSync, existsSync, unlinkSync } from "node:fs";
import {
  WATCHDOG_LIMITS,
  assertArmRequest,
  decodeWatchdogFrame,
  encodeWatchdogFrame,
  type ArmRequest,
} from "./watchdog-protocol";
import {
  AUTH_FAILED_CLOSE_MESSAGE,
  newAuthNonce,
  assertHello,
  assertAuth,
  assertAuthenticatedRequest,
  computeAuthProof,
  payloadDigest,
  verifyAuthProof,
  type ServerSession,
} from "./watchdog-auth";
import { assertTerminalContext } from "./terminal-auth";
import type { Watchdog } from "./watchdog";

/** Additional bounds the authenticated channel needs beyond the frame limit. */
export const AUTH_LIMITS = Object.freeze({
  /** Concurrent connections, authenticated or not. */
  maxConnections: 8,
  /** How long a connection may sit between accept and a completed handshake. */
  handshakeTimeoutMs: 2_000,
  /** Requests one authenticated connection may issue before it must reconnect. */
  maxRequestsPerConnection: 16,
  /** Nonces remembered per connection for replay rejection. */
  maxRequestNonces: 32,
  /**
   * Bytes the server will buffer toward a peer that is not reading.
   *
   * A control reply is a few hundred bytes; a peer that has not drained this much is not reading
   * and the connection is destroyed rather than allowed to grow.
   */
  maxResponseBufferBytes: 64 * 1024,
});

export type WatchdogServerOptions = {
  socketPath: string;
  watchdog: Watchdog;
  /** The shared control secret. Requests without a valid proof are refused. */
  secret: Buffer;
  /** How often deadlines are checked. The bound is what makes a deadline a deadline. */
  tickIntervalMs?: number;
  /** Called after a termination attempt, so the entry point can record the attestation. */
  onTermination?: (result: Awaited<ReturnType<Watchdog["terminate"]>>) => void;
  log?: (line: string) => void;
};

/**
 * Buffer frames until a complete one is available.
 *
 * Assuming one `data` event per frame works in a test and fails under load, where two messages
 * coalesce — and the failure is silent, because the second message is parsed as a continuation of
 * the first and both are lost.
 */
class FrameBuffer {
  private pending: Buffer = Buffer.alloc(0);

  constructor(private readonly maxBytes: number) {}

  push(chunk: Buffer): Buffer[] {
    this.pending = Buffer.concat([this.pending, chunk]);
    if (this.pending.byteLength > this.maxBytes + 4) {
      throw new Error("the peer sent more than one bounded frame without a boundary");
    }
    const frames: Buffer[] = [];
    while (this.pending.byteLength >= 4) {
      const length = this.pending.readUInt32BE(0);
      if (length === 0 || length > this.maxBytes) throw new Error("the peer declared an unacceptable frame length");
      if (this.pending.byteLength < 4 + length) break;
      frames.push(this.pending.subarray(0, 4 + length));
      this.pending = this.pending.subarray(4 + length);
    }
    return frames;
  }
}

/**
 * Start the watchdog server.
 *
 * The socket is created with mode 0600 before the server listens. Creating it world-writable and
 * tightening afterwards leaves a window in which any local process can connect — and, before this
 * change, arm a deadline.
 */
export async function startWatchdogServer(options: WatchdogServerOptions): Promise<{ server: Server; stop: () => Promise<void> }> {
  if (existsSync(options.socketPath)) unlinkSync(options.socketPath);

  const connections = new Set<Socket>();
  const server = createServer((socket) => {
    connections.add(socket);
    if (connections.size > AUTH_LIMITS.maxConnections) {
      socket.destroy();
      connections.delete(socket);
      return;
    }

    const frames = new FrameBuffer(WATCHDOG_LIMITS.frameBytes);
    let session: ServerSession | null = null;
    let requests = 0;

    // A connection that never completes the handshake is closed rather than allowed to sit. An
    // unauthenticated peer costs a socket and a timer; it must not cost anything unbounded.
    const handshakeTimer = setTimeout(() => {
      if (session === null || !session.authenticated) socket.destroy();
    }, AUTH_LIMITS.handshakeTimeoutMs);
    handshakeTimer.unref();

    const reply = (message: unknown): void => {
      const encoded = encodeWatchdogFrame(message);
      // A peer that is not draining must not be allowed to grow a server-side buffer.
      if (socket.writableLength + encoded.byteLength > AUTH_LIMITS.maxResponseBufferBytes) {
        socket.destroy();
        return;
      }
      socket.write(encoded);
    };

    // Serialized, not merely async: two frames arriving in one chunk must be answered in order,
    // and an async handler would otherwise interleave two dispatches and reply out of order.
    let queue: Promise<void> = Promise.resolve();
    socket.on("data", (chunk: Buffer) => {
      queue = queue.then(() => handleData(chunk)).catch(() => { socket.destroy(); });
    });

    const handleData = async (chunk: Buffer): Promise<void> => {
      let incoming: Buffer[];
      try {
        incoming = frames.push(chunk);
      } catch {
        // Framing violation. No recovery keeps the peer's identity trustworthy.
        socket.destroy();
        return;
      }
      for (const frame of incoming) {
        let message: unknown;
        try {
          message = decodeWatchdogFrame(frame);
        } catch (error) {
          reply({ kind: "ERROR", code: "FRAMING", detail: error instanceof Error ? error.message : "unreadable" });
          continue;
        }

        try {
          // ---- Handshake ----
          if (typeof message === "object" && message !== null && (message as { kind?: unknown }).kind === "HELLO") {
            const hello = assertHello(message);
            clearTimeout(handshakeTimer);
            session = {
              clientNonce: hello.clientNonce,
              serverNonce: newAuthNonce(),
              clientInstance: hello.clientInstance,
              serverInstance: options.watchdog.identity.instance,
              bootId: options.watchdog.identity.bootId,
              authenticated: false,
              consumedNonces: new Set(),
              createdAtMs: Date.now(),
            };
            reply({
              kind: "CHALLENGE",
              serverNonce: session.serverNonce,
              clientNonce: session.clientNonce,
              serverInstance: session.serverInstance,
              bootId: session.bootId,
              pid: options.watchdog.identity.pid,
              protocolVersion: 2,
            });
            continue;
          }

          if (typeof message === "object" && message !== null && (message as { kind?: unknown }).kind === "AUTH") {
            const auth = assertAuth(message);
            if (session === null) {
              socket.destroy();
              return;
            }
            // The nonces must be the ones this connection issued. A stale nonce is a replayed
            // handshake, and accepting it would let an entire recorded exchange be reused.
            if (auth.clientNonce !== session.clientNonce || auth.serverNonce !== session.serverNonce) {
              reply(AUTH_FAILED_CLOSE_MESSAGE);
              socket.destroy();
              return;
            }
            const ok = verifyAuthProof(options.secret, {
              direction: "client-to-watchdog",
              kind: "AUTH",
              clientNonce: session.clientNonce,
              serverNonce: session.serverNonce,
              clientInstance: session.clientInstance,
              serverInstance: session.serverInstance,
              bootId: session.bootId,
              requestNonce: "",
              payloadSha256: payloadDigest({ kind: "AUTH" }),
            }, auth.proof);
            if (!ok) {
              reply(AUTH_FAILED_CLOSE_MESSAGE);
              socket.destroy();
              return;
            }
            session.authenticated = true;
            // The acknowledgement is signed in the other direction over the same transcript, so
            // the client learns it is talking to the process holding the secret, not merely to
            // something that accepted a guess.
            reply({
              kind: "AUTH_OK",
              clientNonce: session.clientNonce,
              serverNonce: session.serverNonce,
              watchdogInstance: session.serverInstance,
              bootId: session.bootId,
              proof: computeAuthProof(options.secret, {
                direction: "watchdog-to-client",
                kind: "AUTH_OK",
                clientNonce: session.clientNonce,
                serverNonce: session.serverNonce,
                clientInstance: session.clientInstance,
                serverInstance: session.serverInstance,
                bootId: session.bootId,
                requestNonce: "",
                payloadSha256: payloadDigest({ kind: "AUTH_OK" }),
              }),
            });
            continue;
          }

          // ---- Everything below requires an authenticated session ----
          if (session === null || !session.authenticated) {
            reply({ kind: "ERROR", code: "UNAUTHENTICATED" });
            socket.destroy();
            return;
          }

          requests += 1;
          if (requests > AUTH_LIMITS.maxRequestsPerConnection) {
            reply({ kind: "ERROR", code: "REQUEST_LIMIT" });
            socket.destroy();
            return;
          }

          const request = assertAuthenticatedRequest(message);

          // Per-request nonce: a captured request cannot be replayed, even on this connection.
          if (session.consumedNonces.has(request.requestNonce)) {
            reply({ kind: "ERROR", code: "REPLAYED_REQUEST" });
            socket.destroy();
            return;
          }
          if (session.consumedNonces.size >= AUTH_LIMITS.maxRequestNonces) {
            reply({ kind: "ERROR", code: "REQUEST_LIMIT" });
            socket.destroy();
            return;
          }
          session.consumedNonces.add(request.requestNonce);

          // The proof binds the exact payload. A message altered in transit cannot verify, and a
          // proof captured for one payload cannot authorize another.
          const proofOk = verifyAuthProof(options.secret, {
            direction: "client-to-watchdog",
            kind: request.kind,
            clientNonce: session.clientNonce,
            serverNonce: session.serverNonce,
            clientInstance: session.clientInstance,
            serverInstance: session.serverInstance,
            bootId: session.bootId,
            requestNonce: request.requestNonce,
            payloadSha256: payloadDigest(request.payload),
          }, request.proof);
          if (!proofOk) {
            reply({ kind: "ERROR", code: "BAD_PROOF" });
            socket.destroy();
            return;
          }

          // `dispatch` is async because DISARM verifies completion against the host. Awaiting it is
          // load-bearing: an un-awaited Promise serialises to `{}`, so the supervisor would receive
          // a well-framed empty object instead of a denial — a refusal that looks like a success
          // with no fields.
          reply(await dispatch(options, request.kind, request.payload));
        } catch (error) {
          // Answered, not ignored: silence leaves the supervisor waiting until its own deadline,
          // which looks like a hang rather than a refusal.
          reply({ kind: "ERROR", code: "BAD_REQUEST", detail: error instanceof Error ? error.message : "unhandled" });
        }
      }
    };

    socket.on("close", () => {
      clearTimeout(handshakeTimer);
      connections.delete(socket);
    });
    socket.on("error", () => {
      clearTimeout(handshakeTimer);
      connections.delete(socket);
    });
    socket.setTimeout(WATCHDOG_LIMITS.requestTimeoutMs * 10, () => socket.destroy());
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.socketPath, () => {
      server.removeListener("error", reject);
      chmodSync(options.socketPath, 0o600);
      resolve();
    });
  });

  // The independent timer. `unref` is deliberately not used: this interval is the reason the
  // process stays alive when nothing is connected, and a watchdog that exits because it is idle is
  // a watchdog that is not watching.
  const tick = setInterval(() => {
    void runDeadlines(options).catch((error: unknown) => {
      options.log?.(`deadline tick failed: ${error instanceof Error ? error.message : "unknown"}`);
    });
  }, options.tickIntervalMs ?? 250);

  return {
    server,
    stop: async () => {
      clearInterval(tick);
      for (const socket of connections) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      if (existsSync(options.socketPath)) unlinkSync(options.socketPath);
    },
  };
}

/** Check deadlines and terminate anything that is due. Exported so a test can drive it directly. */
export async function runDeadlines(options: Pick<WatchdogServerOptions, "watchdog" | "onTermination" | "log">): Promise<void> {
  const due = options.watchdog.dueForTermination();
  for (const execution of due) {
    const result = await options.watchdog.terminate(execution);
    options.onTermination?.(result);
    options.log?.(
      result.resolved
        ? `terminated ${execution.executionId}`
        : `termination unresolved for ${execution.executionId}: ${result.detail}`,
    );
  }
}

/**
 * Route one authenticated request.
 *
 * Only four kinds exist, all of them about one execution the client has already proven it may
 * speak about. There is no generic "run this" or "read that path" operation, because a control
 * channel that can be asked arbitrary questions about the host is a privilege escalation with a
 * schema.
 */
async function dispatch(options: WatchdogServerOptions, kind: string, payload: Record<string, unknown>): Promise<unknown> {
  switch (kind) {
    case "ARM_REQ": {
      const request: ArmRequest = assertArmRequest(payload);
      return options.watchdog.arm(request);
    }
    case "HEARTBEAT": {
      const executionId = String(payload.executionId ?? "");
      const messageId = String(payload.messageId ?? "");
      if (!/^[a-f0-9]{32}$/u.test(executionId)) throw new Error("the heartbeat execution id is not acceptable");
      if (!/^[a-f0-9]{16,64}$/u.test(messageId)) throw new Error("the heartbeat message id is not acceptable");
      const result = options.watchdog.heartbeat({
        kind: "HEARTBEAT",
        messageId,
        executionId,
        supervisorInstance: String(payload.supervisorInstance ?? ""),
        monotonicMs: Number(payload.monotonicMs ?? 0),
      });
      return result.ok ? { kind: "HEARTBEAT_ACK" } : { kind: "ERROR", code: result.code };
    }
    case "DISARM_REQ": {
      const messageId = payload.messageId;
      const sequence = payload.sequence;
      if (typeof messageId !== "string" || !/^[a-f0-9]{16,64}$/u.test(messageId)) {
        throw new Error("the disarm message id is not acceptable");
      }
      if (typeof sequence !== "number" || !Number.isSafeInteger(sequence)) {
        throw new Error("the disarm sequence is not an integer");
      }
      const context = assertTerminalContext(payload.context, "disarm context");
      return await options.watchdog.disarm(context, messageId, sequence);
    }
    case "STATE_REQ": {
      const executionId = String(payload.executionId ?? "");
      if (!/^[a-f0-9]{32}$/u.test(executionId)) throw new Error("the state execution id is not acceptable");
      const state = options.watchdog.state(executionId);
      return {
        kind: "STATE_ACK",
        executionId,
        armed: state.armed,
        phase: state.phase,
        // Only the fields a supervisor needs to reconcile. No cgroup path, no PID, no daemon detail:
        // the caller either already knows them or has no reason to.
        outcome: state.record?.outcome ?? null,
        processDebt: state.record?.processDebt ?? null,
        containerDebt: state.record?.containerDebt ?? null,
      };
    }
    default:
      throw new Error(`unrecognised request kind ${kind}`);
  }
}

export { FrameBuffer, AUTH_FAILED_CLOSE_MESSAGE };
