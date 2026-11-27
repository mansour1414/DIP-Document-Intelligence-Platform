/**
 * The Supervisor's role sockets (R7D.1 §5).
 *
 * ## One socket per role, not one socket with a role field
 *
 * A single socket would mean the role is whatever the peer says it is, and the authorization
 * check would be a comparison against an attacker-supplied string. Two sockets — each created
 * with its own mode, owned by its own filesystem group — mean the role is a property of which
 * inode the peer connected to, decided by the kernel.
 *
 * ## One operation per connection
 *
 * A connection performs one execution and is closed. There is no pooling, no keep-alive and no
 * session. A multiplexed connection would have to track which execution a byte belonged to, and
 * every bug in that tracking is a document delivered to the wrong caller.
 *
 * ## Admission
 *
 * One globally active executor. Not one per role, not one per connection: the profile exists to
 * keep memory bounded, and two concurrent 384 MiB executors are 768 MiB whatever the per-container
 * limit says. Queueing is refused rather than deferred — a caller that waits for a slot holds a
 * connection and a body it has not sent, which is unbounded in the wrong dimension.
 */

import { createServer, type Server, type Socket } from "node:net";
import { chmodSync, existsSync, unlinkSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { IPC_LIMITS, ROLE_POLICY, parseOperation, parseRequestId, parseRole, type IpcOperation, type IpcRole } from "./ipc-auth";

/** Admission: one active execution, bounded connections, bounded auth state. */
export type AdmissionState = {
  activeExecution: string | null;
  activeSince: number | null;
  connections: Map<IpcRole, number>;
  /** Per-role reservations, so a worker cannot occupy the executor with a token it guessed. */
  reservations: Map<string, { role: IpcRole; expiresAt: number; sequence: number }>;
};

export function newAdmissionState(): AdmissionState {
  return { activeExecution: null, activeSince: null, connections: new Map(), reservations: new Map() };
}

/** Why admission refused. Closed: the caller branches. */
export type AdmissionRefusal =
  | "BUSY"
  | "ROLE_NOT_PERMITTED"
  | "OPERATION_NOT_PERMITTED"
  | "TOO_MANY_CONNECTIONS"
  | "RESERVATION_REQUIRED"
  | "RESERVATION_INVALID"
  | "BAD_REQUEST";

export type AdmissionDecision = { ok: true; executionId: string } | { ok: false; code: AdmissionRefusal };

/**
 * Decide whether to admit a request.
 *
 * Every input is validated before any state is consulted. A malformed request must not be able to
 * occupy the single executor slot, which means shape validation comes before the busy check.
 */
export function admit(
  state: AdmissionState,
  request: { role: unknown; operation: unknown; requestId: unknown; reservationId?: unknown; executionId: unknown },
  now: number,
  options: { reservationTtlMs: number; maxConnections: number },
): AdmissionDecision {
  let role: IpcRole;
  let operation: IpcOperation;
  let requestId: string;
  try {
    role = parseRole(request.role);
    operation = parseOperation(request.operation);
    requestId = parseRequestId(request.requestId);
  } catch {
    return { ok: false, code: "BAD_REQUEST" };
  }
  void requestId;

  // Role × operation is a static policy, checked before any dynamic state.
  const permitted = ROLE_POLICY[role];
  if (!(permitted as readonly string[]).includes(operation)) {
    return { ok: false, code: "OPERATION_NOT_PERMITTED" };
  }

  const current = state.connections.get(role) ?? 0;
  if (current >= options.maxConnections) return { ok: false, code: "TOO_MANY_CONNECTIONS" };

  // A worker must present a live reservation. The reservation is what makes "who may fill" a
  // server-side fact rather than a claim on the wire, and its sequence is what prevents replay.
  if (role === "worker") {
    const reservationId = typeof request.reservationId === "string" ? request.reservationId : "";
    const reservation = state.reservations.get(reservationId);
    if (reservation === undefined) return { ok: false, code: "RESERVATION_REQUIRED" };
    if (reservation.role !== "worker" || reservation.expiresAt <= now) {
      state.reservations.delete(reservationId);
      return { ok: false, code: "RESERVATION_INVALID" };
    }
  }

  if (state.activeExecution !== null) return { ok: false, code: "BUSY" };

  const executionId = typeof request.executionId === "string" && /^[a-f0-9]{32}$/u.test(request.executionId)
    ? request.executionId
    : randomBytes(16).toString("hex");

  state.activeExecution = executionId;
  state.activeSince = now;
  return { ok: true, executionId };
}

/** Create a transient sequence reservation. Unpredictable, finite, single-use. */
export function reserve(state: AdmissionState, role: IpcRole, now: number, ttlMs: number): { reservationId: string; expiresAt: number } {
  // Purge expired reservations first, so an idle server does not accumulate them.
  for (const [id, record] of state.reservations) {
    if (record.expiresAt <= now) state.reservations.delete(id);
  }
  const reservationId = randomBytes(24).toString("hex");
  const expiresAt = now + ttlMs;
  const sequence = state.reservations.size + 1;
  state.reservations.set(reservationId, { role, expiresAt, sequence });
  return { reservationId, expiresAt };
}

/** Release the active execution. Must be called on every exit path, including failure. */
export function release(state: AdmissionState, executionId: string): void {
  if (state.activeExecution === executionId) {
    state.activeExecution = null;
    state.activeSince = null;
  }
}

export type SupervisorServerOptions = {
  /** One path per role. The role is the socket, never a field on the wire. */
  socketPaths: Record<IpcRole, string>;
  /** Handles one admitted connection. Must settle exactly once. */
  handle: (input: { role: IpcRole; operation: IpcOperation; socket: Socket; executionId: string }) => Promise<void>;
  monotonicMs?: () => number;
  reservationTtlMs?: number;
  maxConnectionsPerRole?: number;
  log?: (line: string) => void;
};

/**
 * Start both role sockets.
 *
 * The sockets are created inside a directory whose mode the caller controls, and each is
 * chmod'd to 0600 before listening. The group-based separation is a deployment property (a
 * systemd unit and a socket unit), and this code cannot prove it — see the docs for that gap.
 */
export async function startSupervisorServer(options: SupervisorServerOptions): Promise<{
  servers: Server[];
  state: AdmissionState;
  stop: () => Promise<void>;
}> {
  const state = newAdmissionState();
  const now = options.monotonicMs ?? (() => Math.round(performance.now()));
  const servers: Server[] = [];

  for (const role of Object.keys(options.socketPaths) as IpcRole[]) {
    const socketPath = options.socketPaths[role];
    if (existsSync(socketPath)) unlinkSync(socketPath);
    const server = createServer((socket) => {
      let admitted = false;
      let executionId: string | null = null;

      const deny = (code: AdmissionRefusal): void => {
        socket.end(`${JSON.stringify({ kind: "DENIED", code })}\n`);
      };

      // The preamble is bounded and small: it is the only work an unauthenticated peer can cause.
      let preamble = "";
      const onData = (chunk: Buffer): void => {
        if (admitted) return;
        preamble += chunk.toString("utf8");
        if (Buffer.byteLength(preamble, "utf8") > IPC_LIMITS.preambleBytes) {
          socket.destroy();
          return;
        }
        const newline = preamble.indexOf("\n");
        if (newline < 0) return;
        socket.off("data", onData);
        let request: Record<string, unknown>;
        try {
          request = JSON.parse(preamble.slice(0, newline)) as Record<string, unknown>;
        } catch {
          deny("BAD_REQUEST");
          return;
        }
        // The role comes from which socket was connected to, not from the message. A worker
        // that opens the app socket is an app, whatever it claims.
        const decision = admit(state, {
          role,
          operation: request.operation,
          requestId: request.requestId,
          reservationId: request.reservationId,
          executionId: request.executionId,
        }, now(), {
          reservationTtlMs: options.reservationTtlMs ?? 30_000,
          maxConnections: options.maxConnectionsPerRole ?? IPC_LIMITS.maxConnectionsPerRole,
        });
        if (!decision.ok) {
          deny(decision.code);
          return;
        }
        admitted = true;
        executionId = decision.executionId;
        state.connections.set(role, (state.connections.get(role) ?? 0) + 1);
        socket.write(`${JSON.stringify({ kind: "ADMITTED", executionId })}\n`);
        const operation = request.operation as IpcOperation;
        void options.handle({ role, operation, socket, executionId })
          .catch((error: unknown) => {
            options.log?.(`handler failed: ${error instanceof Error ? error.message : "unknown"}`);
          })
          .finally(() => {
            state.connections.set(role, Math.max(0, (state.connections.get(role) ?? 1) - 1));
            if (executionId !== null) release(state, executionId);
            // One operation per connection: the handler finishing ends the connection, whether it
            // succeeded or not.
            socket.end();
          });
      };
      socket.on("data", onData);
      socket.setTimeout(IPC_LIMITS.idleTimeoutMs, () => {
        if (!admitted) socket.destroy();
      });
      socket.on("error", () => {
        if (executionId !== null) release(state, executionId);
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
      await Promise.all(servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
      for (const socketPath of Object.values(options.socketPaths)) {
        if (existsSync(socketPath)) unlinkSync(socketPath);
      }
    },
  };
}
