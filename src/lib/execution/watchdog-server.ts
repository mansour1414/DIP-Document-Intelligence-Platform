/**
 * The Watchdog's socket server (R7D.1 §4).
 *
 * Runs in the watchdog's own process, on its own event loop, with its own timer. `scripts/watchdog-main.mjs`
 * is the entry point; this module is the transport.
 *
 * ## Why the timer is here and not in the client
 *
 * The supervisor arms a deadline and then goes away. If the only thing that checked the deadline
 * were the supervisor's timer, a wedged supervisor would mean the container runs forever, which
 * is exactly the case the watchdog exists to cover. The interval below runs regardless of whether
 * anyone is connected.
 *
 * ## Framing
 *
 * Length-prefixed, bounded, one message per frame. Anything else closes the connection: a control
 * channel that guesses at framing is one that can be desynchronised, and a desynchronised control
 * channel can be made to deliver a stale message to a live execution.
 */

import { createServer, type Server, type Socket } from "node:net";
import { chmodSync, existsSync, unlinkSync } from "node:fs";
import { MessageIdWindow, WATCHDOG_LIMITS, decodeWatchdogFrame, encodeWatchdogFrame, type Heartbeat } from "./watchdog-protocol";
import type { Watchdog } from "./watchdog";
import { assertArmRequest, type ArmRequest } from "./watchdog-protocol";
import { assertTerminalContext } from "./terminal-auth";

export type WatchdogServerOptions = {
  socketPath: string;
  watchdog: Watchdog;
  /** How often deadlines are checked. The bound is what makes a deadline a deadline. */
  tickIntervalMs?: number;
  /** Called after a termination attempt, so the caller can record the attestation. */
  onTermination?: (result: Awaited<ReturnType<Watchdog["terminate"]>>) => void;
  log?: (line: string) => void;
};

/**
 * Buffer frames until a complete one is available.
 *
 * The alternative — assuming one `data` event per frame — works in a test and fails under load,
 * where two messages coalesce. That failure mode is silent: the second message is parsed as a
 * continuation of the first and both are lost.
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
 * tightening afterwards leaves a window in which any local process can connect and arm a deadline.
 */
export async function startWatchdogServer(options: WatchdogServerOptions): Promise<{ server: Server; stop: () => Promise<void> }> {
  if (existsSync(options.socketPath)) unlinkSync(options.socketPath);

  const connections = new Set<Socket>();
  const server = createServer((socket) => {
    connections.add(socket);
    // A watchdog connection is a control channel with a known peer. An unbounded connection is a
    // resource the peer controls, so it is bounded.
    if (connections.size > 8) {
      socket.destroy();
      connections.delete(socket);
      return;
    }
    const frames = new FrameBuffer(WATCHDOG_LIMITS.frameBytes);
    socket.on("data", (chunk: Buffer) => {
      let incoming: Buffer[];
      try {
        incoming = frames.push(chunk);
      } catch {
        // Framing violation. There is no recovery that keeps the peer's identity trustworthy.
        socket.destroy();
        return;
      }
      for (const frame of incoming) {
        try {
          const reply = handle(options, decodeWatchdogFrame(frame));
          if (reply !== null) socket.write(encodeWatchdogFrame(reply));
        } catch (error) {
          // A message that cannot be handled is answered, not ignored: silence would leave the
          // supervisor waiting for a reply until its own deadline, which looks like a hang.
          socket.write(encodeWatchdogFrame({
            kind: "ERROR",
            detail: error instanceof Error ? error.message : "unhandled",
          }));
        }
      }
    });
    socket.on("close", () => connections.delete(socket));
    socket.on("error", () => connections.delete(socket));
    // A control peer that stops reading must not hold a server-side buffer open forever.
    socket.setTimeout(WATCHDOG_LIMITS.requestTimeoutMs * 10, () => socket.destroy());
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.socketPath, () => {
      server.removeListener("error", reject);
      // Tighten the mode before accepting: the listener exists but no peer can connect until the
      // event loop turns, so this closes the window in practice as well as in principle.
      chmodSync(options.socketPath, 0o600);
      resolve();
    });
  });

  // The independent timer. `unref` is deliberately not used: this interval is the reason the
  // process stays alive when nothing is connected, and a watchdog that exits because it is idle
  // is a watchdog that is not watching.
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
    if (!result.containerPresent && result.populated === false) {
      options.log?.(`terminated ${execution.executionId}`);
    } else {
      options.log?.(`termination unresolved for ${execution.executionId}: ${result.detail}`);
    }
  }
}

/** Route one decoded message. Returns the reply, or null when no reply is owed. */
function handle(options: WatchdogServerOptions, message: unknown): unknown {
  if (typeof message !== "object" || message === null) throw new Error("the message was not an object");
  const kind = (message as { kind?: unknown }).kind;

  switch (kind) {
    case "HELLO":
      return options.watchdog.hello();
    case "ARM_REQ": {
      const request: ArmRequest = assertArmRequest(message);
      return options.watchdog.arm(request);
    }
    case "HEARTBEAT": {
      const beat = message as Heartbeat;
      const result = options.watchdog.heartbeat(beat);
      return result.ok ? { kind: "HEARTBEAT_ACK" } : { kind: "ERROR", code: result.code };
    }
    case "DISARM_REQ": {
      const record = message as { context?: unknown; messageId?: unknown; sequence?: unknown };
      if (typeof record.messageId !== "string" || !/^[a-f0-9]{16,64}$/u.test(record.messageId)) {
        throw new Error("the disarm message id is not acceptable");
      }
      if (typeof record.sequence !== "number" || !Number.isSafeInteger(record.sequence)) {
        throw new Error("the disarm sequence is not an integer");
      }
      const context = assertTerminalContext(record.context, "disarm context");
      return options.watchdog.disarm(context, record.messageId, record.sequence);
    }
    case "STATE":
      return { kind: "STATE_ACK", executionId: (message as { executionId?: string }).executionId, ...options.watchdog.state(String((message as { executionId?: string }).executionId)) };
    default:
      throw new Error(`unrecognised message kind ${String(kind)}`);
  }
}

export { MessageIdWindow };
