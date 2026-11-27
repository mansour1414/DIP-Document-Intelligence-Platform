/**
 * Watchdog entry point (R7D.1 §4).
 *
 * A separate OS process, deliberately. It shares no event loop, no memory and no file descriptors
 * with the supervisor: its purpose is to act when the supervisor cannot.
 *
 * Run with `tsx workers/watchdog.ts`, the same way `workers/document-worker.ts` runs, so it uses
 * the repository's existing TypeScript toolchain instead of requiring a build that git ignores.
 *
 * ## Configuration
 *
 * Everything comes from the environment, because this process is started by an init system or by
 * an operator, not imported by a test. Missing configuration is fatal at start-up rather than at
 * the first execution: a watchdog that discovers it has no secret when a deadline fires has
 * already failed.
 *
 * ```
 *   DIP_WATCHDOG_SOCKET   /run/dip/watchdog.sock
 *   DIP_WATCHDOG_SECRET   >= 32 bytes, shared with the supervisor
 *   DIP_WATCHDOG_STATE    /var/lib/dip/watchdog
 * ```
 *
 * ## What it does not do
 *
 * It does not create containers, does not read document bytes, and does not know what an
 * execution produced. Its entire vocabulary is identity, deadline, termination.
 */

import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { readBootId, selfStartTimeTicks } from "../src/lib/execution/host-facts";
import { Watchdog, newWatchdogIdentity } from "../src/lib/execution/watchdog";
import { startWatchdogServer } from "../src/lib/execution/watchdog-server";
import { killContainerAsync, inspectContainerAsync } from "../src/lib/execution/docker-lifecycle";

const required = (name: string): string => {
  const value = process.env[name];
  if (value === undefined || value === "") {
    process.stderr.write(`FATAL: ${name} is not set\n`);
    process.exit(1);
  }
  return value;
};

const emit = (event: Record<string, unknown>): void => {
  // One JSON object per line: an init system captures it, a test reads it, and neither has to
  // parse a human-readable log to learn that a termination happened.
  process.stdout.write(`${JSON.stringify(event)}\n`);
};

function main(): void {
  const socketPath = required("DIP_WATCHDOG_SOCKET");
  const secret = Buffer.from(required("DIP_WATCHDOG_SECRET"), "utf8");
  if (secret.byteLength < 32) {
    process.stderr.write("FATAL: DIP_WATCHDOG_SECRET must be at least 32 bytes\n");
    process.exit(1);
  }
  const stateDir = required("DIP_WATCHDOG_STATE");
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  mkdirSync(dirname(socketPath), { recursive: true, mode: 0o700 });

  const monotonic = (): number => Math.round(performance.now());
  const identity = newWatchdogIdentity(monotonic, selfStartTimeTicks(), readBootId());
  const watchdog = new Watchdog({
    identity,
    secret,
    monotonicMs: monotonic,
    // The daemon is asked by exact id and nothing else. No selector, no prefix, no prune.
    killContainer: async (containerId) => {
      const outcome = await killContainerAsync(containerId);
      return outcome.ok ? { ok: true, detail: "killed" } : { ok: false, detail: outcome.fault };
    },
    inspectContainer: async (containerId) => {
      const outcome = await inspectContainerAsync(containerId);
      // Ambiguity is not absence. An unreadable daemon must not be read as "the container is gone",
      // because that is the answer that stops the watchdog from retrying.
      if (!outcome.ok) return { present: true, detail: `unresolved: ${outcome.fault}` };
      return { present: true, detail: "present" };
    },
  });

  startWatchdogServer({
    socketPath,
    watchdog,
    onTermination: (result) => emit({ event: "termination", ...result }),
    log: (line) => emit({ event: "log", line }),
  }).then((server) => {
    emit({
      event: "ready",
      instance: identity.instance,
      bootId: identity.bootId,
      pid: identity.pid,
      pidStartTimeTicks: identity.pidStartTimeTicks,
      socket: socketPath,
    });

    const shutdown = async (signal: string): Promise<void> => {
      emit({ event: "shutdown", signal, outstanding: watchdog.outstanding() });
      await server.stop();
      // A watchdog that exits with executions still armed leaves containers running with nobody
      // enforcing their deadlines. Exit non-zero so the init system restarts it and it reconciles.
      process.exit(watchdog.outstanding().length === 0 ? 0 : 2);
    };
    process.on("SIGTERM", () => { void shutdown("SIGTERM"); });
    process.on("SIGINT", () => { void shutdown("SIGINT"); });
  }).catch((error: unknown) => {
    process.stderr.write(`FATAL: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  });
}

main();
