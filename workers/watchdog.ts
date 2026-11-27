/**
 * Watchdog entry point (R7D.1 §4; Continuation D1 WD-01, WD-05).
 *
 * A separate OS process, deliberately. It shares no event loop, no memory and no file descriptors
 * with the supervisor: its purpose is to act when the supervisor cannot.
 *
 * ## Start-up order is the requirement
 *
 * ```
 *   create the durable store            ← a failure here is a start-up failure, not a first-request one
 *   recover existing records            ← before the socket listens
 *   refuse readiness if recovery is unresolved
 *   listen
 * ```
 *
 * Reversing recovery and listening would let a client arm a new execution while an unresolved
 * record still refers to a container this process cannot account for.
 *
 * ## Configuration
 *
 * ```
 *   DIP_WATCHDOG_SOCKET   /run/dip/watchdog.sock
 *   DIP_WATCHDOG_SECRET   hex-encoded, >= 32 bytes decoded, shared with the supervisor
 *   DIP_WATCHDOG_STATE    /var/lib/dip/watchdog      (durable records)
 * ```
 *
 * ## What it does not do
 *
 * It does not create containers, does not read document bytes, and does not know what an
 * execution produced. Its entire vocabulary is identity, deadline, termination.
 */

import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { readBootId, selfStartTimeTicks } from "../src/lib/execution/host-facts";
import { makeHostClock, readUptimeMs } from "../src/lib/execution/host-clock";
import { Watchdog, newWatchdogIdentity } from "../src/lib/execution/watchdog";
import { WatchdogStore } from "../src/lib/execution/watchdog-store";
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
  // Hex, not raw text. A shared key has to survive an environment variable, a unit file and a
  // secret store without one of them mangling a byte; and decoding it here means the bytes the
  // supervisor signs with and the bytes this process verifies with are the same bytes rather than
  // the same characters.
  const secretHex = required("DIP_WATCHDOG_SECRET").trim();
  if (!/^(?:[0-9a-fA-F]{2})+$/u.test(secretHex)) {
    process.stderr.write("FATAL: DIP_WATCHDOG_SECRET must be hex-encoded\n");
    process.exit(1);
  }
  const secret = Buffer.from(secretHex, "hex");
  if (secret.byteLength < 32) {
    process.stderr.write("FATAL: DIP_WATCHDOG_SECRET must decode to at least 32 bytes\n");
    process.exit(1);
  }
  const stateDir = required("DIP_WATCHDOG_STATE");
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  mkdirSync(dirname(socketPath), { recursive: true, mode: 0o700 });

  // WD-05: a host-consistent clock, bound to the boot it belongs to. `/proc/uptime` is shared by
  // every process on the host, unlike `performance.now()`, whose origin is this process's start.
  const bootId = readBootId();
  const clock = makeHostClock(bootId);

  // WD-01: the durable store, initialised and fsynced before anything can be armed.
  const store = new WatchdogStore(join(stateDir, "records"));
  try {
    store.init();
  } catch (error) {
    process.stderr.write(`FATAL: the durable store could not be initialised: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }

  const identity = newWatchdogIdentity(() => readUptimeMs(), selfStartTimeTicks(), bootId);
  const watchdog = new Watchdog({
    identity,
    clock,
    secret,
    store,
    // The daemon is asked by exact id and nothing else. No selector, no prefix, no prune.
    killContainer: async (containerId) => {
      const outcome = await killContainerAsync(containerId);
      return outcome.ok ? { ok: true, detail: "killed" } : { ok: false, detail: outcome.fault };
    },
    inspectContainer: async (containerId) => {
      const outcome = await inspectContainerAsync(containerId);
      // Ambiguity is not absence. An unreadable daemon must not be read as "the container is gone",
      // because that is the answer that stops the watchdog from retrying and lets a removal debt
      // be discharged that was never paid.
      if (!outcome.ok) return { present: true, detail: `unresolved: ${outcome.fault}` };
      return { present: true, detail: "present" };
    },
  });

  // WD-01: recovery before readiness.
  let recovery: ReturnType<Watchdog["recover"]>;
  try {
    recovery = watchdog.recover();
  } catch (error) {
    process.stderr.write(`FATAL: recovery failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }
  emit({ event: "recovered", ...recovery });

  if (watchdog.recoveryBlock !== null) {
    // Fail closed. A watchdog with an unresolved record does not know whether a container it is
    // responsible for is still running, so it must not accept new work.
    emit({ event: "recovery-blocked", reason: watchdog.recoveryBlock });
    process.exit(3);
  }

  startWatchdogServer({
    socketPath,
    watchdog,
    secret,
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
      adopted: recovery.adopted,
    });

    const shutdown = async (signal: string): Promise<void> => {
      emit({ event: "shutdown", signal, outstanding: watchdog.outstanding() });
      watchdog.closeAll();
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
