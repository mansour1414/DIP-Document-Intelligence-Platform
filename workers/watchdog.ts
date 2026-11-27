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
import { OwnershipJournal } from "../src/lib/execution/ownership-journal";
import { makeHostClock, readUptimeMs } from "../src/lib/execution/host-clock";
import { Watchdog, newWatchdogIdentity } from "../src/lib/execution/watchdog";
import { WatchdogStore } from "../src/lib/execution/watchdog-store";
import { startWatchdogServer } from "../src/lib/execution/watchdog-server";
import { killContainerAsync, inspectContainerAsync, removeContainerAsync } from "../src/lib/execution/docker-lifecycle";
import { classifyInspect } from "../src/lib/execution/container-identity";

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

/**
 * The seams a watchdog process needs from its host.
 *
 * The production entrypoint supplies none of them, so every fact is read from the real kernel. A
 * test entrypoint may supply the cgroup fixtures it needs, as code, not as environment data.
 */
export type WatchdogSeams = {
  cgroupMount?: () => string | null;
  /** The `major:minor` device of an injected mount. Required with `cgroupMount`. */
  cgroupMountDevice?: () => string | null;
  /**
   * The daemon's cgroup driver.
   *
   * Exists as a seam because the two driver layouts place the container in different trees, and a
   * fixture that models one of them must say which. The production default lives in the
   * `Watchdog` options, not here, so an unset seam means "whatever production does".
   */
  cgroupDriver?: () => "systemd" | "cgroupfs";
  actualCgroupPath?: (pid: number, mountPath: string) => { path: string; relative: string } | null;
};

export function main(seams: WatchdogSeams = {}): void {
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
  // ## D2-F03: the journal is required, not optional
  //
  // It used to be optional: without it the watchdog relied on its own record and live observations.
  // That is a weaker position than it looks, because the record is written by the party the
  // observation is meant to check — one process agreeing with itself is not corroboration. An arm
  // is now refused unless the supervisor's independently written intent can be read and matches on
  // exact identity, so a watchdog started without a journal would refuse every arm. Starting is
  // therefore a start-up failure instead: failing at boot is legible, and failing on every request
  // is not.
  const journalRoot = required("DIP_WATCHDOG_JOURNAL");
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

  // A read-only view of the supervisor's journal: never bound, never written, and never
  // authoritative — it is the second statement of intent that the daemon's answer is checked
  // against. An unreadable intent is treated as "no corroboration" by the watchdog, which refuses
  // the arm; it is not a reason to stop watching executions already in flight.
  let journal: OwnershipJournal;
  try {
    journal = new OwnershipJournal(journalRoot);
  } catch (error) {
    process.stderr.write(`FATAL: the supervisor journal at ${journalRoot} is not usable: ${error instanceof Error ? error.message : String(error)}\n`);
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
    // WD-F01: classify, do not coerce. `classifyInspect` is the only place the daemon's answer is
    // turned into a decision, and `NOT_FOUND` is the only branch that yields absence.
    observeContainer: async (expected) => classifyInspect(await inspectContainerAsync(expected.containerId), expected),
    // WD-F04 / D2-F03: the supervisor's own intent. A read failure is "no corroboration", not
    // "corroborated": the caller must not treat an unreadable journal as agreement.
    readIntent: (executionId) => {
      const record = journal.readSupervisor(executionId);
      if (record === null) return null;
      return {
        executionId: record.executionId,
        bootId: record.bootId,
        supervisorInstance: record.supervisorInstance,
        containerName: record.containerName,
        containerId: record.containerId,
        imageDigest: record.imageDigest,
        profileId: record.profileId,
      };
    },
    // D2-F04: removal by exact id, so a stopped-but-present container's metadata can be discharged
    // rather than left owed forever. The id comes from the watchdog's own record.
    // Present only when the entrypoint supplied them.
    ...(seams.cgroupMount === undefined ? {} : { cgroupMount: seams.cgroupMount }),
    ...(seams.cgroupMountDevice === undefined ? {} : { cgroupMountDevice: seams.cgroupMountDevice }),
    ...(seams.cgroupDriver === undefined ? {} : { cgroupDriver: seams.cgroupDriver }),
    ...(seams.actualCgroupPath === undefined ? {} : { actualCgroupPath: seams.actualCgroupPath }),
    removeContainer: async (containerId) => {
      const outcome = await removeContainerAsync(containerId);
      return outcome.ok ? { ok: true, detail: "removed" } : { ok: false, detail: outcome.fault };
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
