/**
 * Shared harness for the R7D.1 watchdog tests (Continuation D1).
 *
 * ## Why a shared harness
 *
 * The watchdog now requires a durable store, a host clock and a shared secret. Constructing those
 * by hand in every test would mean every test could get durability subtly wrong, and a test that
 * accidentally omits the store would pass against a code path production never uses. One
 * construction here, used everywhere, keeps the tests honest about what they exercise.
 *
 * ## What is real and what is injected
 *
 * Real in every test that uses this: the durable store (a temporary directory, real fsync), the
 * HMAC primitives, the state machine, the transcript construction.
 *
 * Injected: the clock's `nowMs` (so a deadline can be advanced without waiting), host verification
 * (this sandbox has no writable cgroup hierarchy), and the Docker operations.
 */

import { mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { Watchdog, type HostVerification, type WatchdogIdentity } from "../../src/lib/execution/watchdog";
import { WatchdogStore } from "../../src/lib/execution/watchdog-store";
import { type HostClock } from "../../src/lib/execution/host-clock";
import { readBootId, readProcessStartTimeTicks } from "../../src/lib/execution/host-facts";
import { containerNameFor } from "../../src/lib/execution/ownership-journal";
import type { ArmRequest } from "../../src/lib/execution/watchdog-protocol";
import type { TerminalRequest } from "../../src/lib/execution/terminal-auth";
import { pinCgroup } from "../../src/lib/execution/cgroup-pin";

export const BOOT = readBootId();
export const SUPERVISOR = "sv-0123456789ab";
export const WATCHDOG_INSTANCE = "wd-0123456789ab";
export const IMAGE_DIGEST = `sha256:${"d".repeat(64)}`;

/** A clock the test can advance. The real clock reads `/proc/uptime`; this one does not move. */
export type ControllableClock = HostClock & { advance: (deltaMs: number) => void; set: (value: number) => void };

export function makeClock(bootId: string = BOOT, startMs = 10_000): ControllableClock {
  let now = startMs;
  return {
    bootId,
    nowMs: () => now,
    advance: (deltaMs: number) => { now += deltaMs; },
    set: (value: number) => { now = value; },
  };
}

/** A verification answer that reports a verified host. Injected, because no cgroup is writable here. */
export function verifiedHost(overrides: Partial<Extract<HostVerification, { ok: true }>> = {}): HostVerification {
  return {
    ok: true,
    dirInode: 4_001,
    eventsInode: 4_002,
    killInode: 4_003,
    procsInode: 4_004,
    device: "0:25",
    bootId: BOOT,
    ...overrides,
  };
}

/** The cgroup path a conforming arm would name, derived from the execution id. */
export function cgroupPathFor(executionId: string, mountPath = "/sys/fs/cgroup"): string {
  return `${mountPath}/dip-executor.slice/${containerNameFor(executionId)}`;
}

export function armRequest(executionId: string, overrides: Partial<ArmRequest> = {}): ArmRequest {
  return {
    kind: "ARM_REQ",
    messageId: randomBytes(8).toString("hex"),
    sequence: 1,
    executionId,
    requestId: randomBytes(8).toString("hex"),
    operation: "fill",
    supervisorInstance: SUPERVISOR,
    bootId: BOOT,
    containerId: "c".repeat(64),
    containerName: containerNameFor(executionId),
    imageDigest: IMAGE_DIGEST,
    profileId: "synthetic-v1",
    initPid: 4_242,
    initStartTimeTicks: 100,
    cgroupPath: cgroupPathFor(executionId),
    deadlineMs: 20_000,
    startedMonotonicMs: 0,
    ...overrides,
  };
}

/** A terminal context that describes a committed execution. */
export function terminalRequest(executionId: string, overrides: Partial<TerminalRequest> = {}): TerminalRequest {
  return {
    executionId,
    requestId: randomBytes(8).toString("hex"),
    operation: "fill",
    resultDigest: "e".repeat(64),
    resultBytes: 1_024,
    metaBytes: 128,
    containerId: "c".repeat(64),
    containerName: containerNameFor(executionId),
    containerRemoved: true,
    outcome: "committed",
    watchdogInstance: WATCHDOG_INSTANCE,
    supervisorInstance: SUPERVISOR,
    bootId: BOOT,
    nonce: randomBytes(32).toString("hex").slice(0, 16),
    concludedMonotonicMs: 10_500,
    ...overrides,
  };
}

export type Harness = {
  watchdog: Watchdog;
  clock: ControllableClock;
  store: WatchdogStore;
  stateDir: string;
  secret: Buffer;
  cleanup: () => void;
  /** Rebuild a watchdog over the same store, as a restart would. */
  restart: (options?: { bootId?: string; verification?: HostVerification; verifyHost?: (r: ArmRequest, b: string) => HostVerification }) => Harness;
};

export type HarnessOptions = {
  /** What host verification should answer. Defaults to a verified host. */
  verification?: HostVerification | ((request: ArmRequest) => HostVerification);
  /** Whether the daemon reports the container present. */
  containerPresent?: boolean;
  /** Whether a kill attempt is accepted. */
  killAccepted?: boolean;
  /** Inject a failing store write, to prove a failed persist produces no ACK. */
  failStoreWrites?: boolean;
  bootId?: string;
  /** Reuse an existing state directory, for restart tests. */
  stateDir?: string;
  /** Start from an existing clock, so a restart shares the timeline. */
  clock?: ControllableClock;
  /**
   * Use the real pinning implementation. Off by default because this sandbox has no writable
   * cgroup hierarchy; a test that needs real pinning builds its own fixture and passes `pinFd`.
   */
  realPin?: boolean;
  /** Pin descriptors taken from a real fixture directory, for tests that need a real pin. */
  pinFd?: (input: { cgroupPath: string; mountPath: string }) => ReturnType<typeof pinCgroup>;
  /**
   * Build a real (but non-cgroup) directory tree and pin through it, so the termination path can
   * observe `populated 0` and an empty `cgroup.procs` for real. This is what a *granted* disarm
   * requires: the injected pin holds no descriptors and can never confirm termination.
   *
   * The tree is a real filesystem tree under a temporary directory. It is **not** a cgroup: the
   * kernel does not own these files, so this proves the descriptor logic, not cgroup enforcement.
   */
  liveTree?: { populated?: boolean };
};

/** Build a watchdog with a real store, a controllable clock and injected host/Docker answers. */
export function makeWatchdog(options: HarnessOptions = {}): Harness {
  const stateDir = options.stateDir ?? mkdtempSync(join(tmpdir(), "dip-wd-store-"));
  const trees = options.liveTree === undefined ? null : makeLiveTrees(options.liveTree.populated ?? false);
  const clock = options.clock ?? makeClock(options.bootId ?? BOOT);
  const secret = randomBytes(32);
  const bootId = options.bootId ?? BOOT;

  const store = new WatchdogStore(join(stateDir, "records"), options.failStoreWrites === true
    ? { fsync: () => { throw new Error("injected fsync failure"); } }
    : {});
  store.init();

  const verification = options.verification ?? verifiedHost();
  const declaredVerify = typeof verification === "function" ? verification : () => verification;
  // With a live tree the verification must report the tree's *real* inodes, because `arm` compares
  // them against the pin. A fabricated identity would be refused, correctly, as a mismatch.
  const verifyHost = trees === null
    ? declaredVerify
    : (request: ArmRequest) => trees.identityOf(request.cgroupPath);

  const identity: WatchdogIdentity = {
    instance: WATCHDOG_INSTANCE,
    bootId,
    pid: process.pid,
    pidStartTimeTicks: readProcessStartTimeTicks(process.pid),
    startedMonotonicMs: clock.nowMs(),
  };

  const watchdog = new Watchdog({
    identity,
    clock,
    secret,
    store,
    verifyHost,
    // A pin that reports the injected verification's inodes and holds no descriptors. This is the
    // mocked-cgroup path; `realPin` exists so a test can substitute the real implementation.
    pin: options.pinFd ?? (trees !== null
      ? (input) => trees.pin(input.cgroupPath)
      : (options.realPin === true ? undefined : () => ({
      ok: true as const,
      pin: {
        dirFd: -1,
        dirDevice: 0,
        dirInode: (verification as Extract<HostVerification, { ok: true }>).dirInode ?? 4_001,
        pinnedPath: "/injected",
        files: {
          "cgroup.kill": { name: "cgroup.kill" as const, fd: -1, device: 0, inode: (verification as Extract<HostVerification, { ok: true }>).killInode ?? 4_003, resolvedPath: "" },
          "cgroup.events": { name: "cgroup.events" as const, fd: -1, device: 0, inode: (verification as Extract<HostVerification, { ok: true }>).eventsInode ?? 4_002, resolvedPath: "" },
          "cgroup.procs": { name: "cgroup.procs" as const, fd: -1, device: 0, inode: (verification as Extract<HostVerification, { ok: true }>).procsInode ?? 4_004, resolvedPath: "" },
        },
      },
    }))),
    killContainer: async () => ({ ok: options.killAccepted ?? true, detail: "injected" }),
    // `present: false` is a positive not-found. `present: true` covers both "exists" and
    // "unreadable", which is deliberate: an outage is not absence.
    inspectContainer: async () => ({ present: options.containerPresent ?? false, detail: "injected" }),
  });

  return {
    watchdog,
    clock,
    store,
    stateDir,
    secret,
    cleanup: () => {
      watchdog.closeAll();
      rmSync(stateDir, { recursive: true, force: true });
      trees?.cleanup();
    },
    restart: (restartOptions = {}) => makeWatchdog({
      ...options,
      ...restartOptions,
      stateDir,
      clock,
    }),
  };
}

/**
 * Arm an execution and assert it was accepted.
 *
 * Returns the ack so a test that cares about the observed inodes can assert on them, and fails
 * loudly when the arm was denied — a test that silently proceeds after a denial proves nothing
 * about the state it then inspects.
 */
export function armAndAssert(harness: Harness, executionId: string, overrides: Partial<ArmRequest> = {}): void {
  const answer = harness.watchdog.arm(armRequest(executionId, overrides));
  if (answer.kind !== "ARM_ACK") {
    throw new Error(`the arm was denied: ${answer.code}`);
  }
}

/**
 * Real directories shaped like cgroup files, one per execution id, under a temporary mount root.
 *
 * Deliberately a real filesystem: the descriptor pinning this exercises opens real descriptors and
 * reads real files. What it does not do is involve the kernel cgroup controller, so a 
 * written here is a fixture value rather than a kernel statement. Tests using it are labelled
 * mocked for exactly that reason.
 */
function makeLiveTrees(populated: boolean): {
  pin: (cgroupPath: string) => ReturnType<typeof pinCgroup>;
  identityOf: (cgroupPath: string) => HostVerification;
  cleanup: () => void;
} {
  const mount = mkdtempSync(join(tmpdir(), "dip-live-"));
  const paths = new Map<string, string>();

  const ensure = (cgroupPath: string): string => {
    const leaf = cgroupPath.split("/").pop() ?? "unknown";
    const existing = paths.get(leaf);
    if (existing !== undefined) return existing;
    const dir = join(mount, "dip-executor.slice", leaf);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "cgroup.kill"), "");
    writeFileSync(join(dir, "cgroup.events"), `populated ${populated ? 1 : 0}
frozen 0
`);
    writeFileSync(join(dir, "cgroup.procs"), "");
    paths.set(leaf, dir);
    return dir;
  };

  return {
    pin: (cgroupPath: string) => pinCgroup({ cgroupPath: ensure(cgroupPath), mountPath: mount }),
    identityOf: (cgroupPath: string) => {
      const dir = ensure(cgroupPath);
      const dirStat = statSync(dir);
      return {
        ok: true,
        dirInode: dirStat.ino,
        eventsInode: statSync(join(dir, "cgroup.events")).ino,
        killInode: statSync(join(dir, "cgroup.kill")).ino,
        procsInode: statSync(join(dir, "cgroup.procs")).ino,
        device: `${dirStat.dev >> 8}:${dirStat.dev & 0xff}`,
        bootId: BOOT,
      };
    },
    cleanup: () => rmSync(mount, { recursive: true, force: true }),
  };
}
