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

import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { Watchdog, type HostVerification, type WatchdogIdentity } from "../../src/lib/execution/watchdog";
import { dedicatedSubtreeFor, expectedCgroupRelative } from "../../src/lib/execution/docker-lifecycle";
import { WatchdogStore } from "../../src/lib/execution/watchdog-store";
import { type HostClock } from "../../src/lib/execution/host-clock";
import { readBootId, readProcessStartTimeTicks } from "../../src/lib/execution/host-facts";
import { containerNameFor } from "../../src/lib/execution/ownership-journal";
import type { ArmRequest } from "../../src/lib/execution/watchdog-protocol";
import type { TerminalRequest } from "../../src/lib/execution/terminal-auth";
import { pinCgroup } from "../../src/lib/execution/cgroup-pin";
import type { ContainerObservation, ExpectedOwnership } from "../../src/lib/execution/container-identity";
import type { TrustedIntent } from "../../src/lib/execution/watchdog";

export const BOOT = readBootId();
/** The mount a record names. Fixture-backed tests report membership under this prefix. */
export const VIRTUAL_CGROUP_MOUNT = "/sys/fs/cgroup";
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

/**
 * The cgroup path a conforming arm would name.
 *
 * The documented systemd layout: the daemon names the container's cgroup after the *container id*
 * as a transient scope inside the dedicated slice. A leaf named after the container *name* is
 * matched by no driver, so a fixture that used one was testing a layout that cannot exist.
 */
/**
 * The cgroup driver this harness models.
 *
 * The fixture builds a **flat** tree — `dip-executor.slice/<leaf>` — which is what the `cgroupfs`
 * driver produces. It does not model systemd's nesting (`dip.slice/dip-executor.slice/...`), and
 * saying so explicitly is the point: the two layouts are different, so a fixture that stayed silent
 * would be silently asserting the wrong one for whichever driver the production default happened
 * to be.
 */
export const FIXTURE_CGROUP_DRIVER = "cgroupfs" as const;

/** The subtree the fixture's trees live in, relative to the mount. */
export const FIXTURE_SUBTREE = dedicatedSubtreeFor(FIXTURE_CGROUP_DRIVER);

export function cgroupPathFor(containerId: string, mountPath = "/sys/fs/cgroup"): string {
  return `${mountPath}/${expectedCgroupRelative(FIXTURE_CGROUP_DRIVER, containerId)}`;
}

/** The container id `armRequest` uses by default. */
export const DEFAULT_CONTAINER_ID = "c".repeat(64);

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
    containerId: DEFAULT_CONTAINER_ID,
    containerName: containerNameFor(executionId),
    imageDigest: IMAGE_DIGEST,
    profileId: "synthetic-v1",
    initPid: 4_242,
    initStartTimeTicks: 100,
    cgroupPath: cgroupPathFor(DEFAULT_CONTAINER_ID),
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
    containerId: DEFAULT_CONTAINER_ID,
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
  /**
   * The cgroup mount this harness's executions are recorded under.
   *
   * The real path when no fixture tree is used; the fixture's temporary root otherwise. It exists
   * because a fixture tree is not under `/sys/fs/cgroup`, and a record that named the real mount
   * while the descriptors pointed at `/tmp` would fail its own membership check — correctly, but
   * for a reason that has nothing to do with what the test meant to exercise.
   */
  cgroupMount: () => string;
  /**
   * Report the container as removed from now on.
   *
   * This models what actually happens before a legitimate grant: the container is present when the
   * execution is armed, and the supervisor removes it once the work is committed. A grant cannot be
   * minted while the container still exists, so a test that wants one has to say when it went away.
   */
  removeContainer: () => void;
  clock: ControllableClock;
  store: WatchdogStore;
  stateDir: string;
  secret: Buffer;
  cleanup: () => void;
  /** Rebuild a watchdog over the same store, as a restart would. */
  /**
   * Rebuild a watchdog over the same store and clock, as a restart would.
   *
   * Takes the full option set: a restarted process observes a host that may have changed while it
   * was down (an unavailable daemon, a removed container), and a restart test needs to say so.
   */
  restart: (options?: HarnessOptions) => Harness;
};

export type HarnessOptions = {
  /** What host verification should answer. Defaults to a verified host. */
  verification?: HostVerification | ((request: ArmRequest) => HostVerification);
  /**
   * Whether the daemon reports the container present.
   *
   * Defaults to present, because arming now requires positive ownership (WD-F04). Set `false` to
   * model a container the daemon no longer knows about at every moment.
   */
  containerPresent?: boolean;
  /**
   * Model the lifecycle rather than a constant: present while the execution is running, absent once
   * the container has been removed. This is the normal shape of a completion, and it is what a
   * granted disarm requires — absence at arm time would refuse the arm, absence at completion time
   * is the evidence.
   */
  containerRemovedAfterTermination?: boolean;
  /** Present at arm time, then absent once the harness is told the container was removed. */
  observeLifecycle?: boolean;
  /**
   * The supervisor's trusted intent.
   *
   * D2-F03 makes this mandatory for an arm: the watchdog's own record cannot corroborate itself, so
   * every arm is checked against the supervisor's independently written intent. The harness supplies
   * one that matches `armRequest` by default, because that is the normal case — a supervisor that
   * recorded its intent and then created the container it armed against. A test that exercises the
   * refusal (no journal, unreadable journal, a disagreeing intent) sets this explicitly.
   */
  readIntent?: (executionId: string) => TrustedIntent | null;
  /**
   * Model a watchdog started without the supervisor's journal.
   *
   * D2-F03: this must refuse every arm. It is a separate flag rather than passing `readIntent:
   * undefined`, which is indistinguishable from omitting the option.
   */
  noJournal?: boolean;
  /**
   * Remove one container by exact id (D2-F04).
   *
   * Absent by default: the metadata debt then simply stays owed, which is what most tests want. A
   * test about metadata removal supplies this and asserts on the id it receives.
   */
  removeContainer?: (containerId: string) => Promise<{ ok: boolean; detail: string }>;
  /** Whether a kill attempt is accepted. */
  killAccepted?: boolean;
  /** Inject a failing store write, to prove a failed persist produces no ACK. */
  failStoreWrites?: boolean;
  /**
   * The daemon's answer, as the closed observation vocabulary. Absent means the container is
   * positively absent, which is what a successful completion needs.
   */
  observation?: (expected: ExpectedOwnership) => ContainerObservation;
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

  // Whether a kill has been accepted. Drives `containerRemovedAfterTermination`.
  let killedOnce = false;

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
    // A fixture tree is not under the real cgroup2 mount, so both the mount and the membership
    // reading must come from the fixture. This is the mocked-cgroup path made explicit: the code
    // under test is unchanged, the host it is told about is synthetic.
    // The virtual mount, not the fixture root: records name a production path, and membership is
    // reported in the same terms. The descriptors still come from the fixture directory.
    cgroupMount: trees === null ? undefined : () => VIRTUAL_CGROUP_MOUNT,
    // The fixture's trees are flat, so the watchdog is told the driver that produces flat trees.
    // Leaving this to the production default would make every arm on this harness fail ownership,
    // for a reason that has nothing to do with what the test is about.
    cgroupDriver: trees === null ? undefined : () => FIXTURE_CGROUP_DRIVER,
    actualCgroupPath: trees === null ? undefined : (_pid, mountPath) => trees.actualFor(mountPath),
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
    // D2-F03: an intent that matches the arm request the harness builds, so the corroboration
    // succeeds in the ordinary case. `noJournal` removes it entirely, which must refuse every arm.
    removeContainer: options.removeContainer,
    readIntent: options.noJournal === true
      ? undefined
      : (options.readIntent ?? ((executionId: string): TrustedIntent => ({
        executionId,
        bootId,
        supervisorInstance: SUPERVISOR,
        containerName: containerNameFor(executionId),
        containerId: DEFAULT_CONTAINER_ID,
        imageDigest: IMAGE_DIGEST,
        profileId: "synthetic-v1",
      }))),
    killContainer: async () => {
      if (options.killAccepted !== false) killedOnce = true;
      return { ok: options.killAccepted ?? true, detail: "injected" };
    },
    // The observation is injected as the closed vocabulary it now is, so a test names exactly the
    // daemon answer it means to exercise: absent, present, foreign, unavailable, denied, ambiguous.
    // The default is a container that exists and is this execution's: that is what a normal arm
    // sees. A test that wants the daemon to report absence supplies `observation`, because absence
    // is now a *decision* about ownership (WD-F04), not an incidental default.
    observeContainer: async (expected) => {
      if (options.observation !== undefined) return options.observation(expected);

      const present = (): ContainerObservation => ({
        state: "present",
        containerId: expected.containerId,
        labels: {},
        detail: "injected present",
      });

      // A fixture tree models a container that exists until its cgroup is killed. Once `cgroup.kill`
      // has been written through the pinned descriptor, the container is gone — that is the
      // consequence the fixture is standing in for.
      if (trees !== null && trees.killWasWritten()) {
        return { state: "absent", detail: "injected: removed once cgroup.kill was written" };
      }
      if (options.containerRemovedAfterTermination === true) {
        return killedOnce
          ? { state: "absent", detail: "injected: removed after the kill" }
          : present();
      }
      if (options.observeLifecycle === true) {
        return killedOnce
          ? { state: "absent", detail: "injected: removed by the supervisor" }
          : present();
      }
      if (options.containerPresent === false) return { state: "absent", detail: "injected absent" };
      return present();
    },
  });

  return {
    watchdog,
    // The virtual mount the records name. A record's cgroup path is validated against
    // `/sys/fs/cgroup/dip-executor.slice/...`, so the reported mount must be that prefix for a
    // fixture tree even though the descriptors come from a temporary directory.
    cgroupMount: () => VIRTUAL_CGROUP_MOUNT,
    removeContainer: () => { killedOnce = true; },
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
export async function armAndAssert(harness: Harness, executionId: string, overrides: Partial<ArmRequest> = {}): Promise<void> {
  // The record must name the mount the descriptors were taken from. Only the mount prefix is
  // rewritten; the leaf, which carries the ownership meaning, is the test's to choose.
  const cgroupPath = overrides.cgroupPath
    ?? cgroupPathFor(overrides.containerId ?? DEFAULT_CONTAINER_ID, harness.cgroupMount());
  const answer = await harness.watchdog.arm(armRequest(executionId, { ...overrides, cgroupPath }));
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
  killWasWritten: () => boolean;
  mountPath: () => string;
  /** The cgroup the "process" is in: the first execution's tree, as `/proc/<pid>/cgroup` would say. */
  actualFor: (mountPath: string) => { path: string; relative: string };
  cleanup: () => void;
} {
  const mount = mkdtempSync(join(tmpdir(), "dip-live-"));
  const paths = new Map<string, string>();

  const ensure = (cgroupPath: string): string => {
    // The path is the virtual `/sys/fs/cgroup/dip-executor.slice/<leaf>`; the leaf is what maps onto
    // this fixture's real directory.
    const leaf = cgroupPath.split("/").pop() ?? "unknown";
    const existing = paths.get(leaf);
    if (existing !== undefined) return existing;
    const dir = join(mount, FIXTURE_SUBTREE, leaf);
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
    pin: (cgroupPath: string) => pinCgroup({ cgroupPath: ensure(cgroupPath), mountPath: mount, subtree: FIXTURE_SUBTREE }),
    /** True once a kill has been written through a pinned descriptor for any execution. */
    killWasWritten: () => [...paths.values()].some((dir) => readFileSync(join(dir, "cgroup.kill"), "utf8") !== ""),
    mountPath: () => mount,
    actualFor: (mountPath: string) => {
      // Only one execution is normally live per fixture. When several are, the first is reported:
      // a test that needs two distinct memberships supplies `actualCgroupPath` itself.
      //
      // The path is expressed under the mount the watchdog was told about, not under this
      // fixture's real temporary root: the virtual naming is what a record carries.
      const leaf = [...paths.entries()][0]?.[0] ?? "absent";
      const relative = `/${FIXTURE_SUBTREE}/${leaf}`;
      return { path: `${mountPath}${relative}`, relative };
    },
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
