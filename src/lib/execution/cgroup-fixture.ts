/**
 * A filesystem-backed stand-in for the cgroup2 hierarchy (R7D.1 test seam).
 *
 * ## What this is, and what it is not
 *
 * This module exists because the end-to-end harness must run real supervisor and watchdog
 * processes over real sockets on a machine where `/sys/fs/cgroup` is not writable. It provides a
 * directory tree that *behaves* like a cgroup2 tree — `cgroup.kill`, `cgroup.events`,
 * `cgroup.procs`, real inodes, real writes — so that the pinning, identity and termination logic
 * runs unmodified against real descriptors.
 *
 * It is **not** evidence of kernel enforcement. A write to `cgroup.kill` here appends to a file; it
 * does not signal a process tree, and no controller enforces a limit. Every claim about isolation
 * or resource enforcement that depends on this seam is labelled as mocked in the harness and in the
 * report. The production default never imports it: `SupervisorExecution` and `Watchdog` only use it
 * when a test injects it explicitly.
 *
 * ## Why it is a seam and not a mock
 *
 * The alternative — stubbing `pinCgroup` or `verifyArmIdentity` — would have exercised none of the
 * descriptor handling, inode comparison or path replacement logic, which is where the interesting
 * failures are. A real tree with real control files exercises all of it.
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { readProcessStartTimeTicks } from "./host-facts";

/** One carved-out cgroup directory in the fake hierarchy. */
export type FixtureCgroup = {
  /** Absolute path of the directory. */
  path: string;
  /** PIDs listed in `cgroup.procs`, and in `cgroup.events` as the populated count. */
  pids: number[];
};

/**
 * Build a cgroup2-shaped tree under `root`.
 *
 * `root` doubles as the mount point. `findCgroup2Mount` reports it as the mount, so every path the
 * production code composes is consistent with a real hierarchy whose mount happens to live there.
 */
export function createCgroupFixture(root: string): CgroupFixture {
  mkdirSync(root, { recursive: true });
  return new CgroupFixture(root);
}

export class CgroupFixture {
  /** The directory that stands in for the cgroup2 mount point. */
  readonly root: string;

  /** Paths created so far, deepest last, so teardown can be ordered if it ever needs to be. */
  private readonly created: string[] = [];

  constructor(root: string) {
    this.root = root;
  }

  /**
   * The mount point, in the shape `findCgroup2Mount` returns.
   *
   * The device is fabricated but stable: it only has to be a value two observations of the same
   * file can agree on, which is what `verifyArmIdentity` compares.
   */
  mount(): { path: string; device: string } {
    return { path: this.root, device: "0:99" };
  }

  /**
   * The relative cgroup path a process would report in `/proc/<pid>/cgroup`.
   *
   * The supervisor composes the absolute path as `<mount><relative>`, so this is the value that
   * makes a real child process look like it is inside the fixture.
   */
  relativeFor(containerId: string): string {
    return `${DIP_FIXTURE_SUBTREE}/${containerId}`;
  }

  /**
   * Create the cgroup for a container and populate it.
   *
   * The leaf is the container id, which is what the cgroupfs driver produces, and the parent is
   * the dedicated subtree the watchdog verifies against. Both are real production conventions, so
   * the production path checks are exercised rather than bypassed.
   */
  createContainerCgroup(containerId: string, pids: number[]): FixtureCgroup {
    const dir = join(this.root, "dip-executor.slice", containerId);
    mkdirSync(dir, { recursive: true });
    this.created.push(dir);
    this.writeProcs(dir, pids);
    // A freshly populated cgroup: the kernel reports it as populated until the last task leaves.
    writeFileSync(join(dir, "cgroup.events"), "populated 1\nfrozen 0\n");
    writeFileSync(join(dir, "cgroup.kill"), "");
    return { path: dir, pids };
  }

  /**
   * Record a kill and empty the cgroup, in the order a real kill produces.
   *
   * The harness calls this when the watchdog's `cgroup.kill` write is observed. It is deliberately
   * *not* hooked into the write itself: a test that proves termination must see the write happen
   * and then observe its effect, exactly as a real host would.
   */
  applyKill(cgroupPath: string): void {
    writeFileSync(join(cgroupPath, "cgroup.kill"), "1\n");
    writeFileSync(join(cgroupPath, "cgroup.procs"), "");
    writeFileSync(join(cgroupPath, "cgroup.events"), "populated 0\nfrozen 0\n");
  }

  /** Move a process out of the cgroup, as exiting would. */
  removePid(cgroupPath: string, pid: number): void {
    const file = join(cgroupPath, "cgroup.procs");
    const current = readFileSync(file, "utf8").split("\n").filter((l) => l.trim() !== "");
    this.writeProcs(cgroupPath, current.map(Number).filter((p) => p !== pid));
  }

  /** Whether a path is a live cgroup directory in the fixture. */
  exists(cgroupPath: string): boolean {
    return existsSync(join(cgroupPath, "cgroup.events"));
  }

  /**
   * Whether the watchdog wrote the kill.
   *
   * A written `cgroup.kill` is the only positive evidence of a pinned-cgroup termination in this
   * harness, which is why it is a separate observable rather than being folded into `exists`.
   */
  killWasWritten(cgroupPath: string): boolean {
    try {
      return readFileSync(join(cgroupPath, "cgroup.kill"), "utf8").includes("1");
    } catch {
      return false;
    }
  }

  /** Append fresh content to a control file, the way the kernel updates `cgroup.events`. */
  private writeProcs(dir: string, pids: number[]): void {
    writeFileSync(join(dir, "cgroup.procs"), pids.map((p) => `${p}\n`).join(""));
    writeFileSync(join(dir, "cgroup.events"), `populated ${pids.length > 0 ? 1 : 0}\nfrozen 0\n`);
    void appendFileSync;
  }
}

/** The dedicated subtree the watchdog verifies against, restated so the fixture cannot drift. */
export const DIP_FIXTURE_SUBTREE = "dip-executor.slice";

/**
 * Host facts answered from a fixture tree.
 *
 * Only the three facts `SupervisorExecution` consults are redirected; the PID's start time and its
 * liveness remain the real kernel's answer, because those can be read anywhere and mocking them
 * would weaken the identity check rather than relocate its evidence.
 */
export function fixtureHostFacts(root: string): {
  startTimeTicks: (pid: number) => number;
  cgroupMembership: (pid: number) => string | null;
  cgroup2Mount: () => { path: string; device: string } | null;
} {
  const fixture = new CgroupFixture(root);
  return {
    startTimeTicks: readProcessStartTimeTicks,
    // Every process the fixture knows about reports the container cgroup it was placed in. The
    // mapping is registered by the harness through `fixtureMembership`, so a PID the fixture has
    // never seen is reported honestly as unknown rather than given a plausible path.
    cgroupMembership: (pid) => fixtureMembership(root, pid),
    cgroup2Mount: () => fixture.mount(),
  };
}

/**
 * Record which cgroup a PID belongs to in a fixture.
 *
 * Kept as a small file so the *running* supervisor process — which cannot share an object with the
 * test — can answer for a PID the test placed. One line per process.
 */
export function fixtureMembership(root: string, pid: number): string | null {
  try {
    const text = readFileSync(join(root, "membership.map"), "utf8");
    for (const line of text.split("\n")) {
      const [recorded, relative] = line.split(" ");
      if (recorded !== undefined && Number.parseInt(recorded, 10) === pid && relative !== undefined) return relative;
    }
    return null;
  } catch {
    return null;
  }
}

/** Place a PID into a fixture cgroup, from the test process. */
export function recordFixtureMembership(root: string, pid: number, containerId: string): void {
  const relative = `${DIP_FIXTURE_SUBTREE}/${containerId}`;
  const file = join(root, "membership.map");
  let existing: string;
  try {
    existing = readFileSync(file, "utf8");
  } catch {
    existing = "";
  }
  const kept = existing.split("\n").filter((line) => line !== "" && Number.parseInt(line.split(" ")[0] ?? "", 10) !== pid);
  kept.push(`${pid} ${relative}`);
  writeFileSync(file, `${kept.join("\n")}\n`);
}
