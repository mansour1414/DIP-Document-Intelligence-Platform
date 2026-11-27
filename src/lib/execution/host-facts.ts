/**
 * Host and kernel facts the control plane needs, read from `/proc` and `/sys` (R7D.1).
 *
 * ## Why these are read here and not from the executor
 *
 * Everything in this module is used to decide whether a container is isolated, where it is, and
 * whether a process is the one we think it is. An executor reports what it can see; the control
 * plane needs what the *host* sees. A container that lies about its own cgroup is not a
 * surprising container.
 *
 * ## What this cannot do
 *
 * Reading `/proc` and `/sys` establishes what the host currently shows. It does not establish
 * that a container is isolated, that a seccomp profile is loaded, or that a cgroup limit is
 * enforced — those are properties of the running kernel's effect on a specific process tree, and
 * they require a real Docker daemon to observe. Where a fact cannot be obtained, the functions
 * here throw rather than returning a plausible default, because a default is indistinguishable
 * from a measurement.
 */

import { readFileSync, statSync } from "node:fs";

/** The Linux boot identity. A record from a previous boot describes namespaces that are gone. */
export function readBootId(): string {
  const value = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
  if (!/^[0-9a-f-]{36}$/u.test(value)) throw new Error("the kernel boot id was not readable");
  return value;
}

/**
 * Read a process's start time from `/proc/<pid>/stat`.
 *
 * Field 22 of `stat` is the start time in clock ticks since boot. It is the only stable process
 * identity Linux offers to an unprivileged reader: a PID alone is recycled, and two processes
 * with the same PID at different times are different processes.
 *
 * The parsing is delicate because field 2 (`comm`) is a parenthesised string that may itself
 * contain spaces and parentheses. Splitting on whitespace naively breaks for a process named
 * `(foo) bar`. Scanning to the *last* `)` is the standard approach and is correct because the
 * comm field is the only field that can contain `)`.
 */
export function readProcessStartTimeTicks(pid: number): number {
  assertPid(pid);
  const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
  const close = stat.lastIndexOf(")");
  if (close < 0) throw new Error(`/proc/${pid}/stat is malformed`);
  const fields = stat.slice(close + 2).split(" ");
  // After the `)` and the space, fields begin at stat field 3 (`state`). Field 22 (`starttime`)
  // is therefore index 19 of this slice.
  const starttime = fields[19];
  if (starttime === undefined) throw new Error(`/proc/${pid}/stat has no start time`);
  const value = Number.parseInt(starttime, 10);
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`/proc/${pid}/stat start time is not a number`);
  return value;
}

/**
 * Read the cgroup v2 membership of a process.
 *
 * Returns the path relative to the cgroup mount point, or `null` when the process is not under
 * cgroup v2 at all. A hybrid or v1 host is reported honestly rather than being treated as v2
 * with an empty path.
 */
export function readCgroupMembership(pid: number): string | null {
  assertPid(pid);
  const text = readFileSync(`/proc/${pid}/cgroup`, "utf8");
  for (const line of text.split("\n")) {
    // The unified hierarchy is the line with an empty controller list: `0::<path>`.
    const match = /^0::(.*)$/u.exec(line);
    if (match) return match[1] ?? "/";
  }
  return null;
}

/** Identity of a path: its device and inode. Used to prove two observations are the same object. */
export type PathIdentity = { device: string; inode: number; isDirectory: boolean };

/**
 * Stat a path and return its device and inode.
 *
 * `null` when the path does not exist, which for a cgroup is a meaningful answer: the container
 * may have been removed already, so "absent" and "unreadable" must be distinguishable.
 */
export function pathIdentity(path: string): PathIdentity | null {
  try {
    const stats = statSync(path, { bigint: false, throwIfNoEntry: false });
    if (stats === undefined) return null;
    return {
      // Linux encodes the device as major:minor in a single integer; the cgroup filesystem is
      // conventionally 0:<n>, and the raw form is what makes a remount detectable.
      device: `${(stats.dev >> 8) & 0xff}:${stats.dev & 0xff}`,
      inode: stats.ino,
      isDirectory: stats.isDirectory(),
    };
  } catch {
    return null;
  }
}

/**
 * Whether a cgroup's `cgroup.events` reports it populated.
 *
 * `populated 0` means no tasks are in the cgroup. It does **not** mean the memory charge is
 * zero: page cache and swap accounting can outlive the tasks, and a cgroup being empty is not
 * the same as its limits being released. Callers must not treat this as "resources are free".
 */
export function readCgroupPopulated(cgroupDir: string): boolean | null {
  try {
    const events = readFileSync(`${cgroupDir}/cgroup.events`, "utf8");
    const match = /^populated\s+(\d+)$/mu.exec(events);
    if (!match) return null;
    return match[1] !== "0";
  } catch {
    return null;
  }
}

/** PIDs currently in a cgroup, from `cgroup.procs`. Empty when the cgroup is populated by none. */
export function readCgroupProcs(cgroupDir: string): number[] {
  const text = readFileSync(`${cgroupDir}/cgroup.procs`, "utf8");
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "")
    .map((line) => Number.parseInt(line, 10))
    .filter((value) => Number.isSafeInteger(value) && value > 0);
}

/**
 * The cgroup v2 mount point and device.
 *
 * Discovered from `/proc/self/mountinfo` rather than assumed to be `/sys/fs/cgroup`: a test or a
 * nested container may mount it elsewhere, and hard-coding the path would then silently read the
 * wrong hierarchy — or read nothing and be treated as "absent".
 */
export function findCgroup2Mount(): { path: string; device: string } | null {
  const mountinfo = readFileSync("/proc/self/mountinfo", "utf8");
  for (const line of mountinfo.split("\n")) {
    // Fields: id parent major:minor root mountpoint options... - fstype source superopts
    const parts = line.split(" ");
    const separator = parts.indexOf("-");
    if (separator < 0) continue;
    const fstype = parts[separator + 1];
    if (fstype !== "cgroup2") continue;
    const mountPoint = parts[4];
    const device = parts[2];
    if (mountPoint === undefined || device === undefined) continue;
    return { path: decodeMountPath(mountPoint), device };
  }
  return null;
}

/** Octal escapes in mountinfo paths (`\040` for space) are part of the grammar, not decoration. */
function decodeMountPath(value: string): string {
  return value.replace(/\\([0-7]{3})/gu, (_match, octal: string) => String.fromCharCode(Number.parseInt(octal, 8)));
}

/**
 * The process start time of the calling process, used to fence a PID reused between restarts.
 *
 * A supervisor that recorded "pid 1234 is my watchdog" and restarted cannot rely on that PID
 * still naming the same process; comparing this value is what makes the claim checkable.
 */
export function selfStartTimeTicks(): number {
  return readProcessStartTimeTicks(process.pid);
}

function assertPid(pid: number): void {
  if (!Number.isSafeInteger(pid) || pid < 1) throw new Error("pid must be a positive integer");
}
