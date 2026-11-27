/**
 * Descriptor-pinned cgroup control (R7D.1 Continuation D1, WD-03 / WD-06).
 *
 * ## The defect this replaces
 *
 * The previous termination path stat'd `cgroup.kill`, compared the inode, and then called
 * `writeFileSync` on the *path*. Between the check and the write the path can be replaced, and the
 * write then lands on whatever now occupies it. Checking a path and then using the path is not
 * pinning; it is a race with a comment on it.
 *
 * ## What pinning actually is
 *
 * Open the directory once, and reach every control file through `/proc/self/fd/<dirfd>/...`. The
 * descriptor refers to an inode, not to a name, so a rename or replacement of the path does not
 * change what the descriptor reaches. This was verified in this environment before the code was
 * written: with a decoy directory renamed over the pinned path, a write through the descriptor
 * still landed in the original directory and the decoy was untouched. That measurement is the
 * evidence, and the regression test reproduces it.
 *
 * ## What this still does not establish
 *
 * That the kernel honours `cgroup.kill` for the target cgroup, that the cgroup tree is delegated
 * to this watchdog, or that a real container's tasks were actually killed. Those need a real
 * delegated cgroup hierarchy and a real daemon. What is established is that the watchdog writes to
 * the inode it verified, and cannot be redirected to another one.
 *
 * ## Why descriptors are retained
 *
 * The pin is only a pin while it is open. Re-opening `/proc/self/fd/<closed-fd>` is not possible,
 * and re-opening by path reintroduces the race. So the descriptors are held for the execution's
 * lifetime and closed explicitly — on conclusion, or by the operating system if this process dies,
 * which leaves the cgroup to recovery rather than to a half-open handle.
 */

import { closeSync, constants, fstatSync, fsyncSync, openSync, readFileSync, statSync, writeFileSync, readlinkSync } from "node:fs";

/** The control files this module pins. `cgroup.controllers` is deliberately absent: read-only and unrelated. */
export const PINNED_CONTROL_FILES = ["cgroup.kill", "cgroup.events", "cgroup.procs"] as const;
export type PinnedControlFile = (typeof PINNED_CONTROL_FILES)[number];

/** The identity of one open descriptor. Device and inode are what a path can be swapped away from. */
export type PinnedFile = {
  name: PinnedControlFile;
  fd: number;
  device: number;
  inode: number;
  /** The path the descriptor resolves to, read back from `/proc/self/fd/<fd>`, for diagnostics. */
  resolvedPath: string;
};

export type PinnedCgroup = {
  /** The directory descriptor. Every child was opened through it. */
  dirFd: number;
  dirDevice: number;
  dirInode: number;
  /** The absolute path that was pinned, recorded so recovery can compare it later. */
  pinnedPath: string;
  files: Record<PinnedControlFile, PinnedFile>;
};

/** Why a pin could not be established. Closed, because the caller refuses on each. */
export type PinFailure =
  | { ok: false; code: "PATH_INVALID"; detail: string }
  | { ok: false; code: "NOT_DIRECTORY"; detail: string }
  | { ok: false; code: "CONTROL_FILE_ABSENT"; detail: string }
  | { ok: false; code: "PIN_FAILED"; detail: string };

export type PinResult = { ok: true; pin: PinnedCgroup } | PinFailure;

/**
 * Pin a cgroup directory and its control files.
 *
 * The path is validated first — absolute, under the cgroup2 mount, no traversal — because a pin on
 * an unintended path is worse than a refusal: it would be a durable, honoured handle to the wrong
 * object.
 */
export function pinCgroup(options: {
  cgroupPath: string;
  /** The cgroup2 mount point discovered from `/proc/self/mountinfo`. */
  mountPath: string;
}) : PinResult {
  const { cgroupPath, mountPath } = options;

  if (!cgroupPath.startsWith("/") || cgroupPath.split("/").includes("..")) {
    return { ok: false, code: "PATH_INVALID", detail: "the cgroup path must be absolute and must not traverse" };
  }
  // The path must be under the mount this process can see. A path under a different mount is a
  // different hierarchy that happens to share a name.
  if (cgroupPath !== mountPath && !cgroupPath.startsWith(`${mountPath}/`)) {
    return { ok: false, code: "PATH_INVALID", detail: "the cgroup path is not under the cgroup2 mount" };
  }
  // A dedicated DIP subtree only. Pinning the root, or another tenant's directory, would give this
  // watchdog an honoured handle to a cgroup it does not own.
  if (!cgroupPath.startsWith(`${mountPath}/dip-executor.slice`)) {
    return { ok: false, code: "PATH_INVALID", detail: "the cgroup is not in the dedicated DIP subtree" };
  }

  let dirFd: number | undefined;
  try {
    // `O_CLOEXEC` is not exposed on the typed `constants` object, and `openSync` since Node 12 opens
    // descriptors close-on-exec by default, so the flag is not passed explicitly.
    dirFd = openSync(cgroupPath, constants.O_RDONLY | constants.O_DIRECTORY);
  } catch (error) {
    return {
      ok: false,
      code: "NOT_DIRECTORY",
      detail: error instanceof Error ? error.message : "the cgroup directory could not be opened",
    };
  }

  try {
    const dirStat = fstatSync(dirFd);
    if (!dirStat.isDirectory()) {
      closeSync(dirFd);
      return { ok: false, code: "NOT_DIRECTORY", detail: "the pinned path is not a directory" };
    }

    const opened: Partial<Record<PinnedControlFile, PinnedFile>> = {};
    for (const name of PINNED_CONTROL_FILES) {
      // Reached *through the descriptor*, never by re-joining the path. The descriptor is the
      // reference; the path is only how it was found once.
      const throughFd = `/proc/self/fd/${dirFd}/${name}`;
      let fd: number;
      try {
        // Read-only is sufficient for `events` and `procs`, and for `kill` the write itself is done
        // separately through the pinned descriptor, so the handle stays read-only and no wider
        // authority is held than is needed.
        fd = openSync(throughFd, constants.O_RDONLY);
      } catch {
        closeOpenFiles(opened);
        return { ok: false, code: "CONTROL_FILE_ABSENT", detail: `${name} could not be opened through the pinned directory` };
      }
      const stat = fstatSync(fd);
      opened[name] = {
        name,
        fd,
        device: stat.dev,
        inode: stat.ino,
        resolvedPath: safeReadlink(`/proc/self/fd/${fd}`),
      };
    }

    return {
      ok: true,
      pin: {
        dirFd,
        dirDevice: dirStat.dev,
        dirInode: dirStat.ino,
        pinnedPath: cgroupPath,
        files: opened as PinnedCgroup["files"],
      },
    };
  } catch (error) {
    if (dirFd !== undefined) {
      try { closeSync(dirFd); } catch { /* already failing */ }
    }
    return { ok: false, code: "PIN_FAILED", detail: error instanceof Error ? error.message : "the cgroup could not be pinned" };
  }
}

/** Close every descriptor a pin holds. Safe on a partially-built pin. */
export function closePinned(pin: Pick<PinnedCgroup, "dirFd" | "files">): void {
  closeOpenFiles(pin.files);
  try { closeSync(pin.dirFd); } catch { /* already closed */ }
}

/** Close just the control-file descriptors, for the partial-failure path. */
function closeOpenFiles(files: Partial<Record<PinnedControlFile, PinnedFile>>): void {
  for (const name of PINNED_CONTROL_FILES) {
    const file = files[name];
    if (file !== undefined) {
      try { closeSync(file.fd); } catch { /* already closed */ }
    }
  }
}

/**
 * Verify the pin still describes the object it was taken from.
 *
 * Two separate questions, both required:
 *
 *   1. Does `fstat` of the retained descriptors still match the recorded identity? This catches a
 *      descriptor that was closed and reused, which would be a handle to something else.
 *   2. Does the *path* still resolve to the pinned directory? It may not, and that is the case
 *      pinning exists for — the write will still land correctly. But a path that now names a
 *      different inode means the cgroup was replaced, and a termination aimed at it would be
 *      aimed at a resource the watchdog never verified.
 */
export function verifyPin(pin: PinnedCgroup): { ok: true; pathStillPinned: boolean } | { ok: false; code: "DESCRIPTOR_IDENTITY_CHANGED" | "DESCRIPTOR_CLOSED"; detail: string } {
  try {
    const dirStat = fstatSync(pin.dirFd);
    if (dirStat.dev !== pin.dirDevice || dirStat.ino !== pin.dirInode) {
      return { ok: false, code: "DESCRIPTOR_IDENTITY_CHANGED", detail: "the directory descriptor no longer names the pinned inode" };
    }
    for (const name of PINNED_CONTROL_FILES) {
      const file = pin.files[name];
      const stat = fstatSync(file.fd);
      if (stat.dev !== file.device || stat.ino !== file.inode) {
        return { ok: false, code: "DESCRIPTOR_IDENTITY_CHANGED", detail: `the descriptor for ${name} no longer names the pinned inode` };
      }
    }
  } catch {
    // `fstat` on a closed descriptor throws EBADF. A closed pin is not a pin.
    return { ok: false, code: "DESCRIPTOR_CLOSED", detail: "a pinned descriptor is no longer open" };
  }

  // The path comparison is informational: a false answer does not invalidate the pin, it records
  // that the path was replaced and the termination is proceeding on the descriptor alone.
  let pathStillPinned = false;
  try {
    const pathStat = statSync(pin.pinnedPath);
    pathStillPinned = pathStat.dev === pin.dirDevice && pathStat.ino === pin.dirInode;
  } catch {
    pathStillPinned = false;
  }
  return { ok: true, pathStillPinned };
}

/**
 * Signal termination through the pinned `cgroup.kill` descriptor.
 *
 * Writes to `/proc/self/fd/<killFd>`, which resolves through the descriptor to the exact inode that
 * was verified. The path is never used.
 *
 * `fs.writeFileSync` is used rather than `fs.writeSync` because a write through the `/proc`
 * re-open path is a distinct open, and the raw fd returned there is not writable in the way
 * `writeSync` expects. This was measured, not assumed: `writeFileSync` through the descriptor
 * reached the pinned inode after the path was swapped to a decoy.
 *
 * A successful return means the kernel accepted the write. It does **not** mean the processes have
 * exited; the caller must confirm that separately through `cgroup.events` or disappearance.
 */
export function writePinnedKill(pin: PinnedCgroup): { ok: true } | { ok: false; code: "WRITE_FAILED"; detail: string } {
  const kill = pin.files["cgroup.kill"];
  try {
    writeFileSync(`/proc/self/fd/${kill.fd}`, "1");
  } catch (error) {
    return { ok: false, code: "WRITE_FAILED", detail: error instanceof Error ? error.message : "cgroup.kill could not be written" };
  }
  // The write is to a control file on a pseudo-filesystem, so there is no page cache to flush. The
  // descriptor is still fsync'd where the kernel permits it, and a refusal is not an error: some
  // cgroup control files reject fsync, and treating that as a failed kill would report a kill that
  // already happened as failed.
  try {
    fsyncSync(kill.fd);
  } catch {
    /* not a durability-bearing file */
  }
  return { ok: true };
}

/** Read `cgroup.events` through the pinned descriptor. */
export function readPinnedEvents(pin: PinnedCgroup): string | null {
  try {
    return readFileSync(`/proc/self/fd/${pin.files["cgroup.events"].fd}`, "utf8");
  } catch {
    return null;
  }
}

/**
 * Whether the pinned cgroup reports itself unpopulated.
 *
 * `false` is positive evidence that no tasks remain. `null` means the answer could not be obtained,
 * which is *not* the same thing and must not be treated as termination.
 */
export function pinnedIsPopulated(pin: PinnedCgroup): boolean | null {
  const events = readPinnedEvents(pin);
  if (events === null) return null;
  const match = /^populated\s+(\d+)$/mu.exec(events);
  if (!match) return null;
  return match[1] !== "0";
}

/** Read the PIDs in the pinned cgroup. `null` when unreadable. */
export function readPinnedProcs(pin: PinnedCgroup): number[] | null {
  try {
    const text = readFileSync(`/proc/self/fd/${pin.files["cgroup.procs"].fd}`, "utf8");
    return text
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line !== "")
      .map((line) => Number.parseInt(line, 10))
      .filter((value) => Number.isSafeInteger(value) && value > 0);
  } catch {
    return null;
  }
}

function safeReadlink(path: string): string {
  try {
    return readlinkSync(path);
  } catch {
    return "";
  }
}
