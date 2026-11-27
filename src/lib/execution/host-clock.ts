/**
 * A host-consistent monotonic clock (R7D.1 Continuation D1, WD-05).
 *
 * ## The defect this replaces
 *
 * `performance.now()` is process-local. Its origin is the moment the *process* started, so two
 * processes disagree about what "now" is, and a value written to a journal by one process is
 * meaningless to the next. A restarted watchdog that compared a persisted deadline against its own
 * `performance.now()` would either fire immediately (if the persisted value was larger than its
 * fresh clock) or never (if it was smaller) — and either failure mode is silent.
 *
 * ## The clock
 *
 * `/proc/uptime` is the kernel's CLOCK_BOOTTIME, in seconds with hundredths, shared by every
 * process on the host and counting across suspend. Milliseconds since boot is what a cgroup
 * deadline needs. It is *monotonic within a boot*, not across one — so every persisted deadline is
 * stored with the boot id and refuses to be interpreted against a different boot.
 *
 * ## Resolution and honesty about it
 *
 * `CLOCK_BOOTTIME` has centisecond resolution as exposed by `/proc/uptime`, so two reads within
 * 10 ms may return the same value. A caller that needs to distinguish them must not use this
 * clock. Deadlines are measured in seconds, so this is adequate — but it is stated rather than
 * assumed, because a test that "passes" by reading the same value twice proves nothing.
 *
 * ## What this does not do
 *
 * It does not make deadlines survive a reboot. A boot id change invalidates every persisted
 * deadline, deliberately: the containers those deadlines referred to do not exist after a reboot.
 */

import { readFileSync } from "node:fs";

/** Milliseconds since boot, from `/proc/uptime`. Shared by every process on the host. */
export type HostClock = {
  /** The boot identity this clock's readings belong to. */
  readonly bootId: string;
  /** Milliseconds since boot. Monotonic within this boot only. */
  nowMs(): number;
};

/**
 * Read `/proc/uptime` and return milliseconds since boot.
 *
 * Exported separately from `HostClock` so a caller can read it without binding a boot id, and so
 * the parsing has its own tests against a synthetic file instead of the real one.
 */
export function readUptimeMs(source: string = "/proc/uptime"): number {
  const text = readFileSync(source, "utf8");
  const first = text.split(" ")[0];
  if (first === undefined) throw new Error("/proc/uptime is empty");
  const seconds = Number.parseFloat(first);
  if (!Number.isFinite(seconds) || seconds < 0) {
    throw new Error("/proc/uptime did not contain a usable uptime");
  }
  return Math.round(seconds * 1000);
}

/**
 * Build a clock bound to a boot id.
 *
 * The binding is the point. A deadline computed from this clock is only meaningful against the
 * same `bootId`, and `compareDeadline` enforces that rather than trusting a caller to remember.
 */
export function makeHostClock(bootId: string, source: string = "/proc/uptime"): HostClock {
  return {
    bootId,
    nowMs: () => readUptimeMs(source),
  };
}

/** A persisted deadline, always paired with the boot it belongs to. */
export type PersistedDeadline = {
  bootId: string;
  deadlineAtMs: number;
};

/** Why a deadline could not be interpreted. Closed, because recovery branches on it. */
export type DeadlineComparison =
  | { kind: "due"; remainingMs: number }
  | { kind: "pending"; remainingMs: number }
  /** The record was written on a different boot. Its deadline refers to namespaces that are gone. */
  | { kind: "stale-boot" };

/**
 * Compare a persisted deadline against the current clock.
 *
 * A boot mismatch is *not* "pending" and *not* "due": it is a third answer, because neither
 * conclusion is correct. Calling it due would terminate something on this boot because a record
 * from the previous one expired; calling it pending would keep the single executor slot occupied
 * forever for a container that cannot exist.
 */
export function compareDeadline(deadline: PersistedDeadline, clock: HostClock): DeadlineComparison {
  if (deadline.bootId !== clock.bootId) return { kind: "stale-boot" };
  const remainingMs = deadline.deadlineAtMs - clock.nowMs();
  return remainingMs <= 0 ? { kind: "due", remainingMs } : { kind: "pending", remainingMs };
}

/**
 * File descriptor identity, for pinning (WD-03).
 *
 * `fstat` of an open descriptor is the only way to describe the object a descriptor refers to.
 * Comparing this against a `stat` of the path is how a caller learns whether the descriptor and
 * the path still name the same inode — which is the check that makes pinning meaningful rather
 * than decorative.
 */
export type DescriptorIdentity = { device: number; inode: number; isDirectory: boolean };
