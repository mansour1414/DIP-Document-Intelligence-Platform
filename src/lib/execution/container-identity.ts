/**
 * Container identity and observation (R7D.1 Continuation D1-Final: WD-F01, WD-F04).
 *
 * ## The defect this replaces
 *
 * The watchdog's inspect adapter answered one boolean: `present`. A daemon that could not be
 * reached, a container that permission was denied for, and a container that positively does not
 * exist all became `present: true`. The consequence was not a false alarm; it was the opposite —
 * a successful `docker inspect` for an existing container and a failed one were indistinguishable,
 * so **removal could never be positively confirmed**, and a removal debt could never be honestly
 * discharged.
 *
 * ## The correction
 *
 * Observation is a closed vocabulary of five outcomes, and only one of them may establish absence:
 *
 * | observation | may establish absence | may authorize a signal |
 * |---|---|---|
 * | `absent` (exact-id NOT_FOUND) | **yes** | no (nothing there) |
 * | `present` (identity matched) | no | **yes** |
 * | `present-foreign` (identity mismatched) | no | **no** |
 * | `unavailable` | no | no |
 * | `denied` | no | no |
 * | `ambiguous` | no | no |
 *
 * "Unavailable is not absence" is the load-bearing rule, and it is a type-level rule: there is no
 * boolean to confuse.
 *
 * ## Ownership
 *
 * A matching name, subtree and PID start time do not establish that a container is *this
 * execution's* container. Five derived labels, the container id, the resolved image digest and the
 * profile are compared exactly. Derived labels are never caller-supplied, so a container carrying
 * them was created by this codebase for exactly one execution.
 */

import { readFileSync } from "node:fs";
import { INSPECT_FORMAT, type DockerOutcome, type DockerFaultCategory } from "./docker-lifecycle";

/** The five ownership labels, exactly as `ownershipLabels` derives them. */
export const OWNERSHIP_LABEL_KEYS = Object.freeze([
  "dip.execution",
  "dip.boot",
  "dip.supervisor",
  "dip.image",
  "dip.profile",
] as const);

export type OwnershipLabelKey = (typeof OWNERSHIP_LABEL_KEYS)[number];

/** What the daemon said, reduced to what a decision can be made from. */
export type ContainerObservation =
  /** The exact id resolved to no container. This is the only absence. */
  | { state: "absent"; detail: string }
  /** A container exists under the exact id, and its identity is as recorded. */
  | { state: "present"; containerId: string; labels: Record<string, string>; detail: string }
  /** A container exists under the exact id, but it is not this execution's container. */
  | { state: "present-foreign"; reason: ForeignReason; detail: string }
  /** The daemon could not be asked: no binary, no socket, no daemon, a timeout. */
  | { state: "unavailable"; fault: DockerFaultCategory; detail: string }
  /** The daemon answered, and refused. */
  | { state: "denied"; fault: DockerFaultCategory; detail: string }
  /** The daemon may or may not have acted, and the answer is not usable. */
  | { state: "ambiguous"; fault: DockerFaultCategory; detail: string };

export type ForeignReason =
  | "container-id-mismatch"
  | "container-name-mismatch"
  | "label-missing"
  | "label-mismatch"
  | "image-mismatch"
  | "profile-mismatch";

/** What the watchdog expects a container to be, from its own durable record. */
export type ExpectedOwnership = {
  executionId: string;
  containerId: string;
  containerName: string;
  imageDigest: string;
  profileId: string;
  bootId: string;
  supervisorInstance: string;
};

/**
 * Classify one `docker inspect` outcome.
 *
 * `NOT_FOUND` is deliberately narrow: it is the category `classifyFault` assigns only to the
 * daemon's own "no such container"/"no such object" text. Everything else — including a timeout,
 * which proves nothing either way — is not absence.
 */
export function classifyInspect(outcome: DockerOutcome<{ raw: string }>, expected: ExpectedOwnership): ContainerObservation {
  if (outcome.ok) {
    return matchOwnership(parseInspectFields(outcome.value.raw), expected);
  }
  switch (outcome.fault) {
    case "NOT_FOUND":
      return { state: "absent", detail: "the daemon reports no such container for the exact id" };
    case "DAEMON_UNAVAILABLE":
    case "BINARY_MISSING":
      // The daemon was never reached. Nothing about the container is known.
      return { state: "unavailable", fault: outcome.fault, detail: outcome.detail };
    case "PERMISSION_DENIED":
      return { state: "denied", fault: outcome.fault, detail: outcome.detail };
    default:
      return { state: "ambiguous", fault: outcome.fault, detail: outcome.detail };
  }
}

/**
 * The `|`-separated fields `INSPECT_FORMAT` produces, as an identity question.
 *
 * ## D2-F01: why the positions are derived, not written down
 *
 * The previous parser read the labels object from `parts[27]`. `INSPECT_FORMAT` has 28 fields and
 * `Config.Labels` is at **26**; 27 is `Config.Env`. The parser therefore read the container's
 * environment as its labels, `JSON.parse` returned an array, and every real container was
 * classified `ambiguous` — no container could ever be verified as owned, so ownership could never
 * be established from the daemon's answer. The test fixture repeated the same `27`, which is why
 * the suite passed while nothing could work against a real daemon.
 *
 * The indexes are now computed from `INSPECT_FORMAT` itself. A field is found by its template, so
 * inserting a field moves the reference with it, and a missing or duplicated field is a hard error
 * at module load rather than a silent read of the wrong column.
 */
const INSPECT_FIELDS = INSPECT_FORMAT.split("|");

function fieldIndex(template: string): number {
  const index = INSPECT_FIELDS.indexOf(template);
  if (index < 0) throw new Error(`INSPECT_FORMAT no longer contains ${template}, which ownership verification requires`);
  if (INSPECT_FIELDS.lastIndexOf(template) !== index) throw new Error(`INSPECT_FORMAT contains ${template} more than once`);
  return index;
}

/** Zero-based positions of the fields identity is derived from. Derived, never literal. */
const INDEX = Object.freeze({
  id: fieldIndex("{{.Id}}"),
  cgroupParent: fieldIndex("{{.HostConfig.CgroupParent}}"),
  labels: fieldIndex("{{json .Config.Labels}}"),
});

/** How many fields a well-formed inspect line has. A short or long line is a format violation. */
export const INSPECT_FIELD_COUNT = INSPECT_FIELDS.length;

/**
 * Parse the `|`-separated fields `INSPECT_FORMAT` produces.
 *
 * The format is a fixed list and every field is emitted, so a short line is a format violation —
 * which is `ambiguous`, not a container with missing properties.
 */
export function parseInspectFields(raw: string): InspectFields | null {
  // A JSON field may itself contain `|`, but the *labels* field is the only object-valued one and
  // it is JSON, so splitting on `|` is only safe because no earlier field can contain one. Each
  // earlier field is an id, a mode, a number or a boolean. `Config.Env` — an array of strings that
  // may contain `|` — is the last field and is not read here, so it cannot shift the count.
  const parts = raw.trim().split("|");
  // The count is checked rather than assumed: a short line is a format violation, which is a
  // different answer from a container with missing properties.
  if (parts.length !== INSPECT_FIELD_COUNT) return null;
  const id = parts[INDEX.id];
  const cgroupParent = parts[INDEX.cgroupParent];
  const labelsJson = parts[INDEX.labels];
  let labels: Record<string, string>;
  try {
    const parsed: unknown = JSON.parse(labelsJson ?? "null");
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    labels = parsed as Record<string, string>;
  } catch {
    return null;
  }
  return { containerId: id ?? "", cgroupParent: cgroupParent ?? "", labels };
}

export type InspectFields = {
  containerId: string;
  cgroupParent: string;
  labels: Record<string, string>;
};

/**
 * Compare an inspected container against the record's expectation.
 *
 * Every comparison is exact. There is no prefix match, no case folding and no default.
 */
export function matchOwnership(fields: InspectFields | null, expected: ExpectedOwnership): ContainerObservation {
  if (fields === null) {
    // The inspect *succeeded* but the output is not the shape the format promises. That is a
    // format violation, and it proves nothing about ownership.
    return { state: "ambiguous", fault: "BAD_OUTPUT", detail: "the inspect output did not match the requested format" };
  }

  if (fields.containerId !== expected.containerId) {
    return { state: "present-foreign", reason: "container-id-mismatch", detail: "the daemon answered for a different container id" };
  }

  const label = (key: OwnershipLabelKey): string | undefined => fields.labels[key];
  if (label("dip.execution") !== expected.executionId) {
    return label("dip.execution") === undefined
      ? { state: "present-foreign", reason: "label-missing", detail: "the container carries no dip.execution label" }
      : { state: "present-foreign", reason: "label-mismatch", detail: "dip.execution names another execution" };
  }
  if (label("dip.boot") !== expected.bootId) {
    return { state: "present-foreign", reason: "label-mismatch", detail: "dip.boot names another boot" };
  }
  if (label("dip.supervisor") !== expected.supervisorInstance) {
    return { state: "present-foreign", reason: "label-mismatch", detail: "dip.supervisor names another supervisor instance" };
  }
  // `ownershipLabels` derives `dip.image` as the digest after the `@`, so the comparison is against
  // the digest rather than the full reference.
  const expectedImage = expected.imageDigest.slice(expected.imageDigest.indexOf("@") + 1);
  if (label("dip.image") !== expectedImage && label("dip.image") !== expected.imageDigest) {
    return { state: "present-foreign", reason: "image-mismatch", detail: "the container's image is not the pinned image" };
  }
  if (label("dip.profile") !== expected.profileId) {
    return { state: "present-foreign", reason: "profile-mismatch", detail: "the container's profile is not the expected profile" };
  }

  return {
    state: "present",
    containerId: fields.containerId,
    labels: { ...fields.labels },
    detail: "the container's id and all five ownership labels match",
  };
}

/** The only observation that may discharge a removal debt. */
export function provesAbsence(observation: ContainerObservation): boolean {
  return observation.state === "absent";
}

/** The only observation that may authorize signalling a target. */
export function provesOwnership(observation: ContainerObservation): boolean {
  return observation.state === "present";
}

// ── Actual cgroup path, derived from verified host state ──────────────────────────────────────

/**
 * The cgroup a process is actually in, read from `/proc/<pid>/cgroup`.
 *
 * ## Why not a naming convention
 *
 * A container's cgroup path depends on the daemon's cgroup driver: the systemd driver produces
 * `dip-executor.slice/docker-<id>.scope`, the cgroupfs driver produces `<parent>/<id>`. Assuming
 * either one means the watchdog records a path that may not exist, and — worse — a path that could
 * exist for something else. Reading the process's own membership is the only way to learn the path
 * that is true on *this* host, which is why the systemd/cgroupfs distinction stays a host
 * validation gate rather than being decided here.
 *
 * Returns `null` when the file is unreadable, has no unified line, or reports a relative path.
 */
export function actualCgroupPath(pid: number, mountPath: string): { path: string; relative: string } | null {
  if (!Number.isSafeInteger(pid) || pid <= 0) return null;
  let raw: string;
  try {
    raw = readFileSync(`/proc/${pid}/cgroup`, "utf8");
  } catch {
    return null;
  }
  // The unified hierarchy is the `0::` line. Any other line is a legacy hierarchy this watchdog
  // does not act through.
  const unified = raw.split("\n").find((line) => line.startsWith("0::"));
  if (unified === undefined) return null;
  const relative = unified.slice(3);
  if (!relative.startsWith("/")) return null;
  const path = relative === "/" ? mountPath : `${mountPath}${relative}`;
  return { path, relative };
}

/**
 * Exact membership: the process's cgroup is the one named, or is inside it.
 *
 * The previous implementation used `membership.includes("0::" + relative)`, which accepts a
 * *prefix*: a process in `/dip-executor.slice/dip-exec-aaaa…-sibling` satisfies a claim about
 * `/dip-executor.slice/dip-exec-aaaa…`. That is precisely the unrelated-cgroup signal the
 * requirement forbids. This compares whole path components.
 */
export function isExactMembership(actualRelative: string, expectedRelative: string): boolean {
  if (actualRelative === expectedRelative) return true;
  return actualRelative.startsWith(expectedRelative.endsWith("/") ? expectedRelative : `${expectedRelative}/`);
}

/** A cgroup path is inside the dedicated DIP subtree, by whole components. */
export function isInsideDipSubtree(cgroupPath: string, mountPath: string, subtree: string): boolean {
  const prefix = `${mountPath}/${subtree}`;
  if (cgroupPath === prefix) return false; // the slice itself is not an execution's cgroup
  return cgroupPath.startsWith(`${prefix}/`);
}
