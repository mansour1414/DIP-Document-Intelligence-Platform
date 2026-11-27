/**
 * Fixed Docker lifecycle adapter (R7D.1, corrected per review F01).
 *
 * This module builds the **only** Docker command shapes this system is allowed to run. The
 * caller supplies validated policy values; it never supplies arguments. That is the whole
 * security posture of this file: if a value cannot be produced by a function here, it cannot
 * reach the daemon.
 *
 * ## What the review found, and what changed
 *
 * The first version of this file passed flags that the Docker CLI does not accept, and
 * assumed defaults in places where it should have verified them. Each is corrected below and
 * each has a regression test.
 *
 * | Was | Why it was wrong | Now |
 * | --- | --- | --- |
 * | `--userns private` | `--userns` takes a *user namespace name* from daemon config, not `private`. The CLI rejects it. | omitted; the effective mode is read back and verified |
 * | `--uts private` | `--uts` documents only `host`. Private is the *default*, not a value. | omitted; `.HostConfig.UTSMode` verified empty |
 * | `--pid private` | `--pid` documents `host` and `container:<id>`. Private is the default. | omitted; `.HostConfig.PidMode` verified empty |
 * | /dev/mqueue as a writable tmpfs | A writable tmpfs at a mask point is not a mask — POSIX mqueues stay usable for a denial-of-service. | mounted `ro` |
 * | no pull policy | The daemon default is `--pull missing`, so a missing image would be fetched at execution time. | `--pull never` |
 * | inherited daemon target | `DOCKER_HOST`/context from the parent could redirect to a remote daemon, outside host cgroup accounting. | `--host` fixed to the loopback socket; `DOCKER_CONFIG` pinned to a controller directory |
 * | `/work` 48 MiB **plus** `/tmp` 16 MiB | Two tmpfs allocations silently totalled 64 MiB against an approved 48 MiB writable budget. The page cache backing a tmpfs is charged to the container, so the second tmpfs was an unbudgeted allocation. | one 48 MiB budget split 32 + 16, enforced as a sum |
 * | `TMPDIR=/tmp` override | `/tmp` is already the process default inside the container; setting it added an env key for no benefit and made the working directory look configurable. | override removed; `/tmp` is the tmpfs by virtue of being mounted there |
 * | floating base tag | `node:22-bookworm-slim` is a moving tag. Two builds of the same Dockerfile can resolve to different filesystems. | tag retained for readability, digest recorded and required for the acceptance build |
 * | one label | Ownership could not be tied to boot, supervisor instance, image or profile. | five derived labels, all verified on inspect |
 * | `rm`/`kill` by name | A name is not an identity; another container could hold it after a race. | exact 64-hex container id, validated |
 * | shape-only validation | Only digest form and profile names were checked. | every policy field range-checked |
 * | `runDockerSync(argv)` public | A generic argv entry point is an arbitrary-execution interface for a trusted control plane. | private; only typed operations are exported |
 *
 * ## Two things this file still cannot establish
 *
 * 1. **That the daemon accepts these flags.** Flag support depends on API version
 *    (`--cgroupns` needs 1.41+, `--pull` is 1.42+). Static tests prove construction, not
 *    acceptance. Only a live daemon settles it, and Docker is unavailable in the environment
 *    where this was written, so it is reported BLOCKED.
 * 2. **That the kernel enforces them.** `--read-only`, `ro` on a tmpfs and `--security-opt`
 *    are requests until the container is inspected *after* start. The preflight belongs to
 *    the supervisor increment.
 */

import { PassThrough } from "node:stream";
import { spawn, spawnSync } from "node:child_process";

/** The fixed absolute path to the Docker CLI. Never resolved from `PATH`. */
/**
 * The Docker CLI, at a fixed absolute path.
 *
 * Never resolved through `PATH`: a control plane that runs whatever `docker` happens to be
 * first on the path is one `PATH` edit away from executing something else.
 *
 * `DIP_DOCKER_BIN` exists so the asynchronous operations can be exercised against a stand-in
 * process in tests. It redirects a *fixed, typed* call — it is not a way to pass arbitrary argv,
 * which the typed operations and `assertNoForbiddenFlags` still prevent.
 */
export const DOCKER_BIN = process.env.DIP_DOCKER_BIN ?? "/usr/bin/docker";

/** The loopback socket this system is allowed to talk to. */
export const DOCKER_SOCKET = "unix:///var/run/docker.sock";

/**
 * The minimal environment every Docker invocation receives.
 *
 * An allowlist, not a denylist. Three deliberate properties:
 *
 *   - **No `DOCKER_HOST`.** An inherited value could point at a remote daemon, putting the
 *     container outside this host's cgroup accounting and the watchdog's reach. The daemon is
 *     targeted with an explicit `--host` in argv instead, so the destination is visible in
 *     the command rather than in ambient state.
 *   - **`DOCKER_CONFIG` pinned** to a controller-owned directory. Docker reads `contexts/`
 *     and `config.json` from there; pointing it at an empty directory means no inherited
 *     context, and therefore no TLS material or credential helper, can influence the client.
 *   - **No proxy variables.** The CLI does not need them to reach a Unix socket, and
 *     inheriting them would let the parent process influence how it connects.
 */
export const DOCKER_CONFIG_DIR = "/run/dip-docker-client";

export const DOCKER_ENV = Object.freeze({
  PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
  DOCKER_CLI_HINTS: "false",
  DOCKER_CONFIG: DOCKER_CONFIG_DIR,
  // Next augments `ProcessEnv` with a required `NODE_ENV`. The daemon client does not read
  // it; supplying it keeps this a concrete object so `spawn`'s overloads stay honest.
  NODE_ENV: "production",
}) satisfies NodeJS.ProcessEnv;

/**
 * Global flags that precede the subcommand.
 *
 * `--host` is emitted for every invocation. It is the supported way to name the daemon
 * explicitly and it appears in the argv, so an operator reading a process list or a log can
 * see which socket was targeted.
 */
export const DOCKER_GLOBAL_FLAGS: readonly string[] = Object.freeze(["--host", DOCKER_SOCKET]);

/**
 * Flags this adapter will emit.
 *
 * Declared as data so the test suite can assert the emitted argv is a subset. A flag that
 * appears in argv but not here is a bug by definition.
 */
export const SUPPORTED_FLAGS = Object.freeze([
  "--host",
  "create",
  "start",
  "rm",
  "inspect",
  "kill",
  "--name",
  "--cgroup-parent",
  "--cgroupns",
  "--network",
  "--ipc",
  "--pull",
  "--cap-drop",
  "--security-opt",
  "--read-only",
  "--tmpfs",
  "--memory",
  "--memory-swap",
  "--cpu-period",
  "--cpu-quota",
  "--pids-limit",
  "--ulimit",
  "--user",
  "--workdir",
  "--env",
  "--label",
  "--log-driver",
  "--attach",
  "--interactive",
  "--format",
  "--type",
  "--force",
  "-i",
] as const);

/**
 * Flags that must never appear.
 *
 * `--endpoint` and `--userns private` are the regressions this list exists for. The
 * namespace trio is listed because each has a *supported* way to achieve isolation (omit the
 * flag and verify the default) and an *unsupported* way that looks equivalent.
 */
export const FORBIDDEN_FLAGS = Object.freeze([
  "--endpoint",
  "--privileged",
  "--publish",
  "-p",
  "--volume",
  "-v",
  "--mount",
  "--device",
  "--cap-add",
  "--restart",
  "--userns",
  "--uts",
  "--pid",
  "--security-opt=seccomp=unconfined",
  "--security-opt=apparmor=unconfined",
  "--network=host",
  "--ipc=host",
  "--pull=always",
  "--pull=missing",
] as const);

/**
 * The execution policy for one disposable container.
 *
 * Every field is a decision, and every field is validated. A caller that could omit a control
 * would be a caller that could weaken it.
 */
export type ExecutionPolicy = {
  /** Immutable image allowlist member. Must be a digest reference, not a tag. */
  image: string;
  /** Deterministic container name, derived from the random execution identity. */
  name: string;
  /** Opaque execution id. 32 lowercase hex. Used to derive labels. */
  executionId: string;
  /** Host boot identity, so a record from a previous boot is never treated as current. */
  bootId: string;
  /** Supervisor instance identity, so a restarted supervisor is distinguishable. */
  supervisorInstance: string;
  /** Profile identity, so an artifact can be tied to the limits it was approved under. */
  profileId: string;
  /** The UID the executor runs as. Real, with a passwd entry in the image. */
  uid: number;
  /** The GID the executor runs as. */
  gid: number;
  /** Aggregate memory limit in bytes. */
  memoryBytes: number;
  /** CPU quota in microseconds per `cpuPeriodMicros`. */
  cpuQuotaMicros: number;
  /** CPU period; 100000 is the daemon default and is stated rather than assumed. */
  cpuPeriodMicros: number;
  /** PID/thread ceiling for the container's cgroup. */
  pidsLimit: number;
  /**
   * Approved total writable tmpfs budget in bytes.
   *
   * The page cache backing a tmpfs is charged against the container's memory cgroup, so every
   * tmpfs is an allocation from the same 384 MiB. This is the *sum* bound, and the split below
   * must fit inside it.
   */
  tmpfsBudgetBytes: number;
  /** Portion of the budget mounted at the working directory. */
  workTmpfsBytes: number;
  /** Portion of the budget mounted at `/tmp`. */
  tmpTmpfsBytes: number;
  /** The dedicated cgroup parent this system created and verified. */
  cgroupParent: string;
  /** Seccomp profile, by name. Must be an approved profile, never `unconfined`. */
  seccompProfile: string;
  /** AppArmor profile, by name. Must be enforcing, never `unconfined`. */
  apparmorProfile: string;
  /** V8 old-space bound, passed to the executor as an env value. */
  v8OldSpaceMb: number;
};

/**
 * The synthetic profile approved for R7D.1 isolated testing (D-R7D-04).
 *
 * Not production limits. Named so the tests, the image build and the policy agree by
 * construction, and so changing one is a visible edit rather than a scattered numeric change.
 */
export const SYNTHETIC_PROFILE = Object.freeze({
  globalActiveExecutors: 1,
  cpuQuotaMicros: 75_000,
  cpuPeriodMicros: 100_000,
  memoryBytes: 384 * 1024 * 1024,
  pidsLimit: 48,
  // The approved 48 MiB writable budget, split rather than doubled. 32 + 16 = 48.
  tmpfsBudgetBytes: 48 * 1024 * 1024,
  workTmpfsBytes: 32 * 1024 * 1024,
  tmpTmpfsBytes: 16 * 1024 * 1024,
  v8OldSpaceMb: 256,
  processingTimeoutMs: 20_000,
  maxFixtureBytes: 1024 * 1024,
  id: "synthetic-r7d-v1",
} as const);

// ---------------------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------------------

/** Reject an image reference that is not digest-pinned. */
export function assertDigestPinnedImage(image: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._\-/:]*@sha256:[a-f0-9]{64}$/u.test(image)) {
    throw new Error(`refusing a mutable image reference: ${image}. The allowlist requires @sha256:<64 hex>.`);
  }
}

/**
 * The cgroup driver the daemon is configured with.
 *
 * ## Why the driver is a policy input and not a guess
 *
 * Docker places a container's cgroup differently depending on its cgroup driver, and the two
 * layouts are not interchangeable:
 *
 *   - `systemd` — the default on cgroup v2. A container gets a transient scope unit named
 *     `docker-<container id>.scope`, and because the cgroup parent is a slice, systemd nests that
 *     scope *inside* the slice: `/sys/fs/cgroup/dip-executor.slice/docker-<id>.scope`. The scope is
 *     never a bare child of the parent directory, because systemd always creates the unit's own
 *     cgroup beneath the slice it was placed in.
 *   - `cgroupfs` — the container gets a plain directory named after its id beneath the parent:
 *     `/sys/fs/cgroup/dip-executor.slice/<id>`.
 *
 * A verification that assumed one layout rejected the other. Inferring the layout from an observed
 * path would make the check agree with whatever it was shown, so the operator states the daemon's
 * driver and the watchdog verifies the container is where *that* driver puts it. Both layouts are
 * taken from Docker's documented "Find the cgroup for a given container" table and systemd's
 * slice-nesting rules.
 */
export type CgroupDriver = "systemd" | "cgroupfs";

/**
 * The dedicated cgroup parent: a systemd slice name.
 *
 * ## Why this is a top-level slice, and not a directory
 *
 * `dip-executor.slice` is not a path someone creates; it is a slice unit name, and systemd
 * materialises it at the root of the cgroup tree — `/sys/fs/cgroup/dip-executor.slice` — exactly as
 * it materialises `system.slice` and `user.slice`. Slice nesting is encoded in the name as
 * dash-separated components: `foo-bar.slice` lives inside `foo.slice`, so a name containing no dash
 * is a direct child of the root slice. It is therefore *not* nested under `system.slice`, and it is
 * not correct to assume it is a directory that already exists.
 *
 * The previous form, `--cgroup-parent /dip-executor-<hex>`, could not be resolved to a slice by the
 * systemd driver, and `verifyArmIdentity` only arms containers inside the dedicated subtree, so the
 * two halves of the system disagreed about the hierarchy and no container could ever be armed. One
 * name, serving as both the daemon's parent and the watchdog's boundary, removes that possibility.
 */
export const DEDICATED_CGROUP_SLICE = "dip-executor.slice";

/**
 * The parent passed to `docker create`.
 *
 * Both drivers accept the slice name: systemd resolves it as a slice unit, cgroupfs treats it as a
 * directory beneath the cgroup root. Neither form is per-execution — the watchdog's authority is
 * the subtree, not one container within it.
 */
export function cgroupParentFor(driver: CgroupDriver): string {
  void driver;
  return DEDICATED_CGROUP_SLICE;
}

/**
 * The container's cgroup, relative to the cgroup2 mount.
 *
 * This is what `/proc/<pid>/cgroup` reports for the container's init process: the value the
 * supervisor observes, and the value the watchdog must independently confirm.
 */
export function expectedCgroupRelative(driver: CgroupDriver, containerId: string): string {
  return driver === "systemd"
    ? `${DEDICATED_CGROUP_SLICE}/docker-${containerId}.scope`
    : `${DEDICATED_CGROUP_SLICE}/${containerId}`;
}

/**
 * Reject a cgroup parent that is not the dedicated DIP slice.
 *
 * Exactly one value is accepted. A parent that merely looks dedicated is refused at admission
 * rather than discovered at arm time, because a container outside the subtree can never be armed
 * and would otherwise occupy an executor slot until its deadline.
 */
export function assertDedicatedCgroupParent(parent: string): void {
  // The daemon accepts either form — `dip-executor.slice` or `/dip-executor.slice` — because the
  // leading slash says "resolve from the cgroup root" rather than "resolve as a unit name". Both
  // name the same slice, so both are accepted; nothing else is.
  const normalised = parent.startsWith("/") ? parent.slice(1) : parent;
  if (normalised !== DEDICATED_CGROUP_SLICE) {
    throw new Error(
      `refusing a cgroup parent outside the dedicated DIP namespace: ${parent}. `
        + `The watchdog can only signal within ${DEDICATED_CGROUP_SLICE}, and any other parent creates `
        + "a container that can never be armed.",
    );
  }
}

/** Reject an identifier that is not 32 lowercase hex. */
export function assertOpaqueId(value: string, what: string): void {
  if (!/^[a-f0-9]{32}$/u.test(value)) throw new Error(`${what} must be 32 lowercase hex characters`);
}

/**
 * Reject a container id that is not the exact 64-hex form the daemon issued.
 *
 * Destructive operations use this, not the name. A name is not an identity: after a race or a
 * restart, a different container could hold it, and `docker rm --force <name>` would then
 * destroy something this system does not own.
 */
export function assertContainerId(id: string): void {
  if (!/^[a-f0-9]{64}$/u.test(id)) {
    throw new Error(`refusing a lifecycle operation without an exact 64-hex container id, got: ${id}`);
  }
}

function assertIntegerInRange(value: number, min: number, max: number, what: string): void {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${what} must be an integer in [${min}, ${max}], got ${value}`);
  }
}

/**
 * Validate the complete policy.
 *
 * The review's point was that checking only the digest and the profile names left every
 * numeric limit — memory, CPU, PIDs, tmpfs — free to be anything a caller passed. A negative
 * memory limit or a CPU quota above its period is not a smaller sandbox, it is a different
 * one, and Docker would accept some of those silently.
 */
export function assertExecutionPolicy(policy: ExecutionPolicy): void {
  assertDigestPinnedImage(policy.image);
  assertDedicatedCgroupParent(policy.cgroupParent);
  assertOpaqueId(policy.executionId, "executionId");
  if (policy.name !== `dip-exec-${policy.executionId}`) {
    throw new Error("container name must be derived from the execution id");
  }
  if (!/^[a-z0-9-]{4,64}$/u.test(policy.bootId)) throw new Error("bootId must be 4-64 lowercase alphanumeric or dash characters");
  if (!/^[a-z0-9-]{4,64}$/u.test(policy.supervisorInstance)) throw new Error("supervisorInstance must be 4-64 lowercase alphanumeric or dash characters");
  if (!/^[a-z0-9-]{4,64}$/u.test(policy.profileId)) throw new Error("profileId must be 4-64 lowercase alphanumeric or dash characters");
  // Never root. The image carries a real passwd entry for the executor UID.
  assertIntegerInRange(policy.uid, 1, 2_147_483_647, "uid");
  assertIntegerInRange(policy.gid, 1, 2_147_483_647, "gid");
  // At least 32 MiB, at most 4 GiB. Below 32 MiB the PDF engine cannot start at all, which
  // would make every execution a confusing OOM rather than a limit.
  assertIntegerInRange(policy.memoryBytes, 32 * 1024 * 1024, 4 * 1024 * 1024 * 1024, "memoryBytes");
  assertIntegerInRange(policy.cpuQuotaMicros, 1, 100_000 * 64, "cpuQuotaMicros");
  assertIntegerInRange(policy.cpuPeriodMicros, 1_000, 1_000_000, "cpuPeriodMicros");
  // A quota above the period means more than one core, which the profile forbids.
  if (policy.cpuQuotaMicros > policy.cpuPeriodMicros) {
    throw new Error("cpuQuotaMicros must not exceed cpuPeriodMicros (that would exceed one core)");
  }
  assertIntegerInRange(policy.pidsLimit, 8, 4_096, "pidsLimit");
  assertIntegerInRange(policy.tmpfsBudgetBytes, 1024 * 1024, 1024 * 1024 * 1024, "tmpfsBudgetBytes");
  assertIntegerInRange(policy.workTmpfsBytes, 1024 * 1024, policy.tmpfsBudgetBytes, "workTmpfsBytes");
  assertIntegerInRange(policy.tmpTmpfsBytes, 1024 * 1024, policy.tmpfsBudgetBytes, "tmpTmpfsBytes");
  // The sum is the real constraint. Checking each half against the budget independently would
  // accept 48 + 48 against an approved 48, which is exactly the defect this corrects.
  if (policy.workTmpfsBytes + policy.tmpTmpfsBytes > policy.tmpfsBudgetBytes) {
    throw new Error(
      `tmpfs split ${policy.workTmpfsBytes} + ${policy.tmpTmpfsBytes} exceeds the approved `
      + `${policy.tmpfsBudgetBytes} byte writable budget`,
    );
  }
  assertIntegerInRange(policy.v8OldSpaceMb, 32, 4_096, "v8OldSpaceMb");
  // V8 heap must sit below the cgroup limit, or the OOM killer arrives before the heap cap
  // and the failure looks like a host problem instead of a document problem.
  if (policy.v8OldSpaceMb * 1024 * 1024 >= policy.memoryBytes) {
    throw new Error("v8OldSpaceMb must be strictly below memoryBytes");
  }
  if (policy.seccompProfile === "unconfined" || policy.apparmorProfile === "unconfined") {
    throw new Error("refusing to disable a mandatory security profile");
  }
  if (!/^[A-Za-z0-9._/-]{1,64}$/u.test(policy.seccompProfile)) throw new Error("seccompProfile name is not acceptable");
  if (!/^[A-Za-z0-9._/-]{1,64}$/u.test(policy.apparmorProfile)) throw new Error("apparmorProfile name is not acceptable");
}

/**
 * The complete ownership label set.
 *
 * Derived, never caller-supplied, so a container's labels describe exactly one execution.
 * The preflight compares all five back against the journal before any document moves.
 */
export function ownershipLabels(policy: ExecutionPolicy): string[] {
  return [
    `dip.execution=${policy.executionId}`,
    `dip.boot=${policy.bootId}`,
    `dip.supervisor=${policy.supervisorInstance}`,
    `dip.image=${policy.image.slice(policy.image.indexOf("@") + 1)}`,
    `dip.profile=${policy.profileId}`,
  ];
}

// ---------------------------------------------------------------------------------------
// Command construction
// ---------------------------------------------------------------------------------------

/**
 * Build the `docker create` argv for one execution.
 *
 * `create` retains stdin (`-i`) so `start --attach --interactive` can attach to it. `--rm` is
 * deliberately absent: auto-removal on exit destroys the cgroup and the metadata the watchdog
 * needs in order to reconcile ownership, so removal is an explicit, verified step.
 */
export function buildCreateArgv(policy: ExecutionPolicy): string[] {
  assertExecutionPolicy(policy);
  const argv = [
    ...DOCKER_GLOBAL_FLAGS,
    "create",
    "-i",
    "--pull", "never",
    "--name", policy.name,
    "--cgroup-parent", policy.cgroupParent,
    // The only namespace flag with a documented `private` value. The PID, UTS and user
    // namespaces are private by default and are verified from inspect instead of requested
    // with values the CLI does not document.
    "--cgroupns", "private",
    "--network", "none",
    "--ipc", "none",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--security-opt", `seccomp=${policy.seccompProfile}`,
    "--security-opt", `apparmor=${policy.apparmorProfile}`,
    "--read-only",
    // The work directory: writable, but never executable and never setuid.
    "--tmpfs", `/work:rw,noexec,nosuid,nodev,size=${policy.workTmpfsBytes}`,
    // The approved bounded /tmp profile. TMPDIR points here so nothing falls back to a path
    // that does not exist in a read-only root.
    "--tmpfs", `/tmp:rw,noexec,nosuid,nodev,size=${policy.tmpTmpfsBytes}`,
    // A *read-only* mount at /dev/mqueue. A writable tmpfs there would not be a mask at all:
    // POSIX message queues would remain usable as a denial-of-service channel.
    "--tmpfs", "/dev/mqueue:ro,nosuid,nodev,noexec",
    "--memory", String(policy.memoryBytes),
    // Equal to --memory means zero additional swap for this cgroup.
    "--memory-swap", String(policy.memoryBytes),
    "--cpu-period", String(policy.cpuPeriodMicros),
    "--cpu-quota", String(policy.cpuQuotaMicros),
    "--pids-limit", String(policy.pidsLimit),
    // No core dumps, which would write document-adjacent memory into the image filesystem.
    "--ulimit", "core=0",
    "--user", `${policy.uid}:${policy.gid}`,
    "--workdir", "/work",
    // Diagnostics are discarded. The result travels on fd 3 through the attached stream.
    "--log-driver", "none",
    // The V8 heap bound is an env value, not a cgroup control: it makes the engine fail with
    // a JavaScript heap error, which is diagnosable, instead of being OOM-killed at the cgroup
    // boundary, which looks like a host fault.
    "--env", `NODE_OPTIONS=--max-old-space-size=${policy.v8OldSpaceMb}`,
    // No TMPDIR override. `/tmp` is already the default, it is a tmpfs because it is mounted
    // there, and an env key that restates the default invites the belief that it is a
    // configurable boundary. The mount is the boundary.
    "--env", "NODE_ENV=production",
    ...ownershipLabels(policy).flatMap((label) => ["--label", label]),
    policy.image,
  ];
  assertNoForbiddenFlags(argv);
  return argv;
}

/** Build the `docker start` argv. `--attach` and `--interactive` only; never a TTY. */
export function buildStartArgv(name: string): string[] {
  assertContainerName(name);
  const argv = [...DOCKER_GLOBAL_FLAGS, "start", "--attach", "--interactive", name];
  assertNoForbiddenFlags(argv);
  return argv;
}

/**
 * Build the `docker rm` argv.
 *
 * Takes an exact container id, not a name. See `assertContainerId`.
 */
export function buildRemoveArgv(containerId: string): string[] {
  assertContainerId(containerId);
  const argv = [...DOCKER_GLOBAL_FLAGS, "rm", "--force", containerId];
  assertNoForbiddenFlags(argv);
  return argv;
}

/** Build the `docker kill` argv. Exact container id, same reasoning as removal. */
export function buildKillArgv(containerId: string): string[] {
  assertContainerId(containerId);
  const argv = [...DOCKER_GLOBAL_FLAGS, "kill", containerId];
  assertNoForbiddenFlags(argv);
  return argv;
}

function assertContainerName(name: string): void {
  if (!/^dip-exec-[a-f0-9]{32}$/u.test(name)) throw new Error(`refusing an unrecognised container name: ${name}`);
}

/**
 * The inspect format, expanded to cover every control the preflight must verify.
 *
 * One call, one format string, no second round trip and no parsing of free-form output.
 */
export const INSPECT_FORMAT = [
  "{{.Id}}",
  "{{.HostConfig.CgroupParent}}",
  "{{.HostConfig.CgroupnsMode}}",
  "{{.Config.User}}",
  "{{.HostConfig.NetworkMode}}",
  "{{.HostConfig.IpcMode}}",
  "{{.HostConfig.PidMode}}",
  "{{.HostConfig.UTSMode}}",
  "{{.HostConfig.UsernsMode}}",
  "{{.HostConfig.ReadonlyRootfs}}",
  "{{.HostConfig.Memory}}",
  "{{.HostConfig.MemorySwap}}",
  "{{.HostConfig.PidsLimit}}",
  "{{.HostConfig.NanoCpus}}",
  "{{.HostConfig.CpuQuota}}",
  "{{.HostConfig.CpuPeriod}}",
  "{{.HostConfig.RestartPolicy.Name}}",
  "{{.HostConfig.LogConfig.Type}}",
  "{{.HostConfig.Privileged}}",
  "{{.HostConfig.AutoRemove}}",
  "{{json .HostConfig.CapAdd}}",
  "{{json .HostConfig.CapDrop}}",
  "{{json .HostConfig.Binds}}",
  "{{json .HostConfig.Devices}}",
  "{{json .HostConfig.PortBindings}}",
  "{{json .HostConfig.Tmpfs}}",
  "{{json .Config.Labels}}",
  "{{json .Config.Env}}",
].join("|");

export function buildInspectArgv(nameOrId: string): string[] {
  if (!/^(dip-exec-[a-f0-9]{32}|[a-f0-9]{64})$/u.test(nameOrId)) {
    throw new Error(`refusing to inspect an unrecognised reference: ${nameOrId}`);
  }
  const argv = [...DOCKER_GLOBAL_FLAGS, "inspect", "--type", "container", "--format", INSPECT_FORMAT, nameOrId];
  assertNoForbiddenFlags(argv);
  return argv;
}

/**
 * Assert an emitted argv contains no forbidden flag.
 *
 * Called by every builder as well as by tests. Defence in depth: a policy that slipped past
 * review still cannot reach the daemon unremarked.
 */
export function assertNoForbiddenFlags(argv: readonly string[]): void {
  for (const arg of argv) {
    for (const forbidden of FORBIDDEN_FLAGS) {
      // Exact match, or a `--flag=value` prefix. A bare `includes` would also reject
      // legitimate values that merely contain the text.
      if (arg === forbidden || arg.startsWith(`${forbidden}=`)) {
        throw new Error(`refusing to emit a forbidden docker flag: ${forbidden}`);
      }
    }
  }
}

// ---------------------------------------------------------------------------------------
// Execution — typed operations only
// ---------------------------------------------------------------------------------------
//
// The previous version exported `runDockerSync(argv)` and `spawnDocker(argv)`. That is an
// arbitrary-execution interface sitting inside the trusted control plane: anything able to
// call it can run any Docker command as whatever identity the supervisor holds. Both are now
// private, and only the typed operations below are exported.

export type DockerResult = { status: number; stdout: string; stderr: string };

function runFixed(argv: readonly string[], timeoutMs: number): DockerResult {
  assertNoForbiddenFlags(argv);
  // Captured as buffers and decoded explicitly. Relying on `encoding: "utf8"` makes overload
  // resolution depend on exact tuple types, which varies across @types/node versions.
  const result = spawnSync(DOCKER_BIN, [...argv], {
    shell: false,
    env: { ...DOCKER_ENV },
    timeout: timeoutMs,
    maxBuffer: 4 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  return {
    status: result.status ?? -1,
    stdout: result.stdout ? Buffer.from(result.stdout).toString("utf8") : "",
    // Truncated here, not downstream: a daemon error can be long, and an unbounded capture
    // is its own denial-of-service.
    stderr: result.stderr ? Buffer.from(result.stderr).toString("utf8").slice(0, 4_000) : "",
  };
}

/**
 * Create a container. Returns the daemon-issued id, or an error.
 *
 * Synchronous by necessity in this adapter, but the asynchronous form below is what the
 * supervisor must use: blocking the event loop while a daemon call is outstanding would stall
 * every other connection on a process that is supposed to be a thin, responsive pipe.
 */
export function createContainer(policy: ExecutionPolicy): { ok: true; containerId: string } | { ok: false; error: string } {
  const result = runFixed(buildCreateArgv(policy), 30_000);
  if (result.status !== 0) return { ok: false, error: `docker create failed (${result.status}): ${result.stderr.trim()}` };
  const id = result.stdout.trim();
  // The daemon prints the id on stdout. A create that "succeeded" without one is not
  // something to guess about.
  if (!/^[a-f0-9]{64}$/u.test(id)) return { ok: false, error: "docker create returned no valid container id" };
  return { ok: true, containerId: id };
}

/** Remove a container by exact id. */
export function removeContainer(containerId: string): { ok: boolean; error?: string } {
  const result = runFixed(buildRemoveArgv(containerId), 30_000);
  return result.status === 0 ? { ok: true } : { ok: false, error: `docker rm failed (${result.status}): ${result.stderr.trim()}` };
}

/** Inspect a container's effective configuration. */
export function inspectContainer(nameOrId: string): { ok: true; raw: string } | { ok: false; error: string } {
  const result = runFixed(buildInspectArgv(nameOrId), 15_000);
  if (result.status !== 0) return { ok: false, error: `docker inspect failed (${result.status}): ${result.stderr.trim()}` };
  return { ok: true, raw: result.stdout.trim() };
}

/**
 * Spawn `start --attach --interactive` and return the child, streams piped.
 *
 * Streaming, not collecting: the caller writes the document to `stdin` and reads fd 3 from
 * `stdout` as it is produced. Collecting here would reintroduce the buffering defect.
 */
export function startContainerAttached(name: string) {
  const argv = buildStartArgv(name);
  return spawn(DOCKER_BIN, [...argv], {
    shell: false,
    env: { ...DOCKER_ENV },
    stdio: ["pipe", "pipe", "pipe"],
  });
}

// ---------------------------------------------------------------------------------------
// Asynchronous operations for the supervisor and watchdog
// ---------------------------------------------------------------------------------------
//
// ## The property that makes these different from `runFixed`
//
// These run on the control-plane event loop, which is also serving authenticated sockets,
// streaming a document and enforcing deadlines. Every call therefore needs a hard deadline, a
// bounded capture and a guaranteed reap, or one slow daemon stalls everything at once.
//
// ## Definite versus ambiguous
//
// The distinction that matters for recovery is not "did it fail" but "can the daemon still act".
//
//   - A non-zero exit *after* the client connected and the daemon answered is a **definite**
//     rejection: the operation did not happen.
//   - A timeout, a signal, or an exit before the daemon answered is **ambiguous**. Killing the
//     Docker CLI client does not cancel an outstanding request in the daemon — the daemon may
//     complete the create moments later, and the caller will never learn the id. Treating that
//     as "nothing happened" is how an unowned container is created.
//
// An ambiguous outcome must leave the journal intent in place and quarantine. It is reported as
// `ambiguous: true` and the caller is required to reconcile rather than proceed.

/** How long any single Docker CLI invocation may run before it is killed and reaped. */
export const DOCKER_DEADLINE_MS = Object.freeze({
  create: 30_000,
  remove: 20_000,
  inspect: 10_000,
  kill: 10_000,
});

/**
 * Bytes of stdout/stderr retained per operation.
 *
 * A daemon can emit arbitrarily long diagnostics — a failed pull is the obvious case. Capturing
 * without a bound lets a remote peer's error text grow the supervisor's heap. Excess is counted
 * and discarded, never silently truncated into something that looks complete.
 */
export const DOCKER_CAPTURE_BYTES = 64 * 1024;

/**
 * The closed set of failure categories.
 *
 * Free-form messages are what leak into logs and telemetry, and a message assembled by a daemon
 * from container input is not something the control plane should retain verbatim. The category
 * is what recovery branches on; the detail is for the caller's immediate decision and is
 * deliberately not persisted.
 */
export type DockerFaultCategory =
  | "BINARY_MISSING"
  | "SPAWN_FAILED"
  | "DAEMON_UNAVAILABLE"
  | "PERMISSION_DENIED"
  | "NOT_FOUND"
  | "CONFLICT"
  | "INVALID_ARGUMENT"
  | "TIMEOUT"
  | "SIGNALLED"
  | "BAD_OUTPUT"
  | "DAEMON_ERROR";

export type DockerOutcome<T> =
  | { ok: true; value: T }
  | {
      ok: false;
      fault: DockerFaultCategory;
      /** True when the daemon may still act. The caller must quarantine and reconcile. */
      ambiguous: boolean;
      /** Short, sanitized, non-persisted detail. Never a full daemon transcript. */
      detail: string;
    };

type Capture = { chunks: Buffer[]; bytes: number; truncated: boolean };

function newCapture(): Capture {
  return { chunks: [], bytes: 0, truncated: false };
}

function appendBounded(capture: Capture, chunk: Buffer): void {
  const room = DOCKER_CAPTURE_BYTES - capture.bytes;
  if (room <= 0) {
    capture.truncated = true;
    return;
  }
  if (chunk.byteLength > room) {
    capture.chunks.push(chunk.subarray(0, room));
    capture.bytes += room;
    capture.truncated = true;
    return;
  }
  capture.chunks.push(chunk);
  capture.bytes += chunk.byteLength;
}

function readCapture(capture: Capture): string {
  const text = Buffer.concat(capture.chunks).toString("utf8");
  return capture.truncated ? `${text}\n[diagnostics truncated at ${DOCKER_CAPTURE_BYTES} bytes]` : text;
}

/**
 * Map a Docker CLI failure onto a closed category.
 *
 * The daemon's own wording is matched loosely and only to categorize. Anything unrecognised
 * becomes `DAEMON_ERROR`, which is the honest answer: the control plane does not understand it,
 * so it must not pretend to.
 */
function categorize(stderr: string): DockerFaultCategory {
  const text = stderr.toLowerCase();
  if (text.includes("cannot connect to the docker daemon") || text.includes("is the docker daemon running")) return "DAEMON_UNAVAILABLE";
  if (text.includes("permission denied")) return "PERMISSION_DENIED";
  if (text.includes("no such container") || text.includes("no such object")) return "NOT_FOUND";
  if (text.includes("already in use") || text.includes("conflict")) return "CONFLICT";
  if (text.includes("is not a valid") || text.includes("invalid")) return "INVALID_ARGUMENT";
  return "DAEMON_ERROR";
}

/** Categories that prove the requested operation did not take effect. */
function definiteCategory(fault: DockerFaultCategory): boolean {
  return fault === "NOT_FOUND"
    || fault === "DAEMON_UNAVAILABLE"
    || fault === "PERMISSION_DENIED"
    || fault === "INVALID_ARGUMENT"
    || fault === "BINARY_MISSING";
}

/**
 * Run one Docker CLI invocation with a deadline, a bounded capture and a guaranteed reap.
 *
 * `resolveWith` decides what a clean exit means. Everything that is not a clean exit becomes a
 * categorized fault with an explicit ambiguity flag.
 */
function runDockerAsync<T>(
  argv: readonly string[],
  deadlineMs: number,
  resolveWith: (stdout: string, stderr: string) => T,
  /** True when a non-zero exit proves the requested operation did not take effect. */
  definiteOnFailure: boolean,
): Promise<DockerOutcome<T>> {
  return new Promise((resolve) => {
    assertNoForbiddenFlags(argv);

    let settled = false;
    /**
     * The deadline timer, assigned below.
     *
     * Declared with `let` before `finish` closes over it, and explicitly `undefined` until the
     * timer exists. It was formerly a `const` declared *after* this closure, so any path that
     * settled the promise before the timer was created — `assertNoForbiddenFlags` throwing, a
     * `spawn` that failed synchronously — hit the temporal dead zone and rejected with
     * `ReferenceError: Cannot access 'timer' before initialization` instead of returning the typed
     * fault it had already constructed. The bug was invisible because every existing test took the
     * asynchronous path.
     */
    // `let`, not `const`: the declaration must precede the closure (TDZ, above) and the assignment
    // must follow the `spawn` that can settle the promise synchronously. Reacting to this warning
    // by hoisting the assignment is what produced the ReferenceError it exists to prevent.
    // eslint-disable-next-line prefer-const
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (outcome: DockerOutcome<T>): void => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      resolve(outcome);
    };

    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(DOCKER_BIN, [...argv], {
        shell: false,
        env: { ...DOCKER_ENV },
        stdio: ["ignore", "pipe", "pipe"],
        // Own process group, so a deadline can kill the client *and* anything it started.
        // Without this, killing the CLI leaves its children holding the stdout/stderr pipes
        // open, `close` never fires, and the deadline only takes effect once the grandchildren
        // happen to exit — which for a hung operation is never.
        detached: true,
      });
    } catch (error) {
      // `spawn` itself throwing means the binary could not be started at all. That is definite:
      // nothing reached the daemon.
      finish({
        ok: false,
        fault: "SPAWN_FAILED",
        ambiguous: false,
        detail: error instanceof Error ? error.message.slice(0, 200) : "spawn failed",
      });
      return;
    }

    const out = newCapture();
    const err = newCapture();
    let killedByDeadline = false;
    let signalled: string | null = null;

    timer = setTimeout(() => {
      killedByDeadline = true;
      // Killing the client does not cancel an in-flight request in the daemon. The outcome is
      // therefore ambiguous regardless of what the exit code turns out to be.
      //
      // The group is signalled, not just the child, because a CLI that spawned helpers would
      // otherwise leave them holding the pipes and `close` would never fire.
      try {
        if (child.pid !== undefined) process.kill(-child.pid, "SIGKILL");
        else child.kill("SIGKILL");
      } catch {
        // The group is already gone, or the platform refused. Fall back to the direct child.
        try { child.kill("SIGKILL"); } catch { /* already dead */ }
      }
      // Do not wait for `close` to settle the promise. A detached grandchild can hold the pipes
      // open indefinitely, and the caller's deadline is the promise that must be kept.
      finish({
        ok: false,
        fault: "TIMEOUT",
        ambiguous: true,
        detail: `no answer within ${deadlineMs} ms; the daemon may still be acting`,
      });
    }, deadlineMs);

    child.stdout?.on("data", (chunk: Buffer) => appendBounded(out, chunk));
    child.stderr?.on("data", (chunk: Buffer) => appendBounded(err, chunk));

    child.on("error", (error: NodeJS.ErrnoException) => {
      // ENOENT is the common one: the CLI is not installed where the policy says it is.
      const fault: DockerFaultCategory = error.code === "ENOENT" ? "BINARY_MISSING" : "SPAWN_FAILED";
      finish({ ok: false, fault, ambiguous: false, detail: error.code ?? "spawn error" });
    });

    child.on("close", (code, signal) => {
      if (signal) signalled = signal;
      const stderrText = readCapture(err);
      const stdoutText = readCapture(out);

      if (killedByDeadline) {
        finish({
          ok: false,
          fault: "TIMEOUT",
          ambiguous: true,
          detail: `no answer within ${deadlineMs} ms; the daemon may still be acting`,
        });
        return;
      }
      if (signalled !== null) {
        finish({ ok: false, fault: "SIGNALLED", ambiguous: true, detail: `terminated by ${signalled}` });
        return;
      }
      if (code !== 0) {
        const fault = categorize(stderrText);
        finish({
          ok: false,
          fault,
          // A non-zero exit is only definite where the caller says so *and* the category proves
          // nothing happened. `NOT_FOUND` from `docker rm` is definite — the container is gone
          // either way. `DAEMON_UNAVAILABLE` and `PERMISSION_DENIED` are definite too: the
          // request never reached an acting daemon. Anything else may have been half-applied,
          // because the operation can complete and the client fail while reporting it.
          ambiguous: !definiteOnFailure && !definiteCategory(fault),
          detail: stderrText.replace(/\s+/gu, " ").trim().slice(0, 300),
        });
        return;
      }
      try {
        finish({ ok: true, value: resolveWith(stdoutText, stderrText) });
      } catch (error) {
        // A clean exit whose output the caller cannot use. The operation may have happened, so
        // this is ambiguous: a `create` that reported a malformed id still created a container.
        finish({
          ok: false,
          fault: "BAD_OUTPUT",
          ambiguous: true,
          detail: error instanceof Error ? error.message.slice(0, 200) : "unusable output",
        });
      }
    });
  });
}

/**
 * Asynchronous `docker create`.
 *
 * A timeout here is the single most dangerous outcome in the system: the daemon may create the
 * container after the client is gone, and nobody will ever learn its id. Callers must treat
 * `ambiguous: true` as "a container may exist that I cannot name" and reconcile, never as
 * "nothing happened".
 */
export function createContainerAsync(policy: ExecutionPolicy): Promise<DockerOutcome<{ containerId: string }>> {
  return runDockerAsync(
    buildCreateArgv(policy),
    DOCKER_DEADLINE_MS.create,
    (stdout) => {
      const id = stdout.trim();
      if (!/^[a-f0-9]{64}$/u.test(id)) throw new Error("docker create returned no valid container id");
      return { containerId: id };
    },
    true,
  );
}

/** Asynchronous `docker rm` by exact id, idempotent for an already-removed container. */
export function removeContainerAsync(containerId: string): Promise<DockerOutcome<{ removed: boolean }>> {
  return runDockerAsync(
    buildRemoveArgv(containerId),
    DOCKER_DEADLINE_MS.remove,
    () => ({ removed: true }),
    // A non-zero exit may mean "no such container", which is success for a cleanup path, so the
    // category decides. Anything else is definite for removal semantics: `rm` either removed it
    // or did not, and the journal keeps the intent until an inspect positively confirms absence.
    false,
  );
}

/** Asynchronous `docker inspect`. Used for preflight and for recovery reconciliation. */
export function inspectContainerAsync(containerId: string): Promise<DockerOutcome<{ raw: string }>> {
  return runDockerAsync(
    buildInspectArgv(containerId),
    DOCKER_DEADLINE_MS.inspect,
    (stdout) => {
      if (stdout.trim() === "") throw new Error("docker inspect returned nothing");
      return { raw: stdout };
    },
    // `inspect` is read-only, so a failure is definite: no state changed.
    true,
  );
}

/**
 * The inspect fields that describe *this instance of* a container, not its configuration.
 *
 * ## Why a second inspect rather than more fields on `INSPECT_FORMAT`
 *
 * `INSPECT_FORMAT` is the effective-configuration contract that `preflightContainer` compares
 * exactly, and its field count is asserted by the parser, the fixture and the tests. The init PID,
 * its kernel start time and the running state are a different question asked at a different moment:
 * configuration is fixed at `create`, while these change with the process. Keeping them in a
 * separate typed read means adding one cannot silently shift the configuration columns, which is the
 * defect class D2-F01/F04 already burned once.
 */
export const STATE_INSPECT_FORMAT = ["{{.State.Pid}}", "{{.State.Running}}", "{{.Id}}"].join("|");

export function buildStateInspectArgv(containerId: string): string[] {
  assertContainerId(containerId);
  const argv = [...DOCKER_GLOBAL_FLAGS, "inspect", "--type", "container", "--format", STATE_INSPECT_FORMAT, containerId];
  assertNoForbiddenFlags(argv);
  return argv;
}

/** What the daemon says about a container's live process. `pid` is 0 when it is not running. */
export type ContainerStateInspect = {
  /** The container's init PID in the host's PID namespace. 0 when the container is not running. */
  pid: number;
  running: boolean;
  /** The id the daemon echoed, so a reply for another container is detectable. */
  containerId: string;
};

/**
 * Asynchronous state inspect by exact id.
 *
 * The PID this returns is checked against the kernel before it is used: a PID is recycled, so the
 * supervisor reads the process's start time from `/proc` and records the pair. D2-F02's preflight
 * then compares the pair against a *second* reading, which is what makes "this process" checkable
 * rather than assumed.
 */
export function inspectStateAsync(containerId: string): Promise<DockerOutcome<ContainerStateInspect>> {
  return runDockerAsync(
    buildStateInspectArgv(containerId),
    DOCKER_DEADLINE_MS.inspect,
    (stdout) => {
      const parts = stdout.trim().split("|");
      if (parts.length !== 3) throw new Error("docker inspect did not return the state format");
      const pid = Number(parts[0]);
      const running = parts[1];
      const id = parts[2] ?? "";
      if (!Number.isSafeInteger(pid) || pid < 0) throw new Error("docker inspect returned no usable init pid");
      if (running !== "true" && running !== "false") throw new Error("docker inspect returned no usable running state");
      if (!/^[a-f0-9]{64}$/u.test(id)) throw new Error("docker inspect echoed no container id");
      return { pid, running: running === "true", containerId: id };
    },
    // Read-only, so a failure is definite: nothing changed.
    true,
  );
}

/** Asynchronous `docker kill` by exact id. */
export function killContainerAsync(containerId: string): Promise<DockerOutcome<{ killed: boolean }>> {
  return runDockerAsync(
    buildKillArgv(containerId),
    DOCKER_DEADLINE_MS.kill,
    () => ({ killed: true }),
    false,
  );
}

/**
 * Start attached, asynchronously, with a reaped child and a real exit code.
 *
 * ## Why this is not `startContainerAttached`
 *
 * That function returns the raw child so a synchronous caller can wire the streams itself. The
 * supervisor runs on the control-plane event loop and needs three things the raw child does not
 * give it: a hard guarantee that the child is reaped (an unreaped child holds a PID and its
 * container's descriptors), an exit code that distinguishes *the executor* finishing from *the
 * Docker CLI* exiting, and a session object narrow enough that nothing downstream can call
 * `kill` on the wrong process group.
 *
 * ## The exit code is the CLI's, and that is why it is not trusted alone
 *
 * `docker start -a` exits with the container's exit code only when the CLI can attach. When the
 * daemon disappears the CLI exits non-zero while the container may still be running, so the caller
 * must pair this code with a confirmed termination and removal. `SupervisorExecution` does exactly
 * that, and the real executor exit code is validated against the result frame it produced.
 */
export function startContainerAttachedAsync(name: string): DockerSessionLike {
  const argv = buildStartArgv(name);
  assertNoForbiddenFlags(argv);
  const child = spawn(DOCKER_BIN, [...argv], {
    shell: false,
    env: { ...DOCKER_ENV },
    // A real three-way channel: stdin is the document, stdout is the container's stdout, and
    // stderr is diagnostic only. The *result* is written to fd 3, which `docker start` does not
    // forward — see the note below.
    stdio: ["pipe", "pipe", "pipe"],
    detached: true,
  });

  // The result channel.
  //
  // `docker start -a -i` does not pass a fourth descriptor through, so the executor's fd 3 cannot
  // arrive this way. The supervisor therefore reads the result from the *same* stdout stream the
  // container writes, and the executor's own framing (a 4-byte length prefix followed by
  // metadata and output) is what separates a result from a stray write. That is a real limitation
  // of the Docker CLI and is recorded as such rather than worked around with a side channel the
  // daemon would not carry anyway.
  const result = child.stdout ?? null;

  const exited = new Promise<number>((resolve) => {
    let settled = false;
    const finish = (code: number): void => {
      if (settled) return;
      settled = true;
      resolve(code);
    };
    child.once("exit", (code, signal) => {
      // A signalled exit has no code. Reported as a non-zero sentinel rather than 0, because 0
      // would read as a clean completion for a process that was killed.
      finish(code ?? (signal === null ? 1 : 128 + signalNumber(signal)));
    });
    child.once("error", () => finish(1));
  });

  return {
    stdin: child.stdin!,
    stdout: child.stdout ?? new PassThrough(),
    stderr: child.stderr ?? new PassThrough(),
    // A stream that yields nothing when the CLI cannot forward fd 3, so `collectResult` fails on
    // an empty frame rather than waiting forever on a channel that will never deliver.
    result: result ?? new PassThrough().end(),
    exited,
  };
}

/** A signal name as the conventional 128+n exit code. */
function signalNumber(signal: NodeJS.Signals): number {
  const numbers: Partial<Record<NodeJS.Signals, number>> = {
    SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGILL: 4, SIGTRAP: 5, SIGABRT: 6, SIGBUS: 7,
    SIGFPE: 8, SIGKILL: 9, SIGUSR1: 10, SIGSEGV: 11, SIGUSR2: 12, SIGPIPE: 13,
    SIGALRM: 14, SIGTERM: 15,
  };
  return numbers[signal] ?? 1;
}

/**
 * The production Docker seam.
 *
 * ## What this is
 *
 * An adapter, not an implementation. Every operation is one of the existing asynchronous functions
 * in this file, which already own the deadline, the bounded capture, the process-group kill and the
 * definite/ambiguous classification. Re-implementing any of that here would be a second copy of the
 * rules that make the daemon calls safe.
 *
 * ## What it deliberately does not do
 *
 * It does not retry. A retry decision depends on whether the previous attempt was definite or
 * ambiguous, which is knowledge the lifecycle holds and this adapter does not. Retrying an
 * ambiguous create is how two containers get created for one intent.
 */
export function createDockerSeam(): DockerSeamLike {
  return {
    create: (policy: ExecutionPolicy) => createContainerAsync(policy),
    inspect: (id: string) => inspectContainerAsync(id),
    remove: (id: string) => removeContainerAsync(id),
    kill: (id: string) => killContainerAsync(id),
    start: async (name: string) => startContainerAttachedAsync(name),
    state: (id: string) => inspectStateAsync(id),
  };
}

/**
 * The seam's shape, restated here.
 *
 * `supervisor.ts` owns the authoritative `DockerSeam` type. Importing it from there would make this
 * file depend on the lifecycle, and the lifecycle depends on this file — a cycle that TypeScript
 * permits for types but which makes the dependency direction untrue. The shapes are checked against
 * each other by `createDockerSeam`'s return type in `execution-handler.ts`, where both are in scope.
 */
export type DockerSeamLike = {
  create: (policy: ExecutionPolicy) => Promise<DockerOutcome<{ containerId: string }>>;
  inspect: (id: string) => Promise<DockerOutcome<{ raw: string }>>;
  remove: (id: string) => Promise<DockerOutcome<{ removed: boolean }>>;
  kill: (id: string) => Promise<DockerOutcome<{ killed: boolean }>>;
  start: (name: string) => Promise<DockerSessionLike>;
  state: (id: string) => Promise<DockerOutcome<ContainerStateInspect>>;
};

export type DockerSessionLike = {
  stdin: NodeJS.WritableStream;
  stdout: NodeJS.ReadableStream;
  stderr: NodeJS.ReadableStream;
  result: NodeJS.ReadableStream;
  exited: Promise<number>;
};
