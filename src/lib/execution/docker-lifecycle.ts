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

import { spawn, spawnSync } from "node:child_process";

/** The fixed absolute path to the Docker CLI. Never resolved from `PATH`. */
export const DOCKER_BIN = "/usr/bin/docker";

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

/** Reject a cgroup parent that is not the dedicated DIP parent. */
export function assertDedicatedCgroupParent(parent: string): void {
  if (!/^\/dip-executor-[a-f0-9]{8,32}$/u.test(parent)) {
    throw new Error(`refusing a cgroup parent outside the dedicated DIP namespace: ${parent}`);
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

/**
 * Asynchronous `docker create`.
 *
 * The supervisor and watchdog are long-lived event-loop processes. Every Docker call they
 * make must be async, or a slow daemon stalls authentication, streaming and deadline
 * enforcement for every other connection at once.
 */
export function createContainerAsync(policy: ExecutionPolicy): Promise<{ ok: true; containerId: string } | { ok: false; error: string }> {
  const argv = buildCreateArgv(policy);
  return new Promise((resolve) => {
    const child = spawn(DOCKER_BIN, [...argv], { shell: false, env: { ...DOCKER_ENV }, stdio: ["ignore", "pipe", "pipe"] });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => out.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => err.push(chunk));
    child.on("error", (error) => resolve({ ok: false, error: `docker create could not start: ${error.message}` }));
    child.on("close", (code) => {
      if (code !== 0) return resolve({ ok: false, error: `docker create failed (${code}): ${Buffer.concat(err).toString("utf8").trim().slice(0, 4_000)}` });
      const id = Buffer.concat(out).toString("utf8").trim();
      if (!/^[a-f0-9]{64}$/u.test(id)) return resolve({ ok: false, error: "docker create returned no valid container id" });
      resolve({ ok: true, containerId: id });
    });
  });
}

/** Asynchronous `docker rm` by exact id. */
export function removeContainerAsync(containerId: string): Promise<{ ok: boolean; error?: string }> {
  const argv = buildRemoveArgv(containerId);
  return new Promise((resolve) => {
    const child = spawn(DOCKER_BIN, [...argv], { shell: false, env: { ...DOCKER_ENV }, stdio: ["ignore", "ignore", "pipe"] });
    const err: Buffer[] = [];
    child.stderr.on("data", (chunk: Buffer) => err.push(chunk));
    child.on("error", (error) => resolve({ ok: false, error: `docker rm could not start: ${error.message}` }));
    child.on("close", (code) => {
      if (code === 0) return resolve({ ok: true });
      resolve({ ok: false, error: `docker rm failed (${code}): ${Buffer.concat(err).toString("utf8").trim().slice(0, 4_000)}` });
    });
  });
}
