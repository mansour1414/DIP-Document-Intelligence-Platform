/**
 * Fixed Docker lifecycle adapter (R7D.1).
 *
 * This module builds the **only** Docker command shapes this system is allowed to run. The
 * caller supplies a container name, an image, and an execution identity; it never supplies
 * arguments. That is the whole security posture of this file: if a value cannot be produced
 * by a function here, it cannot reach the daemon.
 *
 * ## Defect 1 from the abandoned implementation, and what changed
 *
 * The previous candidate assembled argv with an unverified `--endpoint` flag and started
 * containers with `start -ai` without having asked `create` to retain stdin. Both would
 * have been caught by the tests in `test/r7d.docker-argv.test.ts`, and neither was.
 *
 * Three corrections are baked in here:
 *
 *   1. **No `--endpoint`.** Local daemon selection is `DOCKER_HOST`-free and relies on the
 *      default socket. An `--endpoint` flag is a Swarm-era option that a plain
 *      `docker create` does not accept; passing it is a hard error, not a preference.
 *      `assertSupportedDockerFlags` below rejects it explicitly so a future edit notices.
 *   2. **`create` opens stdin, and `start -ai` attaches to it.** `docker create -i` retains
 *      stdin on the container; `docker start -ai` then attaches. A `start -ai` against a
 *      container created *without* `-i` fails with "the input device is not a TTY" or
 *      attaches nothing, which is exactly the defect.
 *   3. **`--cgroup-parent` names a dedicated parent we create and verify**, not an
 *      inherited one, so the watchdog can resolve ownership by cgroup identity rather than
 *      by name or label.
 *
 * ## Why `shell: false` and a fixed environment
 *
 * `spawnSync`/`spawn` with an argument array and `shell: false` means no word splitting, no
 * globbing and no shell builtins. The environment is built from an allowlist constant, so
 * the daemon client cannot inherit `DOCKER_HOST`, `DOCKER_CONFIG`, proxy settings or any
 * application secret from the process that started the supervisor.
 *
 * ## What this file does NOT prove
 *
 * Nothing here demonstrates that Docker *accepts* or *enforces* this policy. Argv
 * construction is a unit-level property. Effective enforcement needs a live daemon and is
 * reported BLOCKED wherever Docker is unavailable — see the test file's separation of
 * argv assertions from OS assertions.
 */

import { spawn, spawnSync } from "node:child_process";

/** The fixed absolute path to the Docker CLI. Never resolved from `PATH`. */
export const DOCKER_BIN = "/usr/bin/docker";

/**
 * The minimal environment every Docker invocation receives.
 *
 * An allowlist, not a denylist. `DOCKER_HOST` is deliberately absent: it would let an
 * inherited variable redirect the loopback-only socket to a remote daemon, which would put
 * the executor outside the host's lifetime and cgroup accounting. If this system ever needs
 * a non-default socket, it will be added here as an explicit, reviewed constant.
 */
export const DOCKER_ENV = Object.freeze({
  PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
  // Suppress the CLI's own telemetry/update chatter; nothing it says is used as a result.
  DOCKER_CLI_HINTS: "false",
  // Next augments `ProcessEnv` with a required `NODE_ENV`. The daemon client does not read
  // it, but supplying it keeps this environment a *concrete* object rather than a relaxed
  // `Record<string, string>`, which in turn keeps `spawn`'s overload resolution honest.
  NODE_ENV: "production",
}) satisfies NodeJS.ProcessEnv;

/**
 * Flags this adapter will emit.
 *
 * Declared as data so the test suite can assert the emitted argv is a subset of this set.
 * A flag that appears in argv but not here is a bug by definition.
 */
export const SUPPORTED_FLAGS = Object.freeze([
  "create",
  "start",
  "rm",
  "inspect",
  "kill",
  "--name",
  "--cgroup-parent",
  "--network",
  "--ipc",
  "--pid",
  "--uts",
  "--userns",
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
  "--entrypoint",
  "--env",
  "--label",
  "--log-driver",
  "--attach",
  "--interactive",
  "-i",
  "-a",
  "-ai",
  "--rm",
  "--force",
  "--type",
  "--format",
  "--attach",
] as const);

/** Flags that must never appear. `--endpoint` is the Defect 1 regression. */
export const FORBIDDEN_FLAGS = Object.freeze([
  "--endpoint",
  "--privileged",
  "--network=host",
  "--pid=host",
  "--ipc=host",
  "--uts=host",
  "--userns=host",
  "--publish",
  "-p",
  "--volume",
  "-v",
  "--mount",
  "--device",
  "--cap-add",
  "--security-opt=seccomp=unconfined",
  "--security-opt=apparmor=unconfined",
  "--restart",
] as const);

/**
 * The execution policy for one disposable container.
 *
 * Every field is a decision. None is optional, because a caller that could omit a control
 * would be a caller that could weaken it.
 */
export type ExecutionPolicy = {
  /** Immutable image allowlist member. Must be a digest reference, not a tag. */
  image: string;
  /** Deterministic container name, derived from the random execution identity. */
  name: string;
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
  /** Private tmpfs size in bytes, mounted at the working directory. */
  tmpfsBytes: number;
  /** The dedicated cgroup parent this system created and verified. */
  cgroupParent: string;
  /** Seccomp profile, by name. Must be an approved profile, never `unconfined`. */
  seccompProfile: string;
  /** AppArmor profile, by name. Must be enforcing, never `unconfined`. */
  apparmorProfile: string;
};

/**
 * The synthetic profile approved for R7D.1 isolated testing (D-R7D-04).
 *
 * These are not production limits. They are here as a named constant so the tests and the
 * image build refer to one object, and so changing them is a visible edit rather than a
 * scattered numeric change.
 */
export const SYNTHETIC_PROFILE = Object.freeze({
  globalActiveExecutors: 1,
  cpuQuotaMicros: 75_000,
  cpuPeriodMicros: 100_000,
  memoryBytes: 384 * 1024 * 1024,
  pidsLimit: 48,
  tmpfsBytes: 48 * 1024 * 1024,
  /** V8 old-space, passed to the executor as an env value, not a cgroup control. */
  v8OldSpaceMb: 256,
  processingTimeoutMs: 20_000,
  maxFixtureBytes: 1024 * 1024,
} as const);

/**
 * Reject an image reference that is not digest-pinned.
 *
 * The allowlist requirement is "immutable image allowlist". A tag is mutable by definition,
 * so accepting one would make the allowlist a suggestion. `@sha256:` is the only form that
 * names exact bytes.
 */
export function assertDigestPinnedImage(image: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._\-/:]*@sha256:[a-f0-9]{64}$/u.test(image)) {
    throw new Error(`refusing a mutable image reference: ${image}. The allowlist requires @sha256:<64 hex>.`);
  }
}

/** Reject a cgroup parent that is not the dedicated DIP parent. */
export function assertDedicatedCgroupParent(parent: string): void {
  if (!/^\/dip-executor-[a-z0-9]{8,32}$/u.test(parent)) {
    throw new Error(`refusing a cgroup parent outside the dedicated DIP namespace: ${parent}`);
  }
}

/**
 * Build the `docker create` argv for one execution.
 *
 * Ordering note: `create` is given `-i` so stdin is retained, and `--rm` is deliberately
 * **not** passed. `--rm` on create makes the container auto-remove on *exit*, which removes
 * the cgroup and the metadata the watchdog needs to reconcile ownership. Removal is an
 * explicit, verified `docker rm` after the watchdog grants disarm.
 */
export function buildCreateArgv(policy: ExecutionPolicy): string[] {
  assertDigestPinnedImage(policy.image);
  assertDedicatedCgroupParent(policy.cgroupParent);
  if (policy.seccompProfile === "unconfined" || policy.apparmorProfile === "unconfined") {
    throw new Error("refusing to disable a mandatory security profile");
  }
  return [
    "create",
    // Retain stdin. This is the half of Defect 1 that `start -ai` depends on.
    "-i",
    "--name", policy.name,
    "--cgroup-parent", policy.cgroupParent,
    // No host namespaces, no network, no IPC.
    "--network", "none",
    "--ipc", "none",
    "--pid", "private",
    "--uts", "private",
    "--userns", "private",
    // Drop everything, then forbid regaining it.
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--security-opt", `seccomp=${policy.seccompProfile}`,
    "--security-opt", `apparmor=${policy.apparmorProfile}`,
    // Immutable root, with one private scratch mount.
    "--read-only",
    "--tmpfs", `/work:rw,noexec,nosuid,nodev,size=${policy.tmpfsBytes}`,
    // Mask the pseudo-filesystems that would otherwise stay writable.
    "--tmpfs", "/dev/mqueue:rw,nosuid,nodev,noexec,size=64k",
    // Aggregate limits.
    "--memory", String(policy.memoryBytes),
    // Equal to `--memory` means zero additional swap for this cgroup.
    "--memory-swap", String(policy.memoryBytes),
    "--cpu-period", String(policy.cpuPeriodMicros),
    "--cpu-quota", String(policy.cpuQuotaMicros),
    "--pids-limit", String(policy.pidsLimit),
    // No core dumps of document bytes.
    "--ulimit", "core=0",
    // Identity from the image's own passwd entry; no HOME/TMPDIR workaround.
    "--user", `${policy.uid}:${policy.gid}`,
    "--workdir", "/work",
    // Diagnostics are discarded; the result travels on fd 3 via the attached stream.
    "--log-driver", "none",
    // One label, carrying only the opaque execution id. No field names, no values.
    "--label", `dip.execution=${policy.name.replace(/^dip-exec-/, "")}`,
    policy.image,
  ];
}

/**
 * Build the `docker start` argv.
 *
 * `-a` attaches stdout/stderr, `-i` attaches stdin. Together with the retained stdin from
 * `create`, this is the only supported way to feed a container and read its streams
 * without a TTY. `--attach` is expanded explicitly rather than relying on the combined
 * short flag, so the argv records what it means.
 */
export function buildStartArgv(name: string): string[] {
  return ["start", "--attach", "--interactive", name];
}

/** Build the `docker rm` argv. Always force, always named exactly. */
export function buildRemoveArgv(name: string): string[] {
  return ["rm", "--force", name];
}

/**
 * Build the `docker inspect` argv used for effective-state verification.
 *
 * The format string asks for exactly the fields the preflight verifies, so the check does
 * not depend on a second call or on parsing free-form output.
 */
export function buildInspectArgv(name: string): string[] {
  return [
    "inspect",
    "--type", "container",
    "--format",
    // Path -> cgroup parent, effective user, and the state fields that prove no restart and
    // no auto-removal policy is in play.
    "{{.Id}}|{{.HostConfig.CgroupParent}}|{{.Config.User}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.PidMode}}|{{.HostConfig.UsernsMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.RestartPolicy.Name}}|{{.HostConfig.LogConfig.Type}}|{{.HostConfig.Privileged}}|{{len .HostConfig.CapAdd}}|{{len .HostConfig.CapDrop}}|{{len .HostConfig.Binds}}|{{len .HostConfig.Devices}}|{{len .HostConfig.PortBindings}}",
    name,
  ];
}

/** Build the `docker kill` argv, used only as a last resort by the supervisor. */
export function buildKillArgv(name: string): string[] {
  return ["kill", name];
}

/**
 * Assert an emitted argv contains no forbidden flag.
 *
 * Called by the adapter itself as well as by tests. Defence in depth: a bad policy that
 * slipped past review still cannot reach the daemon unremarked.
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

/**
 * Run a fixed Docker command synchronously and return its outcome.
 *
 * `shell: false`, explicit environment, no inherited stdio. Errors are surfaced as a
 * structured result rather than thrown, because "the daemon was unreachable" and "the
 * container was rejected" need different handling by the caller and neither is exceptional
 * at the supervisor's boundary.
 */
export function runDockerSync(argv: readonly string[], options: { timeoutMs?: number } = {}): { status: number; stdout: string; stderr: string } {
  assertNoForbiddenFlags(argv);
  // Captured as buffers and decoded explicitly. Relying on `encoding: "utf8"` here makes
  // the overload resolution depend on the exact tuple types of `stdio`, which TypeScript
  // resolves inconsistently across @types/node versions — and a wrong overload silently
  // yields Buffers typed as strings. Decoding by hand removes that ambiguity.
  const result = spawnSync(DOCKER_BIN, [...argv], {
    shell: false,
    env: { ...DOCKER_ENV },
    timeout: options.timeoutMs ?? 30_000,
    maxBuffer: 4 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stdout = result.stdout ? Buffer.from(result.stdout).toString("utf8") : "";
  const stderr = result.stderr ? Buffer.from(result.stderr).toString("utf8") : "";
  return {
    status: result.status ?? -1,
    stdout,
    // Diagnostics are truncated here rather than downstream: a daemon error can echo a
    // container name, and container names are derived from opaque execution ids only, but
    // an unbounded capture is its own denial-of-service.
    stderr: stderr.slice(0, 4_000),
  };
}

/**
 * Spawn a long-lived Docker command (`start -ai`) with piped stdio.
 *
 * Returned as a child process rather than collected, because the whole point is streaming:
 * the caller writes the document to `stdin` and reads the result from `stdout` as it is
 * produced. Collecting here would reintroduce the buffering defect this design exists to
 * prevent.
 */
export function spawnDocker(argv: readonly string[]) {
  assertNoForbiddenFlags(argv);
  return spawn(DOCKER_BIN, [...argv], {
    shell: false,
    env: { ...DOCKER_ENV },
    stdio: ["pipe", "pipe", "pipe"],
  });
}
