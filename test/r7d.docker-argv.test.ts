/**
 * R7D.1 — the fixed Docker command contract.
 *
 * ## What these tests can and cannot prove
 *
 * They prove **argv construction**: that every security control this system claims appears
 * in the command, that no forbidden flag can appear, and that the Defect 1 mistakes are
 * absent. They cannot prove Docker *accepts* or *enforces* any of it — that needs a live
 * daemon, which is unavailable in this environment and is reported BLOCKED, not PASS.
 *
 * The two are kept in separate files on purpose. A green run here must never be read as
 * "the container was isolated"; it means "the command we would send asks for isolation".
 */
import test from "node:test";
import assert from "node:assert/strict";
import {
  assertDedicatedCgroupParent,
  assertDigestPinnedImage,
  assertNoForbiddenFlags,
  buildCreateArgv,
  buildInspectArgv,
  buildRemoveArgv,
  buildStartArgv,
  DOCKER_BIN,
  DOCKER_ENV,
  FORBIDDEN_FLAGS,
  SUPPORTED_FLAGS,
  SYNTHETIC_PROFILE,
  type ExecutionPolicy,
} from "../src/lib/execution/docker-lifecycle";

const DIGEST = `sha256:${"a".repeat(64)}`;

function policy(overrides: Partial<ExecutionPolicy> = {}): ExecutionPolicy {
  return {
    image: `dip-executor@${DIGEST}`,
    name: "dip-exec-0123456789abcdef0123456789abcdef",
    uid: 10001,
    gid: 10001,
    memoryBytes: SYNTHETIC_PROFILE.memoryBytes,
    cpuQuotaMicros: SYNTHETIC_PROFILE.cpuQuotaMicros,
    cpuPeriodMicros: SYNTHETIC_PROFILE.cpuPeriodMicros,
    pidsLimit: SYNTHETIC_PROFILE.pidsLimit,
    tmpfsBytes: SYNTHETIC_PROFILE.tmpfsBytes,
    cgroupParent: "/dip-executor-abcdef0123456789",
    seccompProfile: "runtime/default",
    apparmorProfile: "dip-executor",
    ...overrides,
  };
}

/** Value following a flag in an argv array. */
function valueOf(argv: string[], flag: string): string | undefined {
  const index = argv.indexOf(flag);
  return index >= 0 ? argv[index + 1] : undefined;
}

function allValuesOf(argv: string[], flag: string): string[] {
  const out: string[] = [];
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === flag && index + 1 < argv.length) out.push(argv[index + 1]);
  }
  return out;
}

// ---------------------------------------------------------------------------------------
// Defect 1 regressions.
// ---------------------------------------------------------------------------------------

test("R7D.1-D1-1: create does NOT pass --endpoint", () => {
  // The abandoned implementation included `--endpoint`, a Swarm-era option that a plain
  // `docker create` does not accept. Its presence would be a hard failure at the daemon.
  const argv = buildCreateArgv(policy());
  assert.equal(argv.includes("--endpoint"), false, "--endpoint is not a supported create flag");
  assert.equal(argv.some((arg) => arg.startsWith("--endpoint=")), false);
});

test("R7D.1-D1-2: create retains stdin so that start -ai can attach to it", () => {
  // This is the half of Defect 1 that is easy to miss: `start -ai` against a container
  // created without `-i` attaches nothing. The document would never reach the executor.
  const argv = buildCreateArgv(policy());
  assert.ok(argv.includes("-i"), "create must retain stdin");

  const start = buildStartArgv("dip-exec-0123456789abcdef0123456789abcdef");
  assert.ok(start.includes("--attach"), "start must attach stdout/stderr");
  assert.ok(start.includes("--interactive"), "start must attach stdin");
  // A TTY would mangle binary frames, so it must never be requested.
  assert.equal(start.includes("-t"), false);
  assert.equal(start.includes("--tty"), false);
});

test("R7D.1-D1-3: the start argv names exactly one container and attaches both streams", () => {
  const start = buildStartArgv("dip-exec-x");
  assert.deepEqual(start, ["start", "--attach", "--interactive", "dip-exec-x"]);
});

test("R7D.1-D1-4: removal is an explicit named docker rm, never --rm on create", () => {
  // `--rm` on create would auto-remove the container on exit, destroying the cgroup and the
  // metadata the watchdog needs in order to reconcile ownership. Removal must be explicit
  // and after the watchdog grants disarm.
  const create = buildCreateArgv(policy());
  assert.equal(create.includes("--rm"), false, "create must not auto-remove");
  assert.equal(create.includes("--auto-remove"), false);
  assert.deepEqual(buildRemoveArgv("dip-exec-x"), ["rm", "--force", "dip-exec-x"]);
});

// ---------------------------------------------------------------------------------------
// Mandatory policy coverage (§7).
// ---------------------------------------------------------------------------------------

test("R7D.1-P-1: every mandatory control appears in the create argv", () => {
  const argv = buildCreateArgv(policy());
  const required: Array<[string, string]> = [
    ["--name", "dip-exec-0123456789abcdef0123456789abcdef"],
    ["--cgroup-parent", "/dip-executor-abcdef0123456789"],
    ["--network", "none"],
    ["--ipc", "none"],
    ["--pid", "private"],
    ["--uts", "private"],
    ["--userns", "private"],
    ["--cap-drop", "ALL"],
    ["--memory", String(SYNTHETIC_PROFILE.memoryBytes)],
    ["--cpu-quota", String(SYNTHETIC_PROFILE.cpuQuotaMicros)],
    ["--cpu-period", String(SYNTHETIC_PROFILE.cpuPeriodMicros)],
    ["--pids-limit", String(SYNTHETIC_PROFILE.pidsLimit)],
    ["--user", "10001:10001"],
    ["--workdir", "/work"],
    ["--log-driver", "none"],
  ];
  for (const [flag, expected] of required) {
    assert.equal(valueOf(argv, flag), expected, `${flag} must be ${expected}`);
  }
});

test("R7D.1-P-2: swap is zero, expressed as memory-swap equal to memory", () => {
  // `--memory-swap` equal to `--memory` is how Docker expresses "no additional swap" for a
  // cgroup. Omitting it leaves the default, which is twice the memory limit.
  const argv = buildCreateArgv(policy());
  assert.equal(valueOf(argv, "--memory-swap"), valueOf(argv, "--memory"));
});

test("R7D.1-P-3: the root filesystem is read-only and the scratch mount is hardened", () => {
  const argv = buildCreateArgv(policy());
  assert.ok(argv.includes("--read-only"), "root must be read-only");
  const tmpfs = allValuesOf(argv, "--tmpfs");
  assert.equal(tmpfs.length, 2, "expected the work mount and the masked mqueue mount");
  const [work, mqueue] = tmpfs;
  assert.match(work, /^\/work:rw,noexec,nosuid,nodev,size=50331648$/u);
  // /dev/mqueue stays writable in a default container; it is masked explicitly.
  assert.match(mqueue, /^\/dev\/mqueue:/u);
  assert.match(mqueue, /noexec/u);
  assert.match(mqueue, /nosuid/u);
  assert.match(mqueue, /nodev/u);
});

test("R7D.1-P-4: security profiles are named, never disabled", () => {
  const argv = buildCreateArgv(policy());
  const securityOpts = allValuesOf(argv, "--security-opt");
  assert.ok(securityOpts.includes("no-new-privileges"), "no-new-privileges is mandatory");
  assert.ok(securityOpts.includes("seccomp=runtime/default"));
  assert.ok(securityOpts.includes("apparmor=dip-executor"));
  assert.equal(securityOpts.includes("seccomp=unconfined"), false);
  assert.equal(securityOpts.includes("apparmor=unconfined"), false);
});

test("R7D.1-P-5: no host namespaces, ports, mounts, devices or capabilities are requested", () => {
  const argv = buildCreateArgv(policy());
  for (const forbidden of ["--privileged", "--publish", "-p", "--volume", "-v", "--mount", "--device", "--cap-add", "--restart"]) {
    assert.equal(argv.includes(forbidden), false, `${forbidden} must never be emitted`);
  }
  // Every namespace that would share with the host is set to private.
  for (const flag of ["--pid", "--uts", "--userns"]) {
    assert.equal(valueOf(argv, flag), "private", `${flag} must be private`);
  }
});

test("R7D.1-P-6: core dumps are disabled", () => {
  const argv = buildCreateArgv(policy());
  assert.equal(valueOf(argv, "--ulimit"), "core=0");
});

test("R7D.1-P-7: the only label carries an opaque id, never content", () => {
  const argv = buildCreateArgv(policy());
  const labels = allValuesOf(argv, "--label");
  assert.equal(labels.length, 1);
  assert.match(labels[0], /^dip\.execution=[a-f0-9]{32}$/u, "the label must be the opaque execution id");
});

// ---------------------------------------------------------------------------------------
// The policy itself is enforced, not merely conventional.
// ---------------------------------------------------------------------------------------

test("R7D.1-E-1: a mutable image tag is refused", () => {
  assert.throws(() => assertDigestPinnedImage("dip-executor:latest"), /mutable image reference/u);
  assert.throws(() => assertDigestPinnedImage(`dip-executor@sha256:${"z".repeat(64)}`), /mutable image reference/u);
  assert.throws(() => assertDigestPinnedImage(`dip-executor@sha256:${"a".repeat(63)}`), /mutable image reference/u);
  assert.doesNotThrow(() => assertDigestPinnedImage(`dip-executor@${DIGEST}`));
});

test("R7D.1-E-2: a cgroup parent outside the dedicated namespace is refused", () => {
  assert.throws(() => assertDedicatedCgroupParent("/"), /dedicated DIP namespace/u);
  assert.throws(() => assertDedicatedCgroupParent("/system.slice"), /dedicated DIP namespace/u);
  assert.throws(() => assertDedicatedCgroupParent("/dip-executor-../etc"), /dedicated DIP namespace/u);
  assert.doesNotThrow(() => assertDedicatedCgroupParent("/dip-executor-abcdef0123456789"));
});

test("R7D.1-E-3: an unconfined security profile is refused at construction", () => {
  assert.throws(() => buildCreateArgv(policy({ seccompProfile: "unconfined" })), /mandatory security profile/u);
  assert.throws(() => buildCreateArgv(policy({ apparmorProfile: "unconfined" })), /mandatory security profile/u);
});

test("R7D.1-E-4: assertNoForbiddenFlags rejects each forbidden flag in both forms", () => {
  for (const forbidden of FORBIDDEN_FLAGS) {
    assert.throws(() => assertNoForbiddenFlags(["run", forbidden]), /forbidden docker flag/u, `bare ${forbidden}`);
    assert.throws(() => assertNoForbiddenFlags(["run", `${forbidden}=x`]), /forbidden docker flag/u, `valued ${forbidden}`);
  }
  assert.doesNotThrow(() => assertNoForbiddenFlags(["create", "--name", "x"]));
});

test("R7D.1-E-5: every emitted flag is in the supported allowlist", () => {
  // A flag that appears in argv but not in SUPPORTED_FLAGS is a bug by definition. This is
  // what stops an unreviewed option from being added to a command shape by a future edit.
  const argv = [...buildCreateArgv(policy()), ...buildStartArgv("n"), ...buildRemoveArgv("n"), ...buildInspectArgv("n")];
  const flags = argv.filter((arg) => arg.startsWith("-"));
  for (const flag of flags) {
    assert.ok((SUPPORTED_FLAGS as readonly string[]).includes(flag), `unsupported flag emitted: ${flag}`);
  }
});

// ---------------------------------------------------------------------------------------
// Effective-state verification shape.
// ---------------------------------------------------------------------------------------

test("R7D.1-I-1: inspect asks for exactly the fields the preflight verifies", () => {
  const argv = buildInspectArgv("dip-exec-x");
  const format = valueOf(argv, "--format");
  assert.ok(format, "inspect must use an explicit format");
  for (const field of [".HostConfig.CgroupParent", ".Config.User", ".HostConfig.NetworkMode", ".HostConfig.IpcMode", ".HostConfig.PidMode", ".HostConfig.ReadonlyRootfs", ".HostConfig.Memory", ".HostConfig.MemorySwap", ".HostConfig.RestartPolicy.Name", ".HostConfig.LogConfig.Type", ".HostConfig.Privileged"]) {
    assert.ok(format?.includes(field), `inspect format must include ${field}`);
  }
  assert.equal(argv.includes("--type"), true, "inspect must be typed, so an image or volume of the same name is not returned");
});

// ---------------------------------------------------------------------------------------
// Minimal fixed environment.
// ---------------------------------------------------------------------------------------

test("R7D.1-V-1: the Docker environment is an allowlist and cannot redirect the daemon", () => {
  assert.equal(DOCKER_BIN, "/usr/bin/docker", "the CLI path must be absolute and fixed");
  // DOCKER_HOST would let an inherited variable point the supervisor at a remote daemon,
  // putting containers outside host cgroup accounting and watchdog reach.
  assert.equal("DOCKER_HOST" in DOCKER_ENV, false, "DOCKER_HOST must not be inherited");
  assert.equal("DOCKER_CONFIG" in DOCKER_ENV, false, "DOCKER_CONFIG must not be inherited");
  // No proxy or application secret may leak into the daemon client.
  const keys = Object.keys(DOCKER_ENV);
  assert.deepEqual(keys.sort(), ["DOCKER_CLI_HINTS", "NODE_ENV", "PATH"]);
});
