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
  assertExecutionPolicy,
  assertDigestPinnedImage,
  assertNoForbiddenFlags,
  buildCreateArgv,
  buildInspectArgv,
  buildKillArgv,
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
    executionId: "0123456789abcdef0123456789abcdef",
    bootId: "boot-0001",
    supervisorInstance: "sup-0001",
    profileId: "synthetic-r7d-v1",
    uid: 10001,
    gid: 10001,
    memoryBytes: SYNTHETIC_PROFILE.memoryBytes,
    cpuQuotaMicros: SYNTHETIC_PROFILE.cpuQuotaMicros,
    cpuPeriodMicros: SYNTHETIC_PROFILE.cpuPeriodMicros,
    pidsLimit: SYNTHETIC_PROFILE.pidsLimit,
    tmpfsBudgetBytes: SYNTHETIC_PROFILE.tmpfsBudgetBytes,
    workTmpfsBytes: SYNTHETIC_PROFILE.workTmpfsBytes,
    tmpTmpfsBytes: SYNTHETIC_PROFILE.tmpTmpfsBytes,
    v8OldSpaceMb: SYNTHETIC_PROFILE.v8OldSpaceMb,
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
  const start = buildStartArgv("dip-exec-0123456789abcdef0123456789abcdef");
  assert.deepEqual(start, ["--host", "unix:///var/run/docker.sock", "start", "--attach", "--interactive", "dip-exec-0123456789abcdef0123456789abcdef"]);
  // An arbitrary name is refused: only the derived execution-name form is accepted.
  assert.throws(() => buildStartArgv("something-else"), /unrecognised container name/u);
});

test("R7D.1-D1-4: removal is an explicit named docker rm, never --rm on create", () => {
  // `--rm` on create would auto-remove the container on exit, destroying the cgroup and the
  // metadata the watchdog needs in order to reconcile ownership. Removal must be explicit
  // and after the watchdog grants disarm.
  const create = buildCreateArgv(policy());
  assert.equal(create.includes("--rm"), false, "create must not auto-remove");
  assert.equal(create.includes("--auto-remove"), false);
  const id = "a".repeat(64);
  assert.deepEqual(buildRemoveArgv(id), ["--host", "unix:///var/run/docker.sock", "rm", "--force", id]);
});

test("R7D.1-D1-5: destructive operations require an exact container id, never a name", () => {
  // F01: a name is not an identity. After a race or a restart another container could hold
  // it, and `rm --force <name>` would then destroy something this system does not own.
  assert.throws(() => buildRemoveArgv("dip-exec-0123456789abcdef0123456789abcdef"), /exact 64-hex container id/u);
  assert.throws(() => buildKillArgv("dip-exec-0123456789abcdef0123456789abcdef"), /exact 64-hex container id/u);
  assert.throws(() => buildRemoveArgv("a".repeat(63)), /exact 64-hex container id/u);
  assert.doesNotThrow(() => buildKillArgv("a".repeat(64)));
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
    // F01: --userns/--uts/--pid take no `private` value. --cgroupns does, and it is the
    // documented way to request a private cgroup namespace.
    ["--cgroupns", "private"],
    ["--pull", "never"],
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
  assert.equal(tmpfs.length, 3, "expected work, the bounded /tmp profile, and the masked mqueue mount");
  const [work, tmp, mqueue] = tmpfs;
  // C-F01: the two tmpfs mounts are a split of one approved budget, not two independent
  // allocations. 32 + 16 = 48 MiB.
  assert.match(work, /^\/work:rw,noexec,nosuid,nodev,size=33554432$/u);
  assert.match(tmp, /^\/tmp:rw,noexec,nosuid,nodev,size=16777216$/u);
  const workBytes = Number(/size=(\d+)$/u.exec(work)?.[1]);
  const tmpBytes = Number(/size=(\d+)$/u.exec(tmp)?.[1]);
  assert.equal(workBytes + tmpBytes, SYNTHETIC_PROFILE.tmpfsBudgetBytes, "the split must equal the approved budget");
  assert.ok(workBytes + tmpBytes <= SYNTHETIC_PROFILE.tmpfsBudgetBytes, "never above the approved budget");
  // F01: a *writable* tmpfs at /dev/mqueue is not a mask. It must be read-only.
  assert.match(mqueue, /^\/dev\/mqueue:ro,/u, "the mqueue mask must be read-only");
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
  // F01: the namespace flags with no supported `private` value must not be emitted at all.
  // Their private state is the daemon default and is verified from inspect, not requested
  // with an invented value the CLI would reject.
  for (const flag of ["--pid", "--uts", "--userns"]) {
    assert.equal(argv.includes(flag), false, `${flag} must not be emitted with an unsupported value`);
  }
  assert.equal(valueOf(argv, "--cgroupns"), "private");
});

test("R7D.1-P-6: core dumps are disabled", () => {
  const argv = buildCreateArgv(policy());
  assert.equal(valueOf(argv, "--ulimit"), "core=0");
});

test("R7D.1-P-7: ownership labels are complete, derived and content-free", () => {
  // F01: one label could not tie a container to its boot, supervisor, image and profile, so
  // an orphan from a previous boot could not be distinguished from a current one.
  const argv = buildCreateArgv(policy());
  const labels = allValuesOf(argv, "--label");
  assert.deepEqual(labels.slice().sort(), [
    "dip.boot=boot-0001",
    `dip.execution=0123456789abcdef0123456789abcdef`,
    `dip.image=sha256:${"a".repeat(64)}`,
    "dip.profile=synthetic-r7d-v1",
    "dip.supervisor=sup-0001",
  ].sort());
  for (const label of labels) {
    // Only the five derived identities. No field name, value or digest may appear.
    assert.match(label, /^dip\.(execution|boot|supervisor|image|profile)=[A-Za-z0-9:._-]+$/u);
  }
});

test("R7D.1-P-8: the no-pull policy is explicit, since the daemon default is `missing`", () => {
  // Without this a missing image is fetched at execution time, which turns an immutable
  // allowlist into a suggestion and makes runtime behaviour depend on the network.
  const argv = buildCreateArgv(policy());
  assert.equal(valueOf(argv, "--pull"), "never");
});

test("R7D.1-P-9: the daemon is targeted explicitly, not through ambient configuration", () => {
  const argv = buildCreateArgv(policy());
  assert.equal(valueOf(argv, "--host"), "unix:///var/run/docker.sock");
  // DOCKER_CONFIG is pinned so no inherited context or credential helper applies.
  assert.equal(DOCKER_ENV.DOCKER_CONFIG, "/run/dip-docker-client");
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
  const executable = "a".repeat(64);
  const argv = [
    ...buildCreateArgv(policy()),
    ...buildStartArgv("dip-exec-0123456789abcdef0123456789abcdef"),
    ...buildRemoveArgv(executable),
    ...buildInspectArgv(executable),
  ];
  const flags = argv.filter((arg) => arg.startsWith("-"));
  for (const flag of flags) {
    assert.ok((SUPPORTED_FLAGS as readonly string[]).includes(flag), `unsupported flag emitted: ${flag}`);
  }
});

// ---------------------------------------------------------------------------------------
// Effective-state verification shape.
// ---------------------------------------------------------------------------------------

test("R7D.1-I-1: inspect asks for exactly the fields the preflight verifies", () => {
  const argv = buildInspectArgv("dip-exec-0123456789abcdef0123456789abcdef");
  const format = valueOf(argv, "--format");
  assert.ok(format, "inspect must use an explicit format");
  // F01 added the fields that decide the corrections: cgroupns mode, the three namespace
  // modes that must verify private-by-default, auto-remove, and the label/env sets.
  for (const field of [".HostConfig.CgroupParent", ".Config.User", ".HostConfig.NetworkMode", ".HostConfig.IpcMode", ".HostConfig.PidMode", ".HostConfig.UTSMode", ".HostConfig.UsernsMode", ".HostConfig.CgroupnsMode", ".HostConfig.ReadonlyRootfs", ".HostConfig.Memory", ".HostConfig.MemorySwap", ".HostConfig.RestartPolicy.Name", ".HostConfig.LogConfig.Type", ".HostConfig.Privileged", ".HostConfig.AutoRemove", ".Config.Labels"]) {
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
  // DOCKER_CONFIG is present but *pinned* to a controller-owned directory, which is the
  // point: an inherited value must not reach the client. Absence alone would prove nothing,
  // since Docker would then read the operator's own config and contexts.
  assert.equal(DOCKER_ENV.DOCKER_CONFIG, "/run/dip-docker-client");
  // No proxy or application secret may leak into the daemon client.
  const keys = Object.keys(DOCKER_ENV);
  // F01 added DOCKER_CONFIG (pinned, so no inherited context applies). It must never be
  // allowed to point at a file the supervisor did not create.
  assert.deepEqual(keys.sort(), ["DOCKER_CLI_HINTS", "DOCKER_CONFIG", "NODE_ENV", "PATH"]);
  // No proxy variable may influence how the client reaches the socket.
  for (const key of keys) assert.doesNotMatch(key, /PROXY/iu);
});

// ---------------------------------------------------------------------------------------
// C-F01 — the writable budget is a sum, not a per-mount ceiling
// ---------------------------------------------------------------------------------------

test("R7D.1-CF01-1: the tmpfs split may not exceed the approved writable budget", () => {
  // The defect: /work 48 MiB and /tmp 16 MiB were each validated against a maximum
  // independently, so the container received 64 MiB against an approved 48. The page cache
  // backing a tmpfs is charged to the memory cgroup, so the second mount was an unbudgeted
  // allocation, not a separate resource.
  assert.throws(
    () => assertExecutionPolicy(policy({ workTmpfsBytes: 48 * 1024 * 1024, tmpTmpfsBytes: 16 * 1024 * 1024 })),
    /exceeds the approved/u,
  );
  // Exactly at the budget is acceptable.
  assert.doesNotThrow(() => assertExecutionPolicy(policy({ workTmpfsBytes: 32 * 1024 * 1024, tmpTmpfsBytes: 16 * 1024 * 1024 })));
});

test("R7D.1-CF01-2: every tmpfs in the create argv is accounted for in the budget", () => {
  // /dev/mqueue is a mask, not scratch: it is read-only, so it cannot grow. Anything writable
  // must be part of the 48 MiB.
  const argv = buildCreateArgv(policy());
  const writable = allValuesOf(argv, "--tmpfs").filter((value) => value.includes(":rw,"));
  assert.equal(writable.length, 2, "only the two budgeted mounts may be writable");
  const total = writable.reduce((sum, value) => sum + Number(/size=(\d+)/u.exec(value)?.[1] ?? 0), 0);
  assert.equal(total, SYNTHETIC_PROFILE.tmpfsBudgetBytes);
});

test("R7D.1-CF01-3: no TMPDIR override is injected", () => {
  // `/tmp` is the process default and is a tmpfs because it is mounted there. An env key that
  // restates the default invites the belief that the boundary is configurable; the mount is
  // the boundary.
  const argv = buildCreateArgv(policy());
  assert.equal(argv.some((arg) => arg.startsWith("TMPDIR=")), false);
});
