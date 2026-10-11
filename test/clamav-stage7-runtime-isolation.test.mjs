import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  RuntimeVerificationError,
  classifySupplementalRuntimeLog,
  parseAlertExceedsMaxDefinitions,
  parseClamdCommandLine,
  parseProcStatus,
  verifyClamdConfiguration,
  verifyRuntimeProcessIdentity,
  verifyRuntimeIsolation,
} from "../scripts/experiments/verify-clamav-runtime-isolation.mjs";

const COMMAND = "/usr/sbin/clamd\0--config-file=/etc/clamav/clamd.conf\0--foreground\0";
const WRAPPER = "/usr/local/bin/clamd-freshness-gate";
const DAEMON = "/usr/sbin/clamd";
const CONFIG = "/etc/clamav/clamd.conf";
const DOCKER_ARGS = ["--exec", DAEMON, `--config-file=${CONFIG}`, "--foreground"];
const IMAGE_ENTRYPOINT = [WRAPPER, ...DOCKER_ARGS];
const PROC_STATUS = [
  "Name:\tclamd",
  "State:\tS (sleeping)",
  "Pid:\t1",
  "PPid:\t0",
  "TracerPid:\t0",
  "NoNewPrivs:\t1",
  "Seccomp:\t2",
  "",
].join("\n");
const QEMU_COMMAND = ["/usr/bin/qemu-aarch64", DAEMON, DAEMON, `--config-file=${CONFIG}`, "--foreground"];
const CLAMCONF_ENABLED = [
  "Checking configuration files in /etc/clamav",
  "",
  "Config file: clamd.conf",
  "-----------------------",
  'AlertExceedsMax = "yes"',
  "",
  "Config file: freshclam.conf",
].join("\n");
const WORKFLOW = readFileSync(new URL("../.github/workflows/clamav-stage7-private-ghcr.yml", import.meta.url), "utf8");

function verify(configText, options = {}) {
  return verifyClamdConfiguration({
    commandLine: options.commandLine ?? COMMAND,
    configText,
    clamconfOutput: options.clamconfOutput ?? CLAMCONF_ENABLED,
    runtimeLog: options.runtimeLog ?? "",
  });
}

function expectClassification(run, classification) {
  assert.throws(run, (error) => {
    assert.ok(error instanceof RuntimeVerificationError);
    assert.equal(error.classification, classification);
    return true;
  });
}

function identity(overrides = {}) {
  return verifyRuntimeProcessIdentity({
    dockerPath: WRAPPER,
    dockerArgs: DOCKER_ARGS,
    imageArchitecture: "arm64",
    imageOs: "linux",
    imageEntrypoint: IMAGE_ENTRYPOINT,
    imageCmd: null,
    hostArchitecture: "x86_64",
    proc1Cmdline: `${QEMU_COMMAND.join("\0")}\0`,
    proc1Exe: "/usr/bin/qemu-aarch64",
    proc1Comm: "clamd\n",
    proc1Status: PROC_STATUS,
    ...overrides,
  });
}

test("native clamd PID1 passes with the declared guest command", () => {
  const result = identity({
    hostArchitecture: "aarch64",
    proc1Cmdline: COMMAND,
    proc1Exe: DAEMON,
  });
  assert.equal(result.mode, "native-clamd");
  assert.equal(result.configPath, CONFIG);
});

test("native clamd accepts a separate config-file argument", () => {
  const dockerArgs = ["--exec", DAEMON, "--config-file", CONFIG, "--foreground"];
  const result = identity({
    dockerArgs,
    imageEntrypoint: [WRAPPER, ...dockerArgs],
    hostArchitecture: "arm64",
    proc1Cmdline: `${[DAEMON, "--config-file", CONFIG, "--foreground"].join("\0")}\0`,
    proc1Exe: DAEMON,
  });
  assert.equal(result.mode, "native-clamd");
  assert.equal(result.configPath, CONFIG);
});

test("native clamd accepts the observed equals config-file argument", () => {
  assert.equal(parseClamdCommandLine(COMMAND).configPath, CONFIG);
});

test("the exact observed QEMU ARM64 identity passes", () => {
  const result = identity();
  assert.equal(result.mode, "qemu-arm64-clamd");
  assert.deepEqual(result.procArgs, QEMU_COMMAND);
  assert.equal(result.logicalExecutable, DAEMON);
});

test("QEMU with a non-clamd guest target fails closed", () => {
  const command = ["/usr/bin/qemu-aarch64", "/usr/bin/freshclam", "/usr/bin/freshclam", `--config-file=${CONFIG}`];
  expectClassification(() => identity({ proc1Cmdline: `${command.join("\0")}\0` }), "qemu_guest_target_unresolved");
});

test("QEMU with an ambiguous guest argv0 fails closed", () => {
  const command = ["/usr/bin/qemu-aarch64", DAEMON, "/usr/bin/freshclam", `--config-file=${CONFIG}`, "--foreground"];
  expectClassification(() => identity({ proc1Cmdline: `${command.join("\0")}\0` }), "qemu_guest_target_unresolved");
});

test("an unexpected wrapper fails closed", () => {
  expectClassification(
    () => identity({ dockerPath: "/bin/sh", dockerArgs: ["-c", DAEMON], imageEntrypoint: ["/bin/sh", "-c", DAEMON] }),
    "unexpected_runtime_wrapper",
  );
});

test("Docker command claiming direct clamd while proc evidence is QEMU fails closed", () => {
  expectClassification(
    () => identity({ dockerPath: DAEMON, dockerArgs: [`--config-file=${CONFIG}`], imageEntrypoint: [DAEMON, `--config-file=${CONFIG}`] }),
    "unexpected_runtime_wrapper",
  );
});

test("proc evidence claiming clamd while Docker command targets another daemon fails closed", () => {
  const dockerArgs = ["--exec", "/usr/bin/freshclam", `--config-file=${CONFIG}`];
  expectClassification(
    () => identity({
      dockerArgs,
      imageEntrypoint: [WRAPPER, ...dockerArgs],
      hostArchitecture: "aarch64",
      proc1Cmdline: COMMAND,
      proc1Exe: DAEMON,
    }),
    "unexpected_runtime_wrapper",
  );
});

test("multiple runtime config paths fail closed", () => {
  const dockerArgs = ["--exec", DAEMON, `--config-file=${CONFIG}`, "--config-file=/tmp/clamd.conf"];
  expectClassification(
    () => identity({ dockerArgs, imageEntrypoint: [WRAPPER, ...dockerArgs] }),
    "config_path_conflict",
  );
});

test("a missing runtime config path fails closed", () => {
  const dockerArgs = ["--exec", DAEMON, "--foreground"];
  expectClassification(
    () => identity({ dockerArgs, imageEntrypoint: [WRAPPER, ...dockerArgs] }),
    "config_argument_unresolved",
  );
});

test("malformed or incomplete proc status fails closed", () => {
  expectClassification(() => identity({ proc1Status: "Name:\tclamd\nPid:\t1\n" }), "pid1_identity_unresolved");
});

test("unexpected QEMU executable fails closed", () => {
  expectClassification(() => identity({ proc1Exe: "/usr/bin/qemu-arm" }), "qemu_guest_target_unresolved");
});

test("QEMU is refused on an unapproved host architecture", () => {
  expectClassification(() => identity({ hostArchitecture: "riscv64" }), "pid1_identity_unresolved");
});

test("Docker and image-declared commands must match exactly", () => {
  expectClassification(() => identity({ dockerArgs: [...DOCKER_ARGS, "--debug"] }), "docker_runtime_command_mismatch");
});

test("proc status parsing preserves only the identity/security allowlist", () => {
  const parsed = parseProcStatus(`${PROC_STATUS}Env:\tSECRET=value\n`);
  assert.deepEqual(Object.keys(parsed), ["Name", "State", "Pid", "PPid", "TracerPid", "NoNewPrivs", "Seccomp"]);
  assert.equal(parsed.Env, undefined);
});

test("effective config explicitly enabled passes", () => {
  const result = verify("AlertExceedsMax yes\n");
  assert.equal(result.effectiveValue, "yes");
  assert.equal(result.configPath, "/etc/clamav/clamd.conf");
});

test("missing option fails closed", () => {
  expectClassification(() => verify("MaxFiles 10000\n"), "alert_exceeds_max_missing");
});

test("disabled option fails closed", () => {
  expectClassification(() => verify("AlertExceedsMax no\n"), "alert_exceeds_max_disabled");
});

test("malformed option fails closed", () => {
  expectClassification(() => verify("AlertExceedsMax\n"), "alert_exceeds_max_malformed");
});

test("duplicate identical enabled definitions pass deterministically", () => {
  const parsed = parseAlertExceedsMaxDefinitions("AlertExceedsMax yes\nAlertExceedsMax yes\n");
  assert.equal(parsed.value, "yes");
  assert.equal(parsed.definitions.length, 2);
});

test("conflicting duplicate definitions fail closed", () => {
  expectClassification(
    () => parseAlertExceedsMaxDefinitions("AlertExceedsMax yes\nAlertExceedsMax no\n"),
    "alert_exceeds_max_conflict",
  );
});

test("ClamAV 1.5.4 semantic log wording is supplemental evidence", () => {
  const result = verify("AlertExceedsMax yes\n", {
    runtimeLog: "Heuristic alerting enabled for scans that exceed set maximums.\n",
  });
  assert.equal(result.supplementalLog.semanticMessage, true);
});

test("missing old literal does not fail when effective config is enabled", () => {
  const result = verify("AlertExceedsMax yes\n", { runtimeLog: "clamd started\n" });
  assert.deepEqual(result.supplementalLog, { semanticMessage: false, legacyLiteral: false });
});

test("enabled config without a proven runtime config path fails closed", () => {
  expectClassification(
    () => verify("AlertExceedsMax yes\n", { commandLine: "/usr/sbin/clamd\0--foreground\0" }),
    "config_argument_unresolved",
  );
});

test("enabled value in an unrelated file cannot override the consumed runtime config", () => {
  const unrelatedConfig = "AlertExceedsMax yes\n";
  assert.equal(parseAlertExceedsMaxDefinitions(unrelatedConfig).value, "yes");
  expectClassification(
    () => verify("AlertExceedsMax no\n"),
    "alert_exceeds_max_disabled",
  );
});

test("effective clamconf output must independently report enabled", () => {
  const disabledClamconf = CLAMCONF_ENABLED.replace('"yes"', '"no"');
  expectClassification(
    () => verify("AlertExceedsMax yes\n", { clamconfOutput: disabledClamconf }),
    "clamconf_effective_value_disabled",
  );
});

test("multiple runtime config arguments fail closed", () => {
  expectClassification(
    () => parseClamdCommandLine("/usr/sbin/clamd\0--config-file=/etc/clamav/clamd.conf\0--config-file=/tmp/clamd.conf\0"),
    "config_path_conflict",
  );
});

test("supplemental classifier distinguishes semantic and legacy messages", () => {
  assert.deepEqual(
    classifySupplementalRuntimeLog("Heuristic alerting enabled for scans that exceed set maximums."),
    { semanticMessage: true, legacyLiteral: false },
  );
  assert.deepEqual(
    classifySupplementalRuntimeLog("AlertExceedsMax: enabled"),
    { semanticMessage: false, legacyLiteral: true },
  );
});

test("full verifier positively checks every Stage 7 isolation control", async () => {
  const evidenceDir = await mkdtemp(join(tmpdir(), "dip-clamav-runtime-"));
  const runtimeLogPath = join(evidenceDir, "clamd-runtime.log");
  await writeFile(runtimeLogPath, "Heuristic alerting enabled for scans that exceed set maximums.\n");
  const image = "ghcr.io/mansour1414/dip-clamav@sha256:test";
  const container = "clamav-stage7";
  const imageInspect = [{
    Architecture: "arm64",
    Os: "linux",
    Config: { User: "clamav", Entrypoint: IMAGE_ENTRYPOINT, Cmd: null },
  }];
  const containerInspect = [{
    Path: WRAPPER,
    Args: DOCKER_ARGS,
    HostConfig: {
      ReadonlyRootfs: true,
      CapDrop: ["ALL"],
      SecurityOpt: ["no-new-privileges:true"],
      PortBindings: {},
      NetworkMode: "dip-stage7-private",
      Memory: 3 * 1024 * 1024 * 1024,
      NanoCpus: 2_000_000_000,
      PidsLimit: 256,
      Tmpfs: {
        "/tmp": "rw,noexec,nosuid,size=1g,uid=101,gid=102",
        "/run/clamav": "rw,noexec,nosuid,size=64m,uid=101,gid=102",
        "/var/log/clamav": "rw,noexec,nosuid,size=64m,uid=101,gid=102",
      },
    },
    State: { Health: { Status: "healthy" } },
    Mounts: [{ Type: "bind", Destination: "/var/lib/clamav", RW: false }],
  }];
  const docker = (args) => {
    const key = JSON.stringify(args);
    const responses = new Map([
      [JSON.stringify(["image", "inspect", image]), JSON.stringify(imageInspect)],
      [JSON.stringify(["inspect", container]), JSON.stringify(containerInspect)],
      [JSON.stringify(["exec", container, "id", "-u"]), "101\n"],
      [JSON.stringify(["exec", container, "id", "-g"]), "102\n"],
      [JSON.stringify(["info", "--format", "{{.Architecture}}"]), "aarch64\n"],
      [JSON.stringify(["exec", container, "cat", "/proc/1/cmdline"]), COMMAND],
      [JSON.stringify(["exec", container, "readlink", "/proc/1/exe"]), `${DAEMON}\n`],
      [JSON.stringify(["exec", container, "cat", "/proc/1/comm"]), "clamd\n"],
      [JSON.stringify(["exec", container, "cat", "/proc/1/status"]), PROC_STATUS],
      [JSON.stringify(["exec", container, "cat", "/etc/clamav/clamd.conf"]), "AlertExceedsMax yes\n"],
      [JSON.stringify(["exec", container, "/usr/bin/clamconf", "--config-dir=/etc/clamav", "--non-default"]), CLAMCONF_ENABLED],
    ]);
    if (!responses.has(key)) throw new Error(`Unexpected Docker call: ${key}`);
    return responses.get(key);
  };

  try {
    const result = verifyRuntimeIsolation({
      containerName: container,
      image,
      evidenceDir,
      runtimeLogPath,
      docker,
      logger: { log() {} },
    });
    assert.equal(result.clamd.alertExceedsMax, "yes");
    assert.equal(result.runtimeProcess.mode, "native-clamd");
    assert.equal(result.runtimeProcess.logicalExecutable, DAEMON);
    assert.equal(result.isolation.publishedPortBindings, 0);
    const evidence = JSON.parse(await readFile(join(evidenceDir, "runtime-isolation-verification.json"), "utf8"));
    assert.equal(evidence.result, "pass");
    assert.equal(evidence.runtimeProcess.proc1Exe, DAEMON);
    assert.equal(evidence.clamd.runtimeConfigPath, "/etc/clamav/clamd.conf");
  } finally {
    await rm(evidenceDir, { recursive: true, force: true });
  }
});

test("Stage 7 workflow uses the config verifier and no longer trusts the brittle log literal", () => {
  assert.match(WORKFLOW, /node scripts\/experiments\/verify-clamav-runtime-isolation\.mjs/);
  assert.ok(WORKFLOW.includes("scripts/experiments/verify-clamav-runtime-isolation.mjs \\"));
  assert.doesNotMatch(WORKFLOW, /grep -Fq 'AlertExceedsMax: enabled'/);
});
