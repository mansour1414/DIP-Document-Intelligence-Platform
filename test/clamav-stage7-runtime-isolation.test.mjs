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
  verifyClamdConfiguration,
  verifyRuntimeIsolation,
} from "../scripts/experiments/verify-clamav-runtime-isolation.mjs";

const COMMAND = "/usr/sbin/clamd\0--config-file=/etc/clamav/clamd.conf\0--foreground\0";
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
    "runtime_config_unresolved",
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
    "runtime_config_unresolved",
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
  const imageInspect = [{ Config: { User: "clamav" } }];
  const containerInspect = [{
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
      [JSON.stringify(["exec", container, "cat", "/proc/1/cmdline"]), COMMAND],
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
    assert.equal(result.isolation.publishedPortBindings, 0);
    const evidence = JSON.parse(await readFile(join(evidenceDir, "runtime-isolation-verification.json"), "utf8"));
    assert.equal(evidence.result, "pass");
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
