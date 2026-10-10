import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const EXPECTED = Object.freeze({
  imageUser: "clamav",
  uid: "101",
  gid: "102",
  network: "dip-stage7-private",
  memoryBytes: 3 * 1024 * 1024 * 1024,
  nanoCpus: 2_000_000_000,
  pidsLimit: 256,
  databaseDestination: "/var/lib/clamav",
  tmpfs: Object.freeze({
    "/tmp": 1024 * 1024 * 1024,
    "/run/clamav": 64 * 1024 * 1024,
    "/var/log/clamav": 64 * 1024 * 1024,
  }),
});

export class RuntimeVerificationError extends Error {
  constructor(classification, detail) {
    super(`${classification}: ${detail}`);
    this.name = "RuntimeVerificationError";
    this.classification = classification;
    this.detail = detail;
  }
}

function fail(classification, detail) {
  throw new RuntimeVerificationError(classification, detail);
}

function sanitizeDiagnostic(value) {
  return String(value ?? "unknown").replace(/[^A-Za-z0-9_./:=+-]/g, "_").slice(0, 240);
}

function requireCondition(condition, classification, detail) {
  if (!condition) fail(classification, detail);
}

function parseJsonArray(value, classification) {
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    fail(classification, "malformed_json");
  }
  requireCondition(Array.isArray(parsed) && parsed.length === 1, classification, "expected_one_object");
  return parsed[0];
}

export function parseClamdCommandLine(commandLine) {
  const args = String(commandLine).split("\0").filter(Boolean);
  requireCondition(args.length > 0, "runtime_config_unresolved", "empty_pid1_cmdline");
  requireCondition(posix.basename(args[0]) === "clamd", "runtime_config_unresolved", "pid1_is_not_clamd");

  const configPaths = [];
  for (let index = 1; index < args.length; index += 1) {
    if (args[index] === "--config-file") {
      if (index + 1 >= args.length) {
        fail("runtime_config_unresolved", "config_argument_missing_value");
      }
      configPaths.push(args[index + 1]);
      index += 1;
    } else if (args[index].startsWith("--config-file=")) {
      configPaths.push(args[index].slice("--config-file=".length));
    }
  }

  requireCondition(configPaths.length === 1, "runtime_config_unresolved", `config_argument_count=${configPaths.length}`);
  const configPath = configPaths[0];
  requireCondition(configPath.startsWith("/"), "runtime_config_unresolved", "config_path_not_absolute");
  requireCondition(posix.normalize(configPath) === configPath, "runtime_config_unresolved", "config_path_not_normalized");
  requireCondition(posix.basename(configPath) === "clamd.conf", "runtime_config_unresolved", "config_filename_not_clamd_conf");
  return { args, configPath };
}

export function parseAlertExceedsMaxDefinitions(configText) {
  const definitions = [];
  const malformed = [];

  for (const [zeroBasedLine, originalLine] of String(configText).split(/\r?\n/).entries()) {
    const uncommented = originalLine.replace(/\s+#.*$/, "").trim();
    if (!uncommented || uncommented.startsWith("#")) continue;
    const match = uncommented.match(/^AlertExceedsMax(?:\s+(\S+))?(?:\s+.*)?$/i);
    if (!match) continue;
    const value = match[1]?.toLowerCase();
    if (!value || uncommented.split(/\s+/).length !== 2) {
      malformed.push(zeroBasedLine + 1);
    } else {
      definitions.push({ line: zeroBasedLine + 1, value });
    }
  }

  if (malformed.length > 0) {
    fail("alert_exceeds_max_malformed", `lines=${malformed.join(",")}`);
  }
  if (definitions.length === 0) {
    fail("alert_exceeds_max_missing", "definitions=0");
  }

  const values = new Set(definitions.map(({ value }) => value));
  if (values.size > 1) {
    fail("alert_exceeds_max_conflict", `values=${[...values].sort().join(",")}`);
  }
  const [value] = values;
  if (value !== "yes") {
    fail("alert_exceeds_max_disabled", `value=${sanitizeDiagnostic(value)}`);
  }

  return { value, definitions };
}

export function parseClamconfAlertExceedsMax(clamconfOutput, expectedConfigName = "clamd.conf") {
  const lines = String(clamconfOutput).split(/\r?\n/);
  let inExpectedSection = false;
  const values = [];

  for (const line of lines) {
    const section = line.match(/^Config file:\s+(.+)\s*$/);
    if (section) {
      inExpectedSection = section[1].trim() === expectedConfigName;
      continue;
    }
    if (!inExpectedSection) continue;
    const match = line.match(/^AlertExceedsMax\s*=\s*"([^"]*)"\s*$/);
    if (match) values.push(match[1].toLowerCase());
  }

  requireCondition(values.length === 1, "clamconf_effective_value_unresolved", `value_count=${values.length}`);
  requireCondition(values[0] === "yes", "clamconf_effective_value_disabled", `value=${sanitizeDiagnostic(values[0])}`);
  return values[0];
}

export function classifySupplementalRuntimeLog(logText) {
  const text = String(logText);
  return {
    semanticMessage: text.includes("Heuristic alerting enabled for scans that exceed set maximums."),
    legacyLiteral: text.includes("AlertExceedsMax: enabled"),
  };
}

function parseSize(value) {
  const match = String(value).toLowerCase().match(/^(\d+)([kmgt])?$/);
  if (!match) return null;
  const exponent = match[2] ? "kmgt".indexOf(match[2]) + 1 : 0;
  return Number(match[1]) * (1024 ** exponent);
}

function parseTmpfsOptions(value) {
  const flags = new Set();
  const keyed = new Map();
  for (const token of String(value).split(",")) {
    const [key, ...rest] = token.split("=");
    if (rest.length === 0) flags.add(key);
    else keyed.set(key, rest.join("="));
  }
  return { flags, keyed };
}

function verifyTmpfs(tmpfs) {
  requireCondition(tmpfs && typeof tmpfs === "object", "tmpfs_invalid", "missing");
  for (const [mountPath, expectedSize] of Object.entries(EXPECTED.tmpfs)) {
    const raw = tmpfs[mountPath];
    requireCondition(typeof raw === "string", "tmpfs_invalid", `mount=${mountPath}_missing`);
    const { flags, keyed } = parseTmpfsOptions(raw);
    for (const flag of ["rw", "noexec", "nosuid"]) {
      requireCondition(flags.has(flag), "tmpfs_invalid", `mount=${mountPath}_missing_${flag}`);
    }
    requireCondition(!flags.has("exec") && !flags.has("suid"), "tmpfs_invalid", `mount=${mountPath}_unsafe_flag`);
    requireCondition(keyed.get("uid") === EXPECTED.uid, "tmpfs_invalid", `mount=${mountPath}_uid`);
    requireCondition(keyed.get("gid") === EXPECTED.gid, "tmpfs_invalid", `mount=${mountPath}_gid`);
    requireCondition(parseSize(keyed.get("size")) === expectedSize, "tmpfs_invalid", `mount=${mountPath}_size`);
  }
}

function defaultDocker(args, options = {}) {
  return execFileSync("docker", args, {
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  });
}

function invokeDocker(docker, args, classification, detail) {
  try {
    return docker(args);
  } catch {
    fail(classification, detail);
  }
}

export function verifyClamdConfiguration({ commandLine, configText, clamconfOutput, runtimeLog = "" }) {
  const { configPath } = parseClamdCommandLine(commandLine);
  const rawConfig = parseAlertExceedsMaxDefinitions(configText);
  const effectiveValue = parseClamconfAlertExceedsMax(clamconfOutput, posix.basename(configPath));
  const supplementalLog = classifySupplementalRuntimeLog(runtimeLog);
  return { configPath, rawConfig, effectiveValue, supplementalLog };
}

export function verifyRuntimeIsolation({
  containerName,
  image,
  evidenceDir,
  runtimeLogPath,
  docker = defaultDocker,
  logger = console,
}) {
  requireCondition(containerName, "input_invalid", "container_name_missing");
  requireCondition(image, "input_invalid", "image_missing");
  requireCondition(evidenceDir, "input_invalid", "evidence_dir_missing");

  const imageInspect = parseJsonArray(
    invokeDocker(docker, ["image", "inspect", image], "image_inspect_invalid", "docker_command_failed"),
    "image_inspect_invalid",
  );
  const containerInspect = parseJsonArray(
    invokeDocker(docker, ["inspect", containerName], "container_inspect_invalid", "docker_command_failed"),
    "container_inspect_invalid",
  );
  const host = containerInspect.HostConfig ?? {};
  const state = containerInspect.State ?? {};

  requireCondition(imageInspect.Config?.User === EXPECTED.imageUser, "image_user_invalid", `value=${sanitizeDiagnostic(imageInspect.Config?.User)}`);
  logger.log(`RUNTIME_ISOLATION_PASS image_user=${EXPECTED.imageUser}`);
  requireCondition(host.ReadonlyRootfs === true, "readonly_rootfs_invalid", `value=${sanitizeDiagnostic(host.ReadonlyRootfs)}`);
  logger.log("RUNTIME_ISOLATION_PASS readonly_rootfs=true");
  requireCondition(Array.isArray(host.CapDrop) && host.CapDrop.includes("ALL"), "cap_drop_invalid", "ALL_missing");
  requireCondition(!Array.isArray(host.CapAdd) || host.CapAdd.length === 0, "cap_add_invalid", "unexpected_capability");
  logger.log("RUNTIME_ISOLATION_PASS cap_drop=ALL");
  requireCondition(Array.isArray(host.SecurityOpt) && host.SecurityOpt.includes("no-new-privileges:true"), "no_new_privileges_invalid", "missing_or_false");
  logger.log("RUNTIME_ISOLATION_PASS no_new_privileges=true");
  requireCondition(Object.keys(host.PortBindings ?? {}).length === 0, "published_ports_invalid", "nonzero");
  logger.log("RUNTIME_ISOLATION_PASS published_ports=0");

  const uid = invokeDocker(docker, ["exec", containerName, "id", "-u"], "runtime_uid_invalid", "docker_exec_failed").trim();
  const gid = invokeDocker(docker, ["exec", containerName, "id", "-g"], "runtime_gid_invalid", "docker_exec_failed").trim();
  requireCondition(uid === EXPECTED.uid, "runtime_uid_invalid", `value=${sanitizeDiagnostic(uid)}`);
  requireCondition(gid === EXPECTED.gid, "runtime_gid_invalid", `value=${sanitizeDiagnostic(gid)}`);
  logger.log(`RUNTIME_ISOLATION_PASS uid=${uid} gid=${gid}`);

  requireCondition(host.NetworkMode === EXPECTED.network, "network_isolation_invalid", `value=${sanitizeDiagnostic(host.NetworkMode)}`);
  logger.log(`RUNTIME_ISOLATION_PASS network=${EXPECTED.network}`);
  requireCondition(host.Memory === EXPECTED.memoryBytes, "memory_limit_invalid", `value=${sanitizeDiagnostic(host.Memory)}`);
  requireCondition(host.NanoCpus === EXPECTED.nanoCpus, "cpu_limit_invalid", `value=${sanitizeDiagnostic(host.NanoCpus)}`);
  requireCondition(host.PidsLimit === EXPECTED.pidsLimit, "pids_limit_invalid", `value=${sanitizeDiagnostic(host.PidsLimit)}`);
  logger.log(`RUNTIME_ISOLATION_PASS memory_bytes=${host.Memory} nano_cpus=${host.NanoCpus} pids_limit=${host.PidsLimit}`);

  const databaseMounts = (containerInspect.Mounts ?? []).filter(({ Destination }) => Destination === EXPECTED.databaseDestination);
  requireCondition(databaseMounts.length === 1, "database_mount_invalid", `count=${databaseMounts.length}`);
  requireCondition(databaseMounts[0].RW === false, "database_mount_invalid", "read_only=false");
  logger.log(`RUNTIME_ISOLATION_PASS database_mount=${EXPECTED.databaseDestination}:ro`);
  verifyTmpfs(host.Tmpfs);
  logger.log("RUNTIME_ISOLATION_PASS tmpfs=bounded_noexec_nosuid");

  requireCondition(state.Health?.Status === "healthy", "container_health_invalid", `value=${sanitizeDiagnostic(state.Health?.Status)}`);
  logger.log("RUNTIME_ISOLATION_PASS health=healthy");

  const commandLine = invokeDocker(
    docker,
    ["exec", containerName, "cat", "/proc/1/cmdline"],
    "runtime_config_unresolved",
    "pid1_cmdline_unreadable",
  );
  const { configPath } = parseClamdCommandLine(commandLine);
  const configText = invokeDocker(
    docker,
    ["exec", containerName, "cat", configPath],
    "runtime_config_unreadable",
    `path=${configPath}`,
  );
  const configDirectory = posix.dirname(configPath);
  const clamconfOutput = invokeDocker(
    docker,
    [
      "exec",
      containerName,
      "/usr/bin/clamconf",
      `--config-dir=${configDirectory}`,
      "--non-default",
    ],
    "clamconf_effective_query_failed",
    `config_dir=${configDirectory}`,
  );
  const runtimeLog = runtimeLogPath ? readFileSync(runtimeLogPath, "utf8") : "";
  const clamd = verifyClamdConfiguration({ commandLine, configText, clamconfOutput, runtimeLog });

  logger.log(`CLAMD_CONFIG_PASS runtime_config=${clamd.configPath} source=pid1_cmdline`);
  logger.log(`CLAMD_CONFIG_PASS AlertExceedsMax=${clamd.effectiveValue} source=clamconf definitions=${clamd.rawConfig.definitions.length}`);
  if (clamd.supplementalLog.semanticMessage) {
    logger.log("SUPPLEMENTAL_RUNTIME_LOG_EVIDENCE semantic_alert_exceeds_max=present");
  } else if (clamd.supplementalLog.legacyLiteral) {
    logger.log("SUPPLEMENTAL_RUNTIME_LOG_EVIDENCE legacy_alert_exceeds_max=present");
  } else {
    logger.log("SUPPLEMENTAL_RUNTIME_LOG_EVIDENCE alert_exceeds_max_message=absent");
  }

  const evidence = {
    result: "pass",
    imageUser: imageInspect.Config.User,
    runtime: { uid, gid, health: state.Health.Status },
    isolation: {
      readonlyRootfs: host.ReadonlyRootfs,
      capDrop: host.CapDrop,
      capAdd: host.CapAdd ?? [],
      securityOpt: host.SecurityOpt,
      publishedPortBindings: Object.keys(host.PortBindings ?? {}).length,
      networkMode: host.NetworkMode,
      memoryBytes: host.Memory,
      nanoCpus: host.NanoCpus,
      pidsLimit: host.PidsLimit,
      databaseMountReadOnly: databaseMounts[0].RW === false,
      tmpfs: host.Tmpfs,
    },
    clamd: {
      pid1Executable: "clamd",
      runtimeConfigPath: clamd.configPath,
      alertExceedsMax: clamd.effectiveValue,
      rawDefinitionCount: clamd.rawConfig.definitions.length,
      verificationSource: "clamconf-effective-config-bound-to-pid1-config-path",
      supplementalRuntimeLog: clamd.supplementalLog,
    },
  };
  writeFileSync(resolve(evidenceDir, "runtime-isolation-verification.json"), `${JSON.stringify(evidence, null, 2)}\n`);
  return evidence;
}

function isDirectExecution() {
  return process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
}

if (isDirectExecution()) {
  try {
    verifyRuntimeIsolation({
      containerName: process.env.CLAMAV_CONTAINER_NAME ?? "clamav-stage7",
      image: process.env.CLAMAV_IMAGE ?? process.env.IMAGE_BY_DIGEST,
      evidenceDir: process.env.EVIDENCE_DIR,
      runtimeLogPath: process.env.CLAMAV_RUNTIME_LOG ?? resolve(process.env.EVIDENCE_DIR ?? ".", "clamd-runtime.log"),
    });
  } catch (error) {
    if (error instanceof RuntimeVerificationError) {
      const configFailure = /^(alert_exceeds_max|clamconf_|runtime_config_)/.test(error.classification);
      const prefix = configFailure ? "CLAMD_CONFIG_FAIL" : "RUNTIME_ISOLATION_FAIL";
      console.error(`${prefix} classification=${error.classification} detail=${sanitizeDiagnostic(error.detail)}`);
      process.exitCode = 1;
    } else {
      console.error("CLAMD_CONFIG_FAIL classification=unexpected_error");
      process.exitCode = 1;
    }
  }
}
