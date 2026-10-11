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
  imageArchitecture: "arm64",
  imageOs: "linux",
  runtimeWrapper: "/usr/local/bin/clamd-freshness-gate",
  daemonExecutable: "/usr/sbin/clamd",
  runtimeConfig: "/etc/clamav/clamd.conf",
  qemuExecutable: "/usr/bin/qemu-aarch64",
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

function parseClamdArguments(args) {
  requireCondition(Array.isArray(args) && args.length > 0, "pid1_identity_unresolved", "empty_clamd_command");
  requireCondition(args.every((value) => typeof value === "string" && value.length > 0), "pid1_identity_unresolved", "malformed_clamd_command");
  requireCondition(args[0] === EXPECTED.daemonExecutable, "pid1_identity_unresolved", `daemon=${sanitizeDiagnostic(args[0])}`);
  const configPaths = [];
  for (let index = 1; index < args.length; index += 1) {
    if (args[index] === "--config-file") {
      if (index + 1 >= args.length) {
        fail("config_argument_unresolved", "config_argument_missing_value");
      }
      configPaths.push(args[index + 1]);
      index += 1;
    } else if (args[index].startsWith("--config-file=")) {
      configPaths.push(args[index].slice("--config-file=".length));
    }
  }

  if (configPaths.length > 1) {
    fail("config_path_conflict", `config_argument_count=${configPaths.length}`);
  }
  requireCondition(configPaths.length === 1, "config_argument_unresolved", "config_argument_count=0");
  const configPath = configPaths[0];
  requireCondition(configPath.startsWith("/"), "config_argument_unresolved", "config_path_not_absolute");
  requireCondition(posix.normalize(configPath) === configPath, "config_argument_unresolved", "config_path_not_normalized");
  requireCondition(configPath === EXPECTED.runtimeConfig, "config_argument_unresolved", `config_path=${sanitizeDiagnostic(configPath)}`);
  return { args, configPath };
}

export function parseClamdCommandLine(commandLine) {
  return parseClamdArguments(String(commandLine).split("\0").filter(Boolean));
}

function arraysEqual(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function requireStringArray(value, classification, detail) {
  requireCondition(Array.isArray(value), classification, detail);
  requireCondition(value.every((item) => typeof item === "string"), classification, detail);
  return value;
}

export function parseProcStatus(statusText) {
  const allowed = new Set(["Name", "State", "Pid", "PPid", "TracerPid", "NoNewPrivs", "Seccomp"]);
  const status = {};
  for (const line of String(statusText).split(/\r?\n/)) {
    const match = line.match(/^([A-Za-z]+):\s*(.*)$/);
    if (match && allowed.has(match[1])) status[match[1]] = match[2].trim();
  }
  for (const required of allowed) {
    requireCondition(status[required] !== undefined, "pid1_identity_unresolved", `proc_status_${required.toLowerCase()}_missing`);
  }
  return status;
}

function verifyDeclaredRuntimeCommand({ dockerPath, dockerArgs, imageEntrypoint, imageCmd }) {
  const entrypoint = requireStringArray(imageEntrypoint, "docker_runtime_command_mismatch", "image_entrypoint_invalid");
  const cmd = imageCmd === null ? [] : requireStringArray(imageCmd, "docker_runtime_command_mismatch", "image_cmd_invalid");
  const declaredImageCommand = [...entrypoint, ...cmd];
  requireCondition(declaredImageCommand.length > 0, "docker_runtime_command_mismatch", "image_command_empty");
  requireCondition(dockerPath === declaredImageCommand[0], "docker_runtime_command_mismatch", "docker_path_differs_from_image");
  requireCondition(arraysEqual(dockerArgs, declaredImageCommand.slice(1)), "docker_runtime_command_mismatch", "docker_args_differ_from_image");
  requireCondition(dockerPath === EXPECTED.runtimeWrapper, "unexpected_runtime_wrapper", `path=${sanitizeDiagnostic(dockerPath)}`);
  requireCondition(dockerArgs[0] === "--exec", "unexpected_runtime_wrapper", "exec_boundary_missing");
  requireCondition(dockerArgs[1] === EXPECTED.daemonExecutable, "unexpected_runtime_wrapper", `target=${sanitizeDiagnostic(dockerArgs[1])}`);

  const daemonCommand = dockerArgs.slice(1);
  const { configPath } = parseClamdArguments(daemonCommand);
  return { daemonCommand, configPath };
}

export function verifyRuntimeProcessIdentity({
  dockerPath,
  dockerArgs,
  imageArchitecture,
  imageOs,
  imageEntrypoint,
  imageCmd,
  hostArchitecture,
  proc1Cmdline,
  proc1Exe,
  proc1Comm,
  proc1Status,
}) {
  requireCondition(imageArchitecture === EXPECTED.imageArchitecture, "pid1_identity_unresolved", `image_architecture=${sanitizeDiagnostic(imageArchitecture)}`);
  requireCondition(imageOs === EXPECTED.imageOs, "pid1_identity_unresolved", `image_os=${sanitizeDiagnostic(imageOs)}`);
  requireStringArray(dockerArgs, "docker_runtime_command_mismatch", "docker_args_invalid");
  const declared = verifyDeclaredRuntimeCommand({ dockerPath, dockerArgs, imageEntrypoint, imageCmd });
  const procArgs = String(proc1Cmdline).split("\0").filter(Boolean);
  requireCondition(procArgs.length > 0, "pid1_identity_unresolved", "empty_proc_cmdline");
  const status = parseProcStatus(proc1Status);
  requireCondition(proc1Comm.trim() === "clamd", "pid1_identity_unresolved", `proc_comm=${sanitizeDiagnostic(proc1Comm.trim())}`);
  requireCondition(status.Name === "clamd", "pid1_identity_unresolved", `proc_status_name=${sanitizeDiagnostic(status.Name)}`);
  requireCondition(status.Pid === "1" && status.PPid === "0" && status.TracerPid === "0", "pid1_identity_unresolved", "proc_status_pid_relationship");
  requireCondition(status.NoNewPrivs === "1", "pid1_identity_unresolved", `proc_status_no_new_privs=${sanitizeDiagnostic(status.NoNewPrivs)}`);
  requireCondition(status.Seccomp === "2", "pid1_identity_unresolved", `proc_status_seccomp=${sanitizeDiagnostic(status.Seccomp)}`);

  const normalizedHostArchitecture = String(hostArchitecture).trim().toLowerCase();
  if (proc1Exe.trim() === EXPECTED.daemonExecutable) {
    requireCondition(["arm64", "aarch64"].includes(normalizedHostArchitecture), "pid1_identity_unresolved", `native_host_architecture=${sanitizeDiagnostic(normalizedHostArchitecture)}`);
    const observedNative = parseClamdArguments(procArgs);
    requireCondition(observedNative.configPath === declared.configPath, "config_path_conflict", "native_and_declared_config_differ");
    requireCondition(arraysEqual(procArgs, declared.daemonCommand), "docker_runtime_command_mismatch", "native_proc_command_differs_from_declared_guest");
    return {
      mode: "native-clamd",
      logicalExecutable: EXPECTED.daemonExecutable,
      configPath: declared.configPath,
      procArgs,
      status,
    };
  }

  if (proc1Exe.trim() === EXPECTED.qemuExecutable) {
    requireCondition(["amd64", "x86_64"].includes(normalizedHostArchitecture), "pid1_identity_unresolved", `qemu_host_architecture=${sanitizeDiagnostic(normalizedHostArchitecture)}`);
    const expectedQemuCommand = [
      EXPECTED.qemuExecutable,
      EXPECTED.daemonExecutable,
      ...declared.daemonCommand,
    ];
    requireCondition(procArgs[1] === EXPECTED.daemonExecutable, "qemu_guest_target_unresolved", `guest=${sanitizeDiagnostic(procArgs[1])}`);
    requireCondition(procArgs[2] === EXPECTED.daemonExecutable, "qemu_guest_target_unresolved", `guest_argv0=${sanitizeDiagnostic(procArgs[2])}`);
    const observedGuest = parseClamdArguments(procArgs.slice(2));
    requireCondition(observedGuest.configPath === declared.configPath, "config_path_conflict", "qemu_and_declared_config_differ");
    requireCondition(arraysEqual(procArgs, expectedQemuCommand), "qemu_guest_target_unresolved", "observed_shape_mismatch");
    return {
      mode: "qemu-arm64-clamd",
      logicalExecutable: EXPECTED.daemonExecutable,
      configPath: declared.configPath,
      procArgs,
      status,
    };
  }

  if (posix.basename(proc1Exe.trim()).startsWith("qemu-")) {
    fail("qemu_guest_target_unresolved", `emulator=${sanitizeDiagnostic(proc1Exe.trim())}`);
  }
  fail("unexpected_runtime_wrapper", `proc_exe=${sanitizeDiagnostic(proc1Exe.trim())}`);
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

export function verifyClamdConfiguration({ commandLine, configPath, configText, clamconfOutput, runtimeLog = "" }) {
  const resolvedConfigPath = configPath ?? parseClamdCommandLine(commandLine).configPath;
  const rawConfig = parseAlertExceedsMaxDefinitions(configText);
  const effectiveValue = parseClamconfAlertExceedsMax(clamconfOutput, posix.basename(resolvedConfigPath));
  const supplementalLog = classifySupplementalRuntimeLog(runtimeLog);
  return { configPath: resolvedConfigPath, rawConfig, effectiveValue, supplementalLog };
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

  const hostArchitecture = invokeDocker(
    docker,
    ["info", "--format", "{{.Architecture}}"],
    "pid1_identity_unresolved",
    "docker_host_architecture_unreadable",
  ).trim();
  const commandLine = invokeDocker(
    docker,
    ["exec", containerName, "cat", "/proc/1/cmdline"],
    "pid1_identity_unresolved",
    "pid1_cmdline_unreadable",
  );
  const proc1Exe = invokeDocker(
    docker,
    ["exec", containerName, "readlink", "/proc/1/exe"],
    "pid1_identity_unresolved",
    "pid1_exe_unreadable",
  ).trim();
  const proc1Comm = invokeDocker(
    docker,
    ["exec", containerName, "cat", "/proc/1/comm"],
    "pid1_identity_unresolved",
    "pid1_comm_unreadable",
  ).trim();
  const proc1Status = invokeDocker(
    docker,
    ["exec", containerName, "cat", "/proc/1/status"],
    "pid1_identity_unresolved",
    "pid1_status_unreadable",
  );
  const identity = verifyRuntimeProcessIdentity({
    dockerPath: containerInspect.Path,
    dockerArgs: containerInspect.Args,
    imageArchitecture: imageInspect.Architecture,
    imageOs: imageInspect.Os,
    imageEntrypoint: imageInspect.Config?.Entrypoint,
    imageCmd: imageInspect.Config?.Cmd ?? null,
    hostArchitecture,
    proc1Cmdline: commandLine,
    proc1Exe,
    proc1Comm,
    proc1Status,
  });
  logger.log(`PID1_IDENTITY docker_path=${sanitizeDiagnostic(containerInspect.Path)} docker_args=${sanitizeDiagnostic(JSON.stringify(containerInspect.Args))}`);
  logger.log(`PID1_IDENTITY image_architecture=${sanitizeDiagnostic(imageInspect.Architecture)} image_entrypoint=${sanitizeDiagnostic(JSON.stringify(imageInspect.Config?.Entrypoint))} image_cmd=${sanitizeDiagnostic(JSON.stringify(imageInspect.Config?.Cmd ?? null))}`);
  logger.log(`PID1_IDENTITY proc_cmdline=${sanitizeDiagnostic(JSON.stringify(identity.procArgs))} proc_exe=${sanitizeDiagnostic(proc1Exe)} proc_comm=${sanitizeDiagnostic(proc1Comm)}`);
  logger.log(`CLAMD_IDENTITY_PASS mode=${identity.mode} logical_executable=${identity.logicalExecutable}`);
  const configPath = identity.configPath;
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
  const clamd = verifyClamdConfiguration({ configPath, configText, clamconfOutput, runtimeLog });

  logger.log(`CLAMD_CONFIG_PASS runtime_config=${clamd.configPath} source=proven_runtime_identity`);
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
    runtimeProcess: {
      mode: identity.mode,
      dockerPath: containerInspect.Path,
      dockerArgs: containerInspect.Args,
      imageArchitecture: imageInspect.Architecture,
      imageOs: imageInspect.Os,
      imageEntrypoint: imageInspect.Config.Entrypoint,
      imageCmd: imageInspect.Config.Cmd ?? null,
      hostArchitecture,
      proc1Cmdline: identity.procArgs,
      proc1Exe,
      proc1Comm,
      proc1Status: identity.status,
      logicalExecutable: identity.logicalExecutable,
      configPath: identity.configPath,
    },
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
      logicalExecutable: identity.logicalExecutable,
      runtimeMode: identity.mode,
      runtimeConfigPath: clamd.configPath,
      alertExceedsMax: clamd.effectiveValue,
      rawDefinitionCount: clamd.rawConfig.definitions.length,
      verificationSource: "clamconf-effective-config-bound-to-proven-runtime-identity",
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
      const configFailure = /^(alert_exceeds_max|clamconf_|config_)/.test(error.classification);
      const identityFailure = /^(pid1_identity_|unexpected_runtime_wrapper|qemu_guest_target_|docker_runtime_command_)/.test(error.classification);
      const prefix = configFailure ? "CLAMD_CONFIG_FAIL" : identityFailure ? "CLAMD_IDENTITY_FAIL" : "RUNTIME_ISOLATION_FAIL";
      console.error(`${prefix} classification=${error.classification} detail=${sanitizeDiagnostic(error.detail)}`);
      process.exitCode = 1;
    } else {
      console.error("CLAMD_CONFIG_FAIL classification=unexpected_error");
      process.exitCode = 1;
    }
  }
}
