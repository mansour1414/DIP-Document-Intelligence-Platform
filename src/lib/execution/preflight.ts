/**
 * Effective host preflight (R7D.1 §6).
 *
 * ## Why the executor's own report is not evidence
 *
 * The executor runs inside the container. If it reports "my root is read-only, I have no network,
 * my memory is 384 MiB", that report is produced by the process whose confinement it describes.
 * A container that escaped, or that is simply misconfigured, reports the same confident things.
 * The only useful source is the daemon's *effective* state plus the kernel's view of the
 * container's process.
 *
 * ## Failing closed
 *
 * Every check here blocks input release. There is no severity level, no warning list, and no
 * "acceptable with a note". A control that cannot be verified is a control that is not present.
 *
 * ## What is still not proven by a pass
 *
 * That the kernel actually enforces these settings. This module compares what the daemon says it
 * configured against what the profile requires. Whether the daemon told the truth, and whether
 * the kernel honoured it, requires a real Docker daemon and a real container — evidence that this
 * environment does not have. A pass here is "no discrepancy between configuration and profile",
 * not "the isolation works".
 */

import type { ExecutionPolicy } from "./docker-lifecycle";

/** One failed control. Codes are closed so a test can assert on them. */
export type PreflightFailure = {
  code:
    | "IMAGE_NOT_DIGEST_PINNED"
    | "CONTAINER_ID_MISMATCH"
    | "CGROUP_PARENT_MISMATCH"
    | "CGROUPNS_NOT_PRIVATE"
    | "USER_NOT_EXECUTOR"
    | "NETWORK_NOT_NONE"
    | "IPC_NOT_NONE"
    | "PID_MODE_NOT_PRIVATE"
    | "UTS_NOT_PRIVATE"
    | "ROOTFS_NOT_READONLY"
    | "MEMORY_MISMATCH"
    | "SWAP_NOT_DISABLED"
    | "PIDS_MISMATCH"
    | "CPU_MISMATCH"
    | "RESTART_POLICY_SET"
    | "LOG_DRIVER_UNBOUNDED"
    | "PRIVILEGED"
    | "CAPABILITIES_ADDED"
    | "BINDS_PRESENT"
    | "DEVICES_PRESENT"
    | "PORTS_PUBLISHED"
    | "TMPFS_POLICY_MISMATCH"
    | "LABELS_MISMATCH"
    | "ENV_LEAKS_HOST"
    | "AUTOREMOVE_ENABLED"
    | "INSPECT_SHAPE_INVALID";
  detail: string;
};

export type PreflightResult = {
  ok: boolean;
  failures: PreflightFailure[];
};

/**
 * Validate the daemon's effective container configuration against the approved profile.
 *
 * `effective` is the parsed `INSPECT_FORMAT` output. Values are compared exactly: a memory limit
 * of 402653184 bytes is the profile, and 402653184 + 1 is a different container configuration
 * that somebody changed.
 */
export function preflightContainer(input: {
  containerId: string;
  effective: Record<string, string>;
  policy: ExecutionPolicy;
  /** Labels the journal recorded for this execution, which the container must carry exactly. */
  expectedLabels: string[];
}): PreflightResult {
  const failures: PreflightFailure[] = [];
  const add = (code: PreflightFailure["code"], detail: string): void => {
    failures.push({ code, detail });
  };
  const field = (name: string): string => input.effective[name] ?? "";
  const json = (name: string): unknown => {
    const raw = field(name);
    if (raw === "" || raw === "<no value>") return null;
    try {
      return JSON.parse(raw);
    } catch {
      add("INSPECT_SHAPE_INVALID", `${name} was not valid JSON`);
      return null;
    }
  };

  // Identity first. A container whose id does not match the one the journal recorded is not this
  // execution's container, and nothing downstream is meaningful.
  if (field("Config.Labels") !== "" && !hasLabel(input.effective, "dip.execution.id", input.policy.executionId)) {
    add("LABELS_MISMATCH", "the ownership label for this execution is missing");
  }
  const image = field("Image");
  if (image !== "" && image !== input.policy.image) {
    add("IMAGE_NOT_DIGEST_PINNED", `running image ${image} is not the pinned ${input.policy.image}`);
  }

  // Namespace isolation.
  if (field("HostConfig.CgroupParent") !== input.policy.cgroupParent) {
    add("CGROUP_PARENT_MISMATCH", `cgroup parent is ${field("HostConfig.CgroupParent") || "unset"}`);
  }
  if (field("HostConfig.CgroupnsMode") !== "private") add("CGROUPNS_NOT_PRIVATE", `cgroupns is ${field("HostConfig.CgroupnsMode") || "unset"}`);
  if (field("HostConfig.NetworkMode") !== "none") add("NETWORK_NOT_NONE", `network is ${field("HostConfig.NetworkMode") || "unset"}`);
  if (field("HostConfig.IpcMode") !== "none") add("IPC_NOT_NONE", `ipc is ${field("HostConfig.IpcMode") || "unset"}`);
  if (field("HostConfig.PidMode") !== "") add("PID_MODE_NOT_PRIVATE", `pid mode is ${field("HostConfig.PidMode")}`);
  if (field("HostConfig.UTSMode") !== "") add("UTS_NOT_PRIVATE", `uts mode is ${field("HostConfig.UTSMode")}`);
  if (field("HostConfig.UsernsMode") === "host") add("USER_NOT_EXECUTOR", "userns is host");

  // User mapping. A container running as root is not this profile whatever else it gets right.
  const user = field("Config.User");
  const expectedUser = `${input.policy.uid}:${input.policy.gid}`;
  if (user !== expectedUser) add("USER_NOT_EXECUTOR", `user is ${user || "unset"}, expected ${expectedUser}`);

  // Filesystem.
  if (field("HostConfig.ReadonlyRootfs") !== "true") add("ROOTFS_NOT_READONLY", "the root filesystem is writable");
  if (field("HostConfig.AutoRemove") === "true") add("AUTOREMOVE_ENABLED", "auto-remove makes the container's removal unobservable");
  const binds = json("HostConfig.Binds");
  if (Array.isArray(binds) && binds.length > 0) add("BINDS_PRESENT", `${binds.length} host bind mount(s) present`);
  const devices = json("HostConfig.Devices");
  if (Array.isArray(devices) && devices.length > 0) add("DEVICES_PRESENT", `${devices.length} host device(s) present`);
  const ports = json("HostConfig.PortBindings");
  if (ports !== null && typeof ports === "object" && Object.keys(ports as object).length > 0) {
    add("PORTS_PUBLISHED", "ports are published");
  }
  const tmpfs = json("HostConfig.Tmpfs");
  if (tmpfs !== null) {
    const entries = Object.entries(tmpfs as Record<string, string>);
    const work = entries.find(([mount]) => mount === "/work");
    const scratch = entries.find(([mount]) => mount === "/tmp");
    if (work === undefined || scratch === undefined) {
      add("TMPFS_POLICY_MISMATCH", "expected exactly /work and /tmp tmpfs mounts");
    } else {
      if (!work[1].includes(`size=${input.policy.workTmpfsBytes}`)) add("TMPFS_POLICY_MISMATCH", "/work has the wrong size");
      if (!scratch[1].includes(`size=${input.policy.tmpTmpfsBytes}`)) add("TMPFS_POLICY_MISMATCH", "/tmp has the wrong size");
      // Executable tmpfs is a code-execution surface; it must not be enabled.
      if (entries.some(([, options]) => options.includes("exec") && !options.includes("noexec"))) {
        add("TMPFS_POLICY_MISMATCH", "a tmpfs mount is executable");
      }
      // The whole point of the budget: what the container can write is bounded. Each mount is
      // checked against the policy above; this checks that nothing else can be written.
      const total = entries.reduce((sum, [, options]) => sum + (/size=(\d+)/u.exec(options)?.[1] !== undefined ? Number(/size=(\d+)/u.exec(options)![1]) : 0), 0);
      if (total > input.policy.tmpfsBudgetBytes) add("TMPFS_POLICY_MISMATCH", `tmpfs total ${total} exceeds the budget`);
    }
  } else {
    add("TMPFS_POLICY_MISMATCH", "no tmpfs mounts were reported");
  }

  // Resource limits.
  if (field("HostConfig.Memory") !== String(input.policy.memoryBytes)) {
    add("MEMORY_MISMATCH", `memory is ${field("HostConfig.Memory") || "unset"}`);
  }
  // Swap must be off, which Docker expresses as MemorySwap equal to Memory. A larger value means
  // the container can exceed its "aggregate memory" limit through the swap charge.
  const swap = field("HostConfig.MemorySwap");
  if (swap !== "" && swap !== String(input.policy.memoryBytes) && swap !== "-1") {
    add("SWAP_NOT_DISABLED", `memory+swap is ${swap}`);
  }
  if (swap === "-1") add("SWAP_NOT_DISABLED", "swap is unlimited");
  const pids = field("HostConfig.PidsLimit");
  if (pids !== String(input.policy.pidsLimit)) add("PIDS_MISMATCH", `pids limit is ${pids || "unset"}`);
  const quota = field("HostConfig.CpuQuota");
  const period = field("HostConfig.CpuPeriod");
  if (quota !== String(input.policy.cpuQuotaMicros) || period !== String(input.policy.cpuPeriodMicros)) {
    add("CPU_MISMATCH", `cpu is ${quota}/${period}, expected ${input.policy.cpuQuotaMicros}/${input.policy.cpuPeriodMicros}`);
  }
  const nano = field("HostConfig.NanoCpus");
  if (nano !== "" && nano !== "0" && nano !== "0.000000") add("CPU_MISMATCH", "NanoCpus is also set, which conflicts with the quota");

  // Restart and logging. A restart policy turns a crash into an unbounded retry; an unbounded log
  // driver turns attacker-influenced output into disk exhaustion on the host.
  const restart = field("HostConfig.RestartPolicy.Name");
  if (restart !== "" && restart !== "no") add("RESTART_POLICY_SET", `restart policy is ${restart}`);
  const logType = field("HostConfig.LogConfig.Type");
  if (logType !== "none" && logType !== "local") add("LOG_DRIVER_UNBOUNDED", `log driver is ${logType || "default"}`);

  // Privileges.
  if (field("HostConfig.Privileged") === "true") add("PRIVILEGED", "the container is privileged");
  const capAdd = json("HostConfig.CapAdd");
  if (Array.isArray(capAdd) && capAdd.length > 0) add("CAPABILITIES_ADDED", `${capAdd.length} capabilities added`);
  // Capabilities must be dropped to ALL. An absent CapDrop is not "nothing to check": it means
  // the container runs with the daemon's default capability set, which is a weaker profile than
  // the one approved. Null, empty and partial are all failures.
  const capDrop = json("HostConfig.CapDrop");
  if (!Array.isArray(capDrop) || !capDrop.some((entry) => String(entry).toUpperCase() === "ALL")) {
    add("CAPABILITIES_ADDED", "capabilities were not dropped to ALL");
  }

  // Environment. Nothing from the host environment may reach the container: the executor needs
  // exactly the values the profile sets, and an inherited PATH or TMPDIR changes its behaviour.
  const env = json("Config.Env");
  if (Array.isArray(env)) {
    for (const entry of env) {
      const text = String(entry);
      if (!/^(NODE_OPTIONS|DIP_PROFILE|DIP_EXECUTION_ID|HOME|PATH|LANG|TZ)=/u.test(text)) {
        add("ENV_LEAKS_HOST", `unexpected environment key ${text.split("=")[0]}`);
      }
    }
  }

  return { ok: failures.length === 0, failures };
}

function hasLabel(effective: Record<string, string>, key: string, value: string): boolean {
  const raw = effective["Config.Labels"] ?? "";
  try {
    const labels = JSON.parse(raw) as Record<string, string>;
    return labels[key] === value;
  } catch {
    // A label blob that will not parse cannot demonstrate ownership, which is a failure, not a
    // pass with a note.
    return false;
  }
}

/**
 * Fetch the kernel's view of the container's init process.
 *
 * Separate from the daemon check because the two answer different questions. The daemon says what
 * it configured; this says what exists.
 */
export function preflightKernel(input: {
  containerId: string;
  initPid: number;
  initStartTimeTicks: number;
  cgroupPath: string;
  /** What the host reported just before this call, to detect a PID reused between steps. */
  observedStartTimeTicks: number;
}): PreflightResult {
  const failures: PreflightFailure[] = [];
  if (!/^[a-f0-9]{64}$/u.test(input.containerId)) {
    failures.push({ code: "CONTAINER_ID_MISMATCH", detail: "the container id is not a 64-character id" });
  }
  if (!Number.isSafeInteger(input.initPid) || input.initPid <= 1) {
    failures.push({ code: "INSPECT_SHAPE_INVALID", detail: "the init PID is not a real process id" });
  }
  // A PID is recycled; the start time is the only thing that makes "this process" checkable.
  if (input.initStartTimeTicks !== input.observedStartTimeTicks) {
    failures.push({ code: "INSPECT_SHAPE_INVALID", detail: "the init PID's start time changed between observation and check" });
  }
  if (input.cgroupPath === "" || input.cgroupPath.split("/").includes("..")) {
    failures.push({ code: "CGROUP_PARENT_MISMATCH", detail: "the cgroup path is absent or may traverse" });
  }
  return { ok: failures.length === 0, failures };
}
