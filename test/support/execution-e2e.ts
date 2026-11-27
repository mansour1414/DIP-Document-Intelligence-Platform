/**
 * The end-to-end harness for R7D.1 D2 closure.
 *
 * ## What is real, and what is fake
 *
 * ```text
 *   real  caller process        the authenticated role client, over a Unix socket
 *   real  supervisor process    workers/supervisor.ts, spawned as a child
 *   real  watchdog process      workers/watchdog.ts, spawned as a child
 *   real  executor process      dist/executor-child.js, spawned per execution
 *   fake  Docker adapter        a script that answers `create`/`inspect`/`rm`/`kill` and, for
 *                               `start`, spawns the real executor and pipes the document into it
 * ```
 *
 * The Docker adapter is fake because there is no daemon in this environment. It is *labelled* fake:
 * it lives in this file, it is only ever installed through `DIP_DOCKER_BIN`, and every test that
 * uses it says so. What it does not fake is the executor — `start` runs the real bundle as a real
 * child process, so the document really is parsed, filled and validated by the real code.
 *
 * ## The one thing it cannot prove
 *
 * Isolation. Nothing here creates a namespace, a cgroup, a seccomp filter or a user namespace. The
 * fake adapter reports the *labels and limits* a real container would carry, which lets preflight
 * and the watchdog do their work, but a passing test says nothing about whether a real daemon would
 * enforce them. That is D-A04, and it remains NOT TESTED.
 */

import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { PDFDocument, StandardFonts } from "pdf-lib";
import { encodeControlV2 } from "../../src/lib/pdf/worker-protocol-v2";
import { randomUUID } from "node:crypto";

/**
 * The host's real boot identity.
 *
 * Read rather than invented: the watchdog verifies the boot it is running on against the one the
 * supervisor claims, and a made-up value is exactly the mismatch that check exists to catch. This
 * was a real failure in the first draft of this harness — the supervisor refused to start, which is
 * the correct behaviour and a useful demonstration of it.
 */
export const BOOT_ID: string = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();

/** The path the fake adapter writes its state to. */
const STATE = "docker-state.json";

export type E2EEnvironment = {
  root: string;
  appSocket: string;
  workerSocket: string;
  watchdogSocket: string;
  journalRoot: string;
  stateDir: string;
  /**
   * The fixture cgroup hierarchy.
   *
   * Stands in for `/sys/fs/cgroup`, which is not writable in the environments this harness runs
   * in. Evidence gathered through it is mocked cgroup evidence; every other part of the harness —
   * processes, sockets, journal, daemon CLI, executor — is real.
   */
  cgroupRoot: string;
  dockerBin: string;
  executorBundle: string;
  secrets: { app: string; worker: string; watchdog: string };
  supervisorInstance: string;
  watchdogInstance: string;
  cleanup: () => void;
};

/**
 * Build the fake Docker adapter.
 *
 * ## Why a shell script and not a Node module
 *
 * `DIP_DOCKER_BIN` is executed as a binary, exactly as `/usr/bin/docker` would be. Writing it as a
 * script keeps the substitution honest: the supervisor has no idea it is talking to a fake, and
 * nothing in the production path knows this adapter exists.
 *
 * ## What each verb does
 *
 * - `create` — mints a 64-hex id, records it, prints it. Real behaviour, fake daemon.
 * - `inspect` — prints the effective configuration the profile would produce, in the exact 28-field
 *   pipe-separated form `INSPECT_FORMAT` requests, with the real label set.
 * - `inspect --format Pid|Running|Id` — reports the *real* executor PID and a running state, so
 *   preflight's `/proc` cross-check has something true to compare against.
 * - `start -a -i` — spawns the real executor bundle with the document on stdin and the result on
 *   stdout, and exits with the executor's own code.
 * - `rm` — forgets the id. `kill` — signals the executor.
 */
function writeDockerAdapter(path: string, executorBundle: string, stateDir: string, cgroupRoot: string): void {
  const script = `#!/usr/bin/env node
"use strict";
// A labelled fake: this is the Docker adapter for the R7D.1 end-to-end tests. It is never installed
// anywhere but the test harness, and it is only reached through DIP_DOCKER_BIN.
const { spawn, spawnSync } = require("node:child_process");
const { existsSync, mkdirSync, readFileSync, writeFileSync } = require("node:fs");
const { join } = require("node:path");
const { randomBytes } = require("node:crypto");

const STATE_DIR = ${JSON.stringify(stateDir)};
const STATE = join(STATE_DIR, ${JSON.stringify(STATE)});
const EXECUTOR = ${JSON.stringify(executorBundle)};
// The fixture cgroup hierarchy. A real daemon places the container's init process in a cgroup
// named after the container; this adapter does the same, by recording the spawned executor's real
// PID in the fixture, so the supervisor's and watchdog's cgroup observations are of a real process.
const CGROUP_ROOT = ${JSON.stringify(cgroupRoot)};
const LF = String.fromCharCode(10);

/**
 * Place a PID in the container cgroup, the way the daemon does.
 *
 * Two effects, both of which production code reads: the cgroup directory gains the control files
 * and lists the PID, and the fixture membership map says which cgroup that PID is in. The second is
 * what /proc/<pid>/cgroup would report, and it is written to a file because the supervisor and
 * the watchdog are separate processes.
 */
function placeInCgroup(containerId, pid) {
  const dir = join(CGROUP_ROOT, "dip-executor.slice", "docker-" + containerId + ".scope");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "cgroup.kill"), "");
  writeFileSync(join(dir, "cgroup.events"), "populated 1" + LF + "frozen 0" + LF);
  writeFileSync(join(dir, "cgroup.procs"), pid + LF);
  const map = join(CGROUP_ROOT, "membership.map");
  let existing = "";
  try { existing = readFileSync(map, "utf8"); } catch (e) { existing = ""; }
  const kept = existing.split(LF).filter(function (line) { return line !== "" && Number(line.split(" ")[0]) !== pid; });
  kept.push(pid + " dip-executor.slice/docker-" + containerId + ".scope");
  writeFileSync(map, kept.join(LF) + LF);
}

function load() { try { return JSON.parse(readFileSync(STATE, "utf8")); } catch { return { containers: {}, children: {} }; } }
function save(s) { writeFileSync(STATE, JSON.stringify(s)); }

const argv = process.argv.slice(2);
// Strip the global flags the supervisor always passes.
const args = [];
for (let i = 0; i < argv.length; i += 1) {
  if (argv[i] === "--host" || argv[i] === "--config") { i += 1; continue; }
  args.push(argv[i]);
}
const verb = args[0];

// Whether a PID is the executor we started. Signal 0 checks existence without delivering.
function isAlive(pid) {
  if (!pid) return false;
  try { process.kill(pid, 0); return true; } catch (e) { return false; }
}

function fail(message) {
  process.stderr.write("Error response from daemon: " + message + "\\n");
  process.exit(1);
}

if (verb === "create") {
  if (process.env.DIP_FAKE_DOCKER_TRACE) { require("node:fs").appendFileSync(process.env.DIP_FAKE_DOCKER_TRACE, "CREATE " + JSON.stringify(args) + "\\n"); }
  const state = load();
  const id = randomBytes(32).toString("hex");
  // ## Parsed from the real argv, not modelled
  //
  // Every value the inspect reply later reports is taken from the flags the supervisor actually
  // passed. Hand-modelling them was the source of four separate end-to-end failures — cgroup parent,
  // labels, ipc mode, namespace modes — each of which looked like a control-plane bug and was
  // really this adapter mis-describing a correct container.
  //
  // The one thing a fake daemon cannot avoid deciding for itself is *default*: when a flag is
  // absent, what the daemon would have done. Those defaults are stated below, once.
  const merged = { labels: {}, security: [], capDrop: [], capAdd: [], tmpfs: [], env: [], ulimit: [], values: {} };
  const takesValue = {
    "-l": "label", "--label": "label", "--name": "name", "--user": "user", "--memory": "memory",
    "--memory-swap": "memorySwap", "--pids-limit": "pids", "--cpu-period": "cpuPeriod",
    "--cpu-quota": "cpuQuota", "--cpus": "cpus", "--network": "network", "--ipc": "ipc",
    "--pid": "pid", "--uts": "uts", "--userns": "userns", "--cgroupns": "cgroupns",
    "--cgroup-parent": "cgroupParent", "--restart": "restart", "--security-opt": "security",
    "--cap-drop": "capDrop", "--cap-add": "capAdd", "--tmpfs": "tmpfs", "--env": "env",
    "-e": "env", "--log-driver": "logDriver", "--ulimit": "ulimit",
  };
  let image = "";
  for (let i = 0; i < args.length; i += 1) {
    const token = args[i];
    if (token === "--read-only") { merged.values.readOnly = true; continue; }
    if (token === "--privileged") { merged.values.privileged = true; continue; }
    if (token === "--rm" || token === "-i" || token === "-t" || token === "-d" || token === "--pull") {
      if (token === "--pull") i += 1;
      continue;
    }
    const target = takesValue[token];
    if (target) {
      const value = args[i + 1];
      if (target === "label") { const [k, ...rest] = String(value).split("="); merged.labels[k] = rest.join("="); }
      else if (target === "security" || target === "capDrop" || target === "capAdd" || target === "tmpfs" || target === "env" || target === "ulimit") merged[target].push(value);
      else merged.values[target] = value;
      i += 1;
      continue;
    }
    if (!token.startsWith("-")) image = token;
  }
  merged.values.image = image;
  state.containers[id] = { spec: merged, removed: false };
  save(state);
  process.stdout.write(id + "\\n");
  process.exit(0);
}

if (verb === "inspect") {
  if (process.env.DIP_FAKE_DOCKER_TRACE) { require("node:fs").appendFileSync(process.env.DIP_FAKE_DOCKER_TRACE, "INSPECT " + JSON.stringify(args) + "\\n"); }
  const formatIndex = args.indexOf("--format");
  const format = formatIndex >= 0 ? args[formatIndex + 1] : "";
  // The id is the last positional argument. The inspect argv is
  //   docker inspect --type container --format <fmt> <id>
  // so args[len-1] happens to be the id — but only because the id is last. Filtering by position
  // states the rule instead of relying on that coincidence.
  const positional = args.filter(function (a, i) {
    if (a.startsWith("--")) return false;
    if (i > 0 && (args[i - 1] === "--format" || args[i - 1] === "--type")) return false;
    return true;
  });
  const id = positional[positional.length - 1];
  const state = load();
  const record = state.containers[id];
  if (!record || record.removed) fail("No such object: " + id);
  const spec = record.spec;

  if (format === "{{.State.Pid}}|{{.State.Running}}|{{.Id}}") {
    const child = state.children[id];
    const alive = child ? isAlive(child.pid) : false;
    process.stdout.write((alive ? child.pid : 0) + "|" + (alive ? "true" : "false") + "|" + id + "\\n");
    process.exit(0);
  }

  // The configuration form.
  //
  // ## Responded to by name, not by position
  //
  // The first version of this adapter emitted a hand-ordered list and silently diverged from
  // the INSPECT_FORMAT template: the supervisor reads HostConfig.CgroupParent by template key, so a
  // reordering turns a correct container into a CGROUP_PARENT_MISMATCH. The template the daemon
  // was asked for is right there in the argv, so this parses it and answers each field — which is
  // also why the adapter cannot drift again without the template changing too.
  const labels = spec.labels || {};
  const v = spec.values || {};
  const num = function (value, fallback) { const n = Number(value); return Number.isFinite(n) ? n : fallback; };
  const security = spec.security || [];
  const hasSecurity = function (prefix) { return security.some(function (s) { return String(s).indexOf(prefix) === 0; }); };

  const values = {
    ".Id": id,
    ".HostConfig.CgroupParent": v.cgroupParent || "",
    ".HostConfig.CgroupnsMode": v.cgroupns || "",
    ".Config.User": v.user || "",
    ".HostConfig.NetworkMode": v.network || "default",
    ".HostConfig.IpcMode": v.ipc || "private",
    ".HostConfig.PidMode": v.pid || "",
    ".HostConfig.UTSMode": v.uts || "",
    ".HostConfig.UsernsMode": v.userns || "",
    ".HostConfig.ReadonlyRootfs": v.readOnly === true,
    ".HostConfig.Memory": num(v.memory, 0),
    ".HostConfig.MemorySwap": num(v.memorySwap, 0),
    ".HostConfig.PidsLimit": num(v.pids, 0),
    ".HostConfig.NanoCpus": 0,
    ".HostConfig.CpuQuota": num(v.cpuQuota, 0),
    ".HostConfig.CpuPeriod": num(v.cpuPeriod, 100000),
    ".HostConfig.RestartPolicy.Name": v.restart || "",
    ".HostConfig.LogConfig.Type": v.logDriver || "json-file",
    ".HostConfig.Privileged": v.privileged === true,
    ".HostConfig.AutoRemove": false,
    ".HostConfig.CapAdd": (spec.capAdd || []).length > 0 ? spec.capAdd : null,
    ".HostConfig.CapDrop": (spec.capDrop || []).length > 0 ? spec.capDrop : null,
    ".HostConfig.Binds": null,
    ".HostConfig.Devices": [],
    ".HostConfig.PortBindings": {},
    ".HostConfig.Tmpfs": tmpfsMap(spec.tmpfs || []),
    ".Config.Labels": labels,
    ".Config.Env": (spec.env || []),
  };

  // The seccomp and AppArmor profiles are reported from the security options the CLI was given,
  // because that is what a daemon does: it records the option and reports it back in inspect.
  void hasSecurity;

  function tmpfsMap(entries) {
    const out = {};
    for (const entry of entries) {
      const parts = String(entry).split(":");
      out[parts[0]] = parts.slice(1).join(":") || "";
    }
    return out;
  }

  const fields = [];
  const pattern = /\{\{(json )?([^}]+)\}\}/g;
  let match;
  while ((match = pattern.exec(format)) !== null) {
    const isJson = match[1] === "json ";
    const key = match[2].trim();
    const value = values[key];
    if (isJson) fields.push(value === null || value === undefined ? "null" : JSON.stringify(value));
    else if (typeof value === "boolean") fields.push(String(value));
    else fields.push(value === null || value === undefined ? "" : String(value));
  }
  process.stdout.write(fields.join("|") + "\\n");
  process.exit(0);
}

if (verb === "start") {
  // The container name is the last argument that is not a flag. For
  //   docker start --attach --interactive <name>
  // that is the name; there are no flag values to skip.
  const name = args.filter(function (a) { return !a.startsWith("-"); }).pop();
  const state = load();
  let id = null;
  for (const key of Object.keys(state.containers)) {
    // The container name lives with the other parsed flag values, not at the top of the record.
    // Reading spec.name here was the sixth adapter bug: create stored it, start looked elsewhere.
    if (state.containers[key].spec.values && state.containers[key].spec.values.name === name) id = key;
  }
  if (id === null) fail("No such object: " + name);
  // ## Bridging the executor's fd 3
  //
  // The executor writes its framed result to fd 3 and keeps stdout diagnostic. A real Docker
  // daemon cannot forward a fourth descriptor through an attached start, so a deployment binds fd 3
  // to the container's stdout: the supervisor therefore reads results from stdout.
  //
  // This adapter performs exactly that binding, with a pipe this process owns. The child is given a
  // stdio entry of "pipe", whose write end becomes its fd 3 and whose read end is re-emitted on
  // this process's stdout. Nothing about the executor changes, and the channel the supervisor reads
  // is the one a deployment would give it.
  const child = spawn(process.execPath, [EXECUTOR], {
    stdio: ["pipe", "pipe", "pipe", "pipe"],
    env: { PATH: process.env.PATH || "/usr/bin:/bin", NODE_ENV: "production" },
  });
  // Recorded as running *before* any state inspection can ask: a real daemon reports the container
  // running the moment start returns, and preflight inspects immediately afterwards.
  state.children[id] = { pid: child.pid, startedAt: Date.now() };
  save(state);
  // The cgroup placement a real daemon performs. The leaf is the documented systemd form and the
  // PID is the real executor's, so both processes observe a genuine process in a real directory.
  placeInCgroup(id, child.pid);
  // stdio[3] is the parent's read end of the child's fd 3.
  //
  // It is forwarded with writeSync(1, ...) rather than process.stdout.write: this adapter is
  // repeatedly spawned and short-lived, and a stream write is buffered until the event loop drains.
  // The process exits on the child's exit, which can occur before that buffer is flushed, and the
  // result silently disappeared — the last hop of a working pipeline, losing the bytes.
  if (child.stdio[3]) {
    child.stdio[3].on("data", function (chunk) {
      let offset = 0;
      while (offset < chunk.length) {
        offset += require("node:fs").writeSync(1, chunk, offset, chunk.length - offset);
      }
    });
  }
  // ## The document, held open until the caller sends it
  //
  // A real attached start keeps the container's stdin open for the whole session. Relaying this
  // process's stdin as it arrives, and ending it only when this adapter's own stdin ends, is what
  // gives the executor the same lifetime: the supervisor deliberately writes nothing until
  // READY_FOR_BODY, so an executor whose stdin closed at once would finish, exit, and be reported
  // "not running" by the preflight that follows the start.
  //
  // An explicit resume is required: a piped stdin is not put into flowing mode by attaching a
  // listener alone, and the adapter would otherwise sit idle while the supervisor wrote into it.
  process.stdin.on("data", function (chunk) { child.stdin.write(chunk); });
  process.stdin.on("end", function () { child.stdin.end(); });
  process.stdin.on("error", function () { /* the daemon stdin closing early is not fatal */ });
  process.stdin.resume();
  child.stderr.pipe(process.stderr);
  child.on("exit", function (code) {
    const after = load();
    if (after.children[id]) { after.children[id].exited = code; save(after); }
    process.exit(code === null ? 1 : code);
  });
  return;
}

if (verb === "kill") {
  const id = args[args.length - 1];
  const state = load();
  const child = state.children[id];
  if (!child) fail("No such object: " + id);
  try { process.kill(child.pid, "SIGKILL"); } catch (e) { /* already gone */ }
  process.exit(0);
}

if (verb === "rm") {
  const id = args[args.length - 1];
  const state = load();
  const record = state.containers[id];
  if (!record || record.removed) fail("No such container: " + id);
  record.removed = true;
  delete state.children[id];
  save(state);
  // ## Removal empties the cgroup, because that is what removal means
  //
  // A real docker rm destroys the container's cgroup with it: the directory is gone and the
  // membership with it. The watchdog's termination evidence is exactly that disappearance
  // (populated 0 through a pinned descriptor), so an adapter that removed the container from its
  // own bookkeeping but left the cgroup populated made every completion UNCERTAIN — the daemon
  // said the container was gone while the cgroup still listed a process. Both effects are
  // performed here so the two agree, as they do on a real host.
  const cgroupDir = join(CGROUP_ROOT, "dip-executor.slice", "docker-" + id + ".scope");
  try {
    writeFileSync(join(cgroupDir, "cgroup.procs"), "");
    writeFileSync(join(cgroupDir, "cgroup.events"), "populated 0" + LF + "frozen 0" + LF);
  } catch (e) { /* the cgroup was already gone */ }
  const mapFile = join(CGROUP_ROOT, "membership.map");
  try {
    const kept = readFileSync(mapFile, "utf8").split(LF).filter(function (line) {
      return line !== "" && line.indexOf("docker-" + id + ".scope") < 0;
    });
    writeFileSync(mapFile, kept.length > 0 ? kept.join(LF) + LF : "");
  } catch (e) { /* no membership map */ }
  process.stdout.write(id + "\\n");
  process.exit(0);
}

fail("unsupported verb: " + String(verb));
`;
  writeFileSync(path, script, { mode: 0o700 });
  chmodSync(path, 0o700);
}

/** Make the environment: directories, sockets, secrets, the fake adapter. */
export function makeEnvironment(): E2EEnvironment {
  const root = mkdtempSync(join(tmpdir(), "dip-e2e-"));
  const sockets = join(root, "sockets");
  const journalRoot = join(root, "journal");
  const stateDir = join(root, "docker");
  const binDir = join(root, "bin");
  const cgroupRoot = join(root, "cgroup");
  for (const dir of [sockets, journalRoot, stateDir, binDir, cgroupRoot]) mkdirSync(dir, { recursive: true, mode: 0o700 });

  const env: E2EEnvironment = {
    root,
    appSocket: join(sockets, "app.sock"),
    workerSocket: join(sockets, "worker.sock"),
    watchdogSocket: join(sockets, "watchdog.sock"),
    journalRoot,
    stateDir,
    cgroupRoot,
    dockerBin: join(binDir, "docker"),
    executorBundle: join(process.cwd(), "dist", "executor-child.js"),
    secrets: {
      app: randomBytes(32).toString("hex"),
      worker: randomBytes(32).toString("hex"),
      watchdog: randomBytes(32).toString("hex"),
    },
    supervisorInstance: "sv-0123456789ab",
    watchdogInstance: "wd-0123456789ab",
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
  if (!existsSync(env.executorBundle)) throw new Error(`the executor bundle is missing at ${env.executorBundle}; run scripts/esbuild-executor.mjs`);
  writeDockerAdapter(env.dockerBin, env.executorBundle, stateDir, cgroupRoot);
  return env;
}

/** A supervisor or watchdog child, with its JSON-lines events collected. */
export type Proc = {
  child: ChildProcess;
  events: () => Record<string, unknown>[];
  waitFor: (event: string, timeoutMs?: number) => Promise<Record<string, unknown>>;
  stop: () => Promise<void>;
};

function spawnNode(script: string, env: Record<string, string>): Proc {
  const child = spawn(process.execPath, ["--import", "tsx", script], {
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, ...env },
  });
  const events: Record<string, unknown>[] = [];
  const waiters: { event: string; resolve: (value: Record<string, unknown>) => void }[] = [];
  let buffer = "";
  child.stdout?.on("data", (chunk: Buffer) => {
    buffer += chunk.toString("utf8");
    let index = buffer.indexOf("\n");
    while (index >= 0) {
      const line = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      try {
        const event = JSON.parse(line) as Record<string, unknown>;
        events.push(event);
        for (let i = waiters.length - 1; i >= 0; i -= 1) {
          if (waiters[i].event === event.event) {
            const waiter = waiters.splice(i, 1)[0];
            waiter.resolve(event);
          }
        }
      } catch {
        // A non-JSON line is diagnostic output, not an event.
      }
      index = buffer.indexOf("\n");
    }
  });
  const proc: Proc = {
    child,
    events: () => [...events],
    waitFor: (event, timeoutMs = 20_000) => {
      const existing = events.find((e) => e.event === event);
      if (existing) return Promise.resolve(existing);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          reject(new Error(`the process never emitted "${event}"; saw ${events.map((e) => String(e.event)).join(", ")}`));
        }, timeoutMs);
        waiters.push({ event, resolve: (value) => { clearTimeout(timer); resolve(value); } });
      });
    },
    stop: () => new Promise<void>((resolve) => {
      if (child.exitCode !== null || child.signalCode !== null) { resolve(); return; }
      child.once("exit", () => resolve());
      child.kill("SIGKILL");
    }),
  };
  return proc;
}

/** The one digest-pinned executor image this harness configures. */
export const EXECUTOR_IMAGE = `ghcr.io/mansour1414/dip-executor@sha256:${"d".repeat(64)}`;

export function supervisorEnv(env: E2EEnvironment): Record<string, string> {
  return {
    DIP_SUPERVISOR_ROOT: env.journalRoot,
    DIP_SUPERVISOR_INSTANCE: env.supervisorInstance,
    DIP_SUPERVISOR_BOOT: BOOT_ID,
    DIP_SUPERVISOR_APP_SOCKET: env.appSocket,
    DIP_SUPERVISOR_WORKER_SOCKET: env.workerSocket,
    DIP_WATCHDOG_SOCKET: env.watchdogSocket,
    DIP_WATCHDOG_SECRET: env.secrets.watchdog,
    DIP_CALLER_APP_SECRET: env.secrets.app,
    DIP_CALLER_WORKER_SECRET: env.secrets.worker,
    DIP_SUPERVISOR_DEADLINE_MS: "30000",
    // The trusted execution policy. The harness configures it here, exactly as a deployment does,
    // so the control block the test sends is compared against it rather than becoming it.
    DIP_EXECUTOR_IMAGE: EXECUTOR_IMAGE,
    DIP_EXECUTOR_PROFILE: "synthetic-r7d-v1",
    // The labelled fake. Nothing else in this harness fakes the daemon.
    DIP_DOCKER_BIN: env.dockerBin,
  };
}

export function watchdogEnv(env: E2EEnvironment): Record<string, string> {
  const stateDir = join(env.root, "watchdog-state");
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  return {
    DIP_WATCHDOG_SOCKET: env.watchdogSocket,
    DIP_WATCHDOG_SECRET: env.secrets.watchdog,
    DIP_WATCHDOG_STATE: join(stateDir, "store.json"),
    // Mandatory for a new ARM (D2-F03). Without it every arm is denied.
    DIP_WATCHDOG_JOURNAL: env.journalRoot,
    DIP_WATCHDOG_INSTANCE: env.watchdogInstance,
    DIP_WATCHDOG_BOOT: BOOT_ID,
    // The watchdog talks to the daemon too — it verifies container ownership independently and
    // kills by exact id — so it needs the same labelled adapter the supervisor uses. Omitting this
    // made every arm `OWNERSHIP_UNVERIFIED`: not a policy refusal, an unavailable daemon.
    DIP_DOCKER_BIN: env.dockerBin,
  };
}

/**
 * The supervisor entrypoint.
 *
 * The *fixture* entrypoint, which is a test file: it supplies the fixture host facts and calls the
 * same `main()` the production worker calls. Nothing in `workers/` can be switched onto a fixture
 * by an environment variable.
 */
export function spawnSupervisor(env: E2EEnvironment, overrides: Record<string, string> = {}): Proc {
  return spawnNode("test/support/supervisor-fixture-entry.ts", {
    ...supervisorEnv(env),
    DIP_TEST_CGROUP_FIXTURE: env.cgroupRoot,
    ...overrides,
  });
}

/** The watchdog entrypoint, likewise a fixture entrypoint over the same `main()`. */
export function spawnWatchdog(env: E2EEnvironment, overrides: Record<string, string> = {}): Proc {
  return spawnNode("test/support/watchdog-fixture-entry.ts", {
    ...watchdogEnv(env),
    DIP_TEST_CGROUP_FIXTURE: env.cgroupRoot,
    ...overrides,
  });
}

/**
 * A synthetic fillable PDF.
 *
 * Deliberately small and generated here rather than checked in: the document is an input, and a
 * binary fixture in the repository is one more thing that can drift from what the code expects.
 */
export async function syntheticForm(): Promise<Buffer> {
  const document = await PDFDocument.create();
  const page = document.addPage([300, 400]);
  const font = await document.embedFont(StandardFonts.Helvetica);
  page.drawText("R7D.1 end-to-end fixture", { x: 20, y: 370, size: 11, font });
  const form = document.getForm();
  const name = form.createTextField("applicant.name");
  name.addToPage(page, { x: 20, y: 330, width: 220, height: 20 });
  const consent = form.createCheckBox("applicant.consent");
  consent.addToPage(page, { x: 20, y: 300, width: 12, height: 12 });
  return Buffer.from(await document.save());
}

/**
 * The control frame the executor expects, with the document appended.
 *
 * `encodeControlV2` writes a length prefix, the request JSON, then the body — and the request's
 * `bodyBytes` is set from the body it was given, so the frame declares the truth rather than a
 * number the caller passed.
 */
export function controlFrame(
  request:
    | { op: "inspect" }
    | { op: "fill"; flatten: boolean; fields: Record<string, string | boolean | string[]> }
    | { op: "verify"; kind: "fill" | "flatten" },
  body: Buffer,
): Buffer {
  return encodeControlV2({ v: 2, ...request } as never, body, 512 * 1024 * 1024);
}

export { randomUUID };
