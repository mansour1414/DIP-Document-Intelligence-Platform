/**
 * The Supervisor entry point as a real process (R7D.1 D2).
 *
 * ## Why a subprocess
 *
 * The defect this increment corrects is missing wiring, and wiring cannot be tested in-process: an
 * in-process test supplies the environment a real deployment would have to supply. These tests spawn
 * `workers/watchdog.ts` and `workers/supervisor.ts` as OS processes with environment variables, and
 * read the JSON lines they emit.
 *
 * ## What is real here
 *
 * Real: both processes, the Unix sockets, the handshake, the journal on disk (real fsync), the
 * reconciliation read, the boot id from `/proc`.
 *
 * Mocked: Docker has no daemon in this sandbox, so a record that names a container resolves to a
 * definite `unavailable` — which is exactly the answer reconciliation must treat as "unresolved"
 * rather than "absent". That refusal is the behaviour under test in several cases below.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { readBootId } from "../src/lib/execution/host-facts";

const BOOT = readBootId();

type Proc = {
  child: ChildProcess;
  lines: Record<string, unknown>[];
  waitFor: (event: string, timeoutMs?: number) => Promise<Record<string, unknown>>;
  /** Every event emitted so far, for a post-mortem assertion. */
  events: () => Record<string, unknown>[];
  stop: () => Promise<void>;
};

function spawnNode(script: string, env: Record<string, string>): Proc {
  const child = spawn(process.execPath, ["--import", "tsx", script], {
    cwd: process.cwd(),
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const lines: Record<string, unknown>[] = [];
  const waiters: Array<{ event: string; resolve: (value: Record<string, unknown>) => void }> = [];
  let buffer = "";
  let stderr = "";
  child.stderr!.on("data", (chunk: Buffer) => { stderr += chunk.toString("utf8"); });
  child.stdout!.on("data", (chunk: Buffer) => {
    buffer += chunk.toString("utf8");
    for (;;) {
      const newline = buffer.indexOf("\n");
      if (newline < 0) break;
      const line = buffer.slice(0, newline);
      buffer = buffer.slice(newline + 1);
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(line) as Record<string, unknown>;
      } catch {
        continue;
      }
      lines.push(parsed);
      for (let index = waiters.length - 1; index >= 0; index -= 1) {
        if (waiters[index]!.event === String(parsed.event)) {
          const waiter = waiters.splice(index, 1)[0]!;
          waiter.resolve(parsed);
        }
      }
    }
  });
  return {
    child,
    lines,
    events: () => [...lines],
    waitFor: (event, timeoutMs = 20_000) => {
      const already = lines.find((line) => line.event === event);
      if (already !== undefined) return Promise.resolve(already);
      return new Promise<Record<string, unknown>>((resolve, reject) => {
        const timer = setTimeout(() => {
          reject(new Error(`timed out waiting for ${event}; stderr=${stderr}; events=${JSON.stringify(lines)}`));
        }, timeoutMs);
        waiters.push({ event, resolve: (value) => { clearTimeout(timer); resolve(value); } });
        child.once("exit", (code) => {
          reject(new Error(`${script} exited with ${String(code)} before ${event}; stderr=${stderr}; events=${JSON.stringify(lines)}`));
        });
      });
    },
    stop: () => new Promise<void>((resolve) => {
      if (child.exitCode !== null) { resolve(); return; }
      child.once("exit", () => resolve());
      child.kill("SIGTERM");
      setTimeout(() => { child.kill("SIGKILL"); }, 3_000).unref();
    }),
  };
}

type Environment = {
  root: string;
  journalRoot: string;
  stateDir: string;
  watchdogSocket: string;
  appSocket: string;
  workerSocket: string;
  watchdogSecret: string;
  callerSecret: string;
  bootId: string;
  cleanup: () => void;
};

function makeEnvironment(): Environment {
  const root = mkdtempSync(join(tmpdir(), "dip-sv-"));
  return {
    root,
    journalRoot: join(root, "journal"),
    stateDir: join(root, "watchdog-state"),
    watchdogSocket: join(root, "watchdog.sock"),
    appSocket: join(root, "app.sock"),
    workerSocket: join(root, "worker.sock"),
    watchdogSecret: randomBytes(32).toString("hex"),
    callerSecret: randomBytes(32).toString("hex"),
    bootId: BOOT,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

function watchdogEnv(env: Environment): Record<string, string> {
  return {
    DIP_WATCHDOG_SOCKET: env.watchdogSocket,
    DIP_WATCHDOG_SECRET: env.watchdogSecret,
    DIP_WATCHDOG_STATE: env.stateDir,
    DIP_WATCHDOG_JOURNAL: env.journalRoot,
  };
}

function supervisorEnv(env: Environment): Record<string, string> {
  return {
    DIP_SUPERVISOR_ROOT: env.journalRoot,
    DIP_SUPERVISOR_INSTANCE: "sv-0123456789ab",
    DIP_SUPERVISOR_BOOT: env.bootId,
    DIP_SUPERVISOR_APP_SOCKET: env.appSocket,
    DIP_SUPERVISOR_WORKER_SOCKET: env.workerSocket,
    DIP_WATCHDOG_SOCKET: env.watchdogSocket,
    DIP_WATCHDOG_SECRET: env.watchdogSecret,
    DIP_CALLER_SECRET: env.callerSecret,
    DIP_SUPERVISOR_DEADLINE_MS: "60000",
  };
}

/**
 * Write a supervisor journal record for one execution, as a previous run would have left it.
 *
 * The record is written by hand rather than through `Journal.writeSupervisor` because a real
 * predecessor is a *different instance*, and the fencing layer refuses a write by an unbound
 * journal — which is the behaviour being modelled, not a detail to work around.
 */
function seedSupervisorRecord(env: Environment, executionId: string, overrides: Record<string, unknown> = {}): void {
  const dir = join(env.journalRoot, "supervisor");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const record = {
    schema: 1,
    executionId,
    bootId: env.bootId,
    supervisorInstance: "sv-predecessor1",
    containerName: `dip-exec-${executionId}`,
    containerId: "c".repeat(64),
    imageDigest: `sha256:${"d".repeat(64)}`,
    profileId: "synthetic-v1",
    deadlineMs: 60_000,
    startedMonotonicMs: 1_000,
    phase: "created",
    sequence: 2,
    outcome: null,
    writerInstance: "sv-predecessor1",
    ...overrides,
  };
  writeFileSync(join(dir, `${executionId}.json`), `${JSON.stringify(record)}\n`, { mode: 0o600 });
}

test("R7D.1-D2S-1: the supervisor starts, reconciles an empty journal, and connects to the watchdog", async () => {
  const env = makeEnvironment();
  const watchdog = spawnNode("workers/watchdog.ts", watchdogEnv(env));
  let supervisor: Proc | null = null;
  try {
    await watchdog.waitFor("ready");
    supervisor = spawnNode("workers/supervisor.ts", supervisorEnv(env));
    const reconciled = await supervisor.waitFor("reconciled");
    assert.equal(reconciled.clear, true);
    assert.equal(reconciled.quarantined, 0);

    const ready = await supervisor.waitFor("ready");
    // The watchdog the supervisor is bound to is the one it actually handshook with.
    assert.equal(ready.watchdog, String((await watchdog.waitFor("ready")).instance));
    assert.equal(ready.bootId, env.bootId);

    // Both role sockets exist and are mode 0600.
    for (const socket of [env.appSocket, env.workerSocket]) {
      assert.ok(existsSync(socket), `${socket} must exist`);
      assert.equal(statSync(socket).mode & 0o777, 0o600, `${socket} must be mode 0600`);
    }
  } finally {
    await supervisor?.stop();
    await watchdog.stop();
    env.cleanup();
  }
});

test("R7D.1-D2S-2: a supervisor whose journal cannot be bound refuses to start", async () => {
  const env = makeEnvironment();
  try {
    // The journal root is a regular file, so it cannot be a directory.
    writeFileSync(join(env.root, "not-a-dir"), "x");
    const supervisor = spawnNode("workers/supervisor.ts", {
      ...supervisorEnv(env),
      DIP_SUPERVISOR_ROOT: join(env.root, "not-a-dir"),
    });
    const code = await new Promise<number | null>((resolve) => supervisor.child.once("exit", resolve));
    assert.notEqual(code, 0, "a supervisor that cannot bind its journal must exit non-zero");
    assert.equal(supervisor.events().some((event) => event.event === "ready"), false);
  } finally {
    env.cleanup();
  }
});

test("R7D.1-D2S-3: a missing watchdog is a start-up failure, before any socket listens", async () => {
  const env = makeEnvironment();
  try {
    const supervisor = spawnNode("workers/supervisor.ts", supervisorEnv(env));
    const code = await new Promise<number | null>((resolve) => supervisor.child.once("exit", resolve));
    assert.notEqual(code, 0);
    // Reconciliation ran (it is before the watchdog), but no socket was created.
    assert.equal(existsSync(env.appSocket), false, "no role socket may be created without a watchdog");
    assert.equal(supervisor.events().some((event) => event.event === "ready"), false);
  } finally {
    env.cleanup();
  }
});

test("R7D.1-D2S-4: an unresolved record blocks admission instead of being ignored", async () => {
  // ## The property
  //
  // A previous supervisor created a container and died. The daemon is not reachable here, so its
  // container cannot be shown absent. The supervisor must refuse to admit new work: the profile
  // allows one executor, and the predecessor's may still be running.
  const env = makeEnvironment();
  const executionId = "e".repeat(32);
  seedSupervisorRecord(env, executionId);
  const watchdog = spawnNode("workers/watchdog.ts", watchdogEnv(env));
  let supervisor: Proc | null = null;
  try {
    await watchdog.waitFor("ready");
    supervisor = spawnNode("workers/supervisor.ts", supervisorEnv(env));
    const reconciled = await supervisor.waitFor("reconciled");
    assert.equal(reconciled.clear, false, "an unaccounted container must not be treated as clear");
    const blocked = await supervisor.waitFor("admission-blocked");
    assert.ok(Array.isArray(blocked.quarantine) && blocked.quarantine.includes(executionId));
    const code = await new Promise<number | null>((resolve) => supervisor!.child.once("exit", resolve));
    assert.equal(code, 3, "the supervisor must exit with the fail-closed code");
    assert.equal(existsSync(env.appSocket), false, "no socket may serve while admission is blocked");
  } finally {
    await supervisor?.stop();
    await watchdog.stop();
    env.cleanup();
  }
});

test("R7D.1-D2S-5: a record from a previous boot is reported and does not block this boot", async () => {
  // A different boot id means a different container namespace: the record describes something that
  // cannot exist here, so it is history rather than debt.
  const env = makeEnvironment();
  seedSupervisorRecord(env, "f".repeat(32), { bootId: "00000000-0000-4000-8000-000000000000" });
  const watchdog = spawnNode("workers/watchdog.ts", watchdogEnv(env));
  let supervisor: Proc | null = null;
  try {
    await watchdog.waitFor("ready");
    supervisor = spawnNode("workers/supervisor.ts", supervisorEnv(env));
    const reconciled = await supervisor.waitFor("reconciled");
    assert.equal(reconciled.clear, true, "a previous-boot record must not block this boot");
    await supervisor.waitFor("ready");
  } finally {
    await supervisor?.stop();
    await watchdog.stop();
    env.cleanup();
  }
});

test("R7D.1-D2S-6: the supervisor refuses a watchdog on a different boot", async () => {
  const env = makeEnvironment();
  const watchdog = spawnNode("workers/watchdog.ts", watchdogEnv(env));
  let supervisor: Proc | null = null;
  try {
    await watchdog.waitFor("ready");
    // The supervisor claims a boot the watchdog is not on. The channel must not authenticate.
    supervisor = spawnNode("workers/supervisor.ts", {
      ...supervisorEnv(env),
      DIP_SUPERVISOR_BOOT: "00000000-0000-4000-8000-000000000000",
    });
    const code = await new Promise<number | null>((resolve) => supervisor!.child.once("exit", resolve));
    assert.notEqual(code, 0);
    assert.equal(supervisor.events().some((event) => event.event === "ready"), false);
    // The reconciliation happened first and found nothing, so the refusal is about the channel.
    assert.equal(supervisor.events().some((event) => event.event === "reconciled"), true);
  } finally {
    await supervisor?.stop();
    await watchdog.stop();
    env.cleanup();
  }
});

test("R7D.1-D2S-7: a supervisor with a short caller secret refuses to start", async () => {
  const env = makeEnvironment();
  try {
    const supervisor = spawnNode("workers/supervisor.ts", {
      ...supervisorEnv(env),
      DIP_CALLER_SECRET: "0011223344",
    });
    const code = await new Promise<number | null>((resolve) => supervisor.child.once("exit", resolve));
    assert.notEqual(code, 0);
    assert.equal(supervisor.events().some((event) => event.event === "ready"), false);
  } finally {
    env.cleanup();
  }
});

// ══ D2-F05 · The executor image's architecture mapping ══════════════════════════════════════════

test("R7D.1-D2F05-1: Docker's TARGETARCH values map onto npm's cpu names", async () => {
  // ## The defect this holds
  //
  // BuildKit sets `TARGETARCH` to Docker's spelling (`amd64`); npm's `--cpu` and the
  // `@napi-rs/canvas-linux-<cpu>-gnu` package name use Node's (`x64`). The Dockerfile used to
  // accept only `arm64|x64` and pass the value straight to `npm ci --cpu`, so a real x64 build was
  // rejected outright, and forcing `x64` produced a closure with the native package filtered out.
  //
  // The mapping is asserted by executing the same shell the Dockerfile runs, rather than by reading
  // the file as text. There is no Docker daemon in this environment, so the image cannot be built;
  // the *decision* can still be checked, and that is where the defect was.
  const dockerfile = readFileSync("Dockerfile.executor", "utf8");
  // Only the first `case ... esac` block: the rest of the deps stage installs packages, and a test
  // must not run an install.
  const caseStart = dockerfile.indexOf('RUN case "${TARGETARCH}" in');
  const caseEnd = dockerfile.indexOf("esac", caseStart);
  const mapping = dockerfile.slice(caseStart, caseEnd + "esac".length);
  assert.ok(mapping.length > 0, "the deps-stage mapping must be present");

  const resolved = (targetArch: string): { code: number; cpu: string } => {
    // The case statement is extracted and evaluated verbatim, so a change to the Dockerfile is a
    // change to what this test checks.
    const script = `NODE_CPU=""\n${mapping.replace(/^RUN /u, "")}\nprintf '%s' "$NODE_CPU"`;
    const result = spawnSync("sh", ["-c", script], { env: { ...process.env, TARGETARCH: targetArch } });
    return { code: result.status ?? -1, cpu: result.stdout.toString("utf8").trim() };
  };

  assert.deepEqual(resolved("amd64"), { code: 0, cpu: "x64" }, `mapping script output: ${JSON.stringify(resolved("amd64"))}`);
  assert.deepEqual(resolved("x64"), { code: 0, cpu: "x64" });
  assert.deepEqual(resolved("arm64"), { code: 0, cpu: "arm64" });
  assert.deepEqual(resolved("aarch64"), { code: 0, cpu: "arm64" });
  // Anything else fails closed rather than silently resolving a wrong architecture.
  assert.notEqual(resolved("mips64").code, 0);
  assert.notEqual(resolved("").code, 0);
});

test("R7D.1-D2F05-2: the runtime stage declares the ARGs it uses and places the binding by resolved name", () => {
  const dockerfile = readFileSync("Dockerfile.executor", "utf8");
  const runtime = dockerfile.slice(dockerfile.indexOf("AS runtime"));
  // `ARG` is stage-scoped: the runtime stage must redeclare what it references, or the expansion is
  // empty and the COPY reads a path that never existed.
  assert.match(runtime, /^ARG TARGETOS=/m);
  assert.match(runtime, /^ARG TARGETARCH/mu);
  // And the native binding is placed from the recorded cpu name, not from `${TARGETARCH}`.
  assert.match(runtime, /NODE_CPU=[\s\S]*\/tmp\/\.node-cpu/);
  assert.match(runtime, /canvas-linux-\$\{NODE_CPU\}-gnu/u);
  // Only the instructions matter; the comment above explains the defect and necessarily names it.
  const instructions = runtime.split("\n").filter((line) => !line.trimStart().startsWith("#")).join("\n");
  assert.doesNotMatch(instructions, /canvas-\$\{TARGETOS\}-\$\{TARGETARCH\}-gnu/u, "the unresolvable path must be gone");
  // Non-root and the lockfile-authority properties are unchanged by this fix.
  assert.match(dockerfile, /useradd --system --uid 10001/u);
  assert.match(dockerfile, /npm ci --no-audit --no-fund --ignore-scripts/u);
});
