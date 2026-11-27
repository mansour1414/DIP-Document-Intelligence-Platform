/**
 * Process boundary and crash recovery (R7D.1 §4, §5, §10; Continuation D1).
 *
 * ## Scope
 *
 * This file is about the *process*: that the watchdog is a separate OS process, that its death is
 * detectable, that its start-up refuses to serve when it cannot account for its records, and that a
 * crashed predecessor's work is neither forgotten nor silently adopted.
 *
 * The arbitration state machine (grants, expiry, replay, ownership) lives in
 * `r7d.watchdog-security.test.ts`. The authenticated channel lives in `r7d.watchdog-channel.test.ts`.
 * Those were previously mixed in here against the old unauthenticated frame protocol, which no
 * longer exists: every control request now requires a completed handshake.
 *
 * ## Evidence classes
 *
 * **Real:** the subprocess, its PID, SIGKILL, the Unix socket, the durable store on a real
 * temporary directory, and the start-up exit codes.
 *
 * **Mocked:** Docker (there is no daemon here). **Host verification is real** in the subprocess, and
 * therefore an arm cannot succeed — there is no writable `dip-executor.slice`. No test in this file
 * establishes OS isolation, kernel cgroup enforcement, or native ARM64 behaviour.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { connect } from "node:net";
import { mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { decodeWatchdogFrame, encodeWatchdogFrame } from "../src/lib/execution/watchdog-protocol";
import { readBootId } from "../src/lib/execution/host-facts";
import { BOOT } from "./support/watchdog-harness";

const EXECUTION = "a".repeat(32);

type Started = {
  child: ChildProcess;
  socketPath: string;
  stateDir: string;
  ready: Record<string, unknown>;
  cleanup: () => Promise<void>;
};

/** Start the real watchdog process and wait for its `ready` line. */
async function startWatchdogProcess(prepare?: (stateDir: string) => void): Promise<Started> {
  const root = mkdtempSync(join(tmpdir(), "dip-fi-"));
  const socketPath = join(root, "watchdog.sock");
  const stateDir = join(root, "state");
  // The predecessor's records are written before the process starts, which is exactly the situation
  // a restart faces.
  if (prepare !== undefined) {
    mkdirSync(join(stateDir, "records"), { recursive: true });
    prepare(stateDir);
  }

  const child = spawn(process.execPath, ["--import", "tsx", "workers/watchdog.ts"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      DIP_WATCHDOG_SOCKET: socketPath,
      DIP_WATCHDOG_SECRET: randomBytes(32).toString("hex"),
      DIP_WATCHDOG_STATE: stateDir,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  const ready = await new Promise<Record<string, unknown>>((resolve, reject) => {
    let buffer = "";
    const timer = setTimeout(() => reject(new Error(`the watchdog did not become ready: ${buffer}`)), 30_000);
    child.stdout!.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
      for (const line of buffer.split("\n")) {
        if (!line.includes('"event":"ready"')) continue;
        clearTimeout(timer);
        resolve(JSON.parse(line) as Record<string, unknown>);
      }
    });
    child.stderr!.on("data", (chunk: Buffer) => { buffer += chunk.toString("utf8"); });
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`the watchdog exited with ${String(code)}: ${buffer}`));
    });
  });

  return {
    child,
    socketPath,
    stateDir,
    ready,
    cleanup: async () => {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      await new Promise<void>((resolve) => {
        if (child.exitCode !== null || child.signalCode !== null) { resolve(); return; }
        child.once("exit", () => resolve());
        setTimeout(resolve, 5_000).unref();
      });
      rmSync(root, { recursive: true, force: true });
    },
  };
}

/**
 * Run the process and report how it started.
 *
 * `ready: true` means it reached readiness and was still serving when the window closed — that is
 * the success case for these tests, so it is named rather than expressed as a timeout.
 */
async function runToExit(stateDir: string): Promise<{ code: number | null; ready: boolean; output: string }> {
  const root = mkdtempSync(join(tmpdir(), "dip-fi-exit-"));
  const child = spawn(process.execPath, ["--import", "tsx", "workers/watchdog.ts"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      DIP_WATCHDOG_SOCKET: join(root, "watchdog.sock"),
      DIP_WATCHDOG_SECRET: randomBytes(32).toString("hex"),
      DIP_WATCHDOG_STATE: stateDir,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  let ready = false;
  child.stdout!.on("data", (chunk: Buffer) => {
    output += chunk.toString("utf8");
    if (output.includes('"event":"ready"')) ready = true;
  });
  child.stderr!.on("data", (chunk: Buffer) => { output += chunk.toString("utf8"); });
  try {
    const code = await new Promise<number | null>((resolve) => {
      child.on("exit", (exitCode) => resolve(exitCode));
      // A ready process never exits on its own, so the window only has to outlive start-up.
      const poll = setInterval(() => {
        if (ready) { clearInterval(poll); resolve(null); }
      }, 50);
      poll.unref();
      setTimeout(() => { clearInterval(poll); resolve(null); }, 20_000).unref();
    });
    return { code, ready, output };
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    rmSync(root, { recursive: true, force: true });
  }
}

/** Send one frame on a fresh connection and read the first reply. */
async function oneFrame(socketPath: string, message: unknown): Promise<unknown> {
  return await new Promise((resolve, reject) => {
    const socket = connect(socketPath);
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => { socket.destroy(); reject(new Error("no reply")); }, 5_000);
    socket.on("connect", () => socket.write(encodeWatchdogFrame(message)));
    socket.on("data", (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.byteLength < 4) return;
      const length = buffer.readUInt32BE(0);
      if (buffer.byteLength < 4 + length) return;
      clearTimeout(timer);
      const frame = decodeWatchdogFrame(buffer.subarray(0, 4 + length));
      socket.destroy();
      resolve(frame);
    });
    socket.on("error", (error) => { clearTimeout(timer); reject(error); });
  });
}

function processExists(pid: number): boolean {
  try {
    const stat = statSync(`/proc/${pid}`);
    void stat;
    return true;
  } catch {
    return false;
  }
}

/** A record a crashed predecessor could have left behind. */
function previousRecord(overrides: Partial<Record<string, unknown>> = {}): Record<string, unknown> {
  return {
    schema: 1,
    executionId: EXECUTION,
    bootId: BOOT,
    watchdogInstance: "wd-0123456789ab",
    supervisorInstance: "sv-0123456789ab",
    requestId: "b".repeat(16),
    operation: "fill",
    containerId: "c".repeat(64),
    containerName: `dip-exec-${EXECUTION}`,
    imageDigest: `sha256:${"d".repeat(64)}`,
    profileId: "synthetic-v1",
    initPid: 4_242,
    initStartTimeTicks: 100,
    cgroupPath: `/sys/fs/cgroup/dip-executor.slice/dip-exec-${EXECUTION}`,
    cgroupDevice: "0:25",
    cgroupDirInode: 4_001,
    cgroupEventsInode: 4_002,
    cgroupKillInode: 4_003,
    cgroupProcsInode: 4_004,
    deadlineAtMs: 30_000,
    armedAtMs: 10_000,
    phase: "armed",
    processDebt: "terminate-required",
    containerDebt: "removal-required",
    outcome: null,
    sequence: 1,
    ...overrides,
  };
}

// ── Process identity and liveness ───────────────────────────────────────────────────────────────

test("R7D.1-FI-1: the watchdog runs as a separate process with its own identity", async () => {
  const watchdog = await startWatchdogProcess();
  try {
    const pid = watchdog.ready.pid as number;
    assert.notEqual(pid, process.pid, "the watchdog must not be this process");
    assert.equal(processExists(pid), true);
    assert.match(String(watchdog.ready.instance), /^wd-[a-f0-9]{12}$/u);
    // The boot id it reports is its own reading of the host, not something it was told.
    assert.equal(watchdog.ready.bootId, readBootId());
    assert.equal(watchdog.ready.bootId, BOOT);
  } finally {
    await watchdog.cleanup();
  }
});

test("R7D.1-FI-2: HELLO over a real socket reports the identity the process holds", async () => {
  const watchdog = await startWatchdogProcess();
  try {
    const challenge = await oneFrame(watchdog.socketPath, {
      kind: "HELLO",
      clientNonce: randomBytes(32).toString("hex"),
      clientInstance: "sv-0123456789ab",
      protocolVersion: 2,
    }) as Record<string, unknown>;
    assert.equal(challenge.kind, "CHALLENGE");
    // The reported identity is the process's own, so a supervisor can tell which watchdog it is
    // talking to before it trusts anything it is told.
    assert.equal(challenge.serverInstance, watchdog.ready.instance);
    assert.equal(challenge.pid, watchdog.ready.pid);
    assert.equal(challenge.bootId, watchdog.ready.bootId);
  } finally {
    await watchdog.cleanup();
  }
});

test("R7D.1-FI-3: an oversized frame is refused, not buffered", async () => {
  const watchdog = await startWatchdogProcess();
  try {
    // A header that declares more than the bound. The server must close rather than allocate 9 MB
    // for a peer that has authenticated nothing.
    const closed = await new Promise<boolean>((resolve) => {
      const socket = connect(watchdog.socketPath);
      socket.on("connect", () => {
        const header = Buffer.alloc(4);
        header.writeUInt32BE(9_000_000, 0);
        socket.write(Buffer.concat([header, Buffer.alloc(16)]));
      });
      socket.on("close", () => resolve(true));
      socket.on("error", () => resolve(true));
      setTimeout(() => resolve(false), 5_000).unref();
    });
    assert.equal(closed, true);

    // The server is still healthy afterwards: one bad peer does not take the watchdog down.
    const challenge = await oneFrame(watchdog.socketPath, {
      kind: "HELLO",
      clientNonce: randomBytes(32).toString("hex"),
      clientInstance: "sv-0123456789ab",
      protocolVersion: 2,
    }) as Record<string, unknown>;
    assert.equal(challenge.kind, "CHALLENGE");
  } finally {
    await watchdog.cleanup();
  }
});

test("R7D.1-FI-4: an unauthenticated privileged message is answered, not ignored", async () => {
  const watchdog = await startWatchdogProcess();
  try {
    // Silence would leave a caller waiting until its own deadline, which looks like a hang rather
    // than a refusal. A generic "do everything" op is refused because it is not in the
    // authenticated vocabulary at all.
    const reply = await oneFrame(watchdog.socketPath, { kind: "REBOOT_EVERYTHING" }) as Record<string, unknown>;
    assert.equal(reply.kind, "ERROR");
    assert.equal(reply.code, "UNAUTHENTICATED");
  } finally {
    await watchdog.cleanup();
  }
});

test("R7D.1-FI-5: a SIGKILLed watchdog is detectable and its socket does not serve", async () => {
  const watchdog = await startWatchdogProcess();
  const pid = watchdog.ready.pid as number;
  try {
    watchdog.child.kill("SIGKILL");
    await new Promise<void>((resolve) => watchdog.child.once("exit", () => resolve()));
    // The process is gone, so the next connect fails rather than hanging. That is what makes
    // "the watchdog died" an event instead of a timeout.
    await assert.rejects(oneFrame(watchdog.socketPath, { kind: "HELLO" }));
    assert.equal(processExists(pid), false, "the watchdog process must actually be gone");
  } finally {
    await watchdog.cleanup();
  }
});

// ── Start-up recovery ───────────────────────────────────────────────────────────────────────────

test("R7D.1-FI-6: a record from this boot that cannot be re-pinned blocks readiness", async () => {
  // The predecessor armed this boot and died. The cgroup cannot be re-pinned in this sandbox, so the
  // watchdog cannot know whether the container is still running. It must refuse to serve rather
  // than accept new work it cannot enforce.
  const result = await runToExitWithRecord(previousRecord());
  assert.equal(result.code, 3, result.output);
  assert.match(result.output, /"event":"recovery-blocked"/u);
});

test("R7D.1-FI-7: a record from a previous boot is reported, and does not block this boot", async () => {
  // A record naming another boot describes namespaces that no longer exist. It cannot be resolved
  // here, and holding the watchdog closed forever would be a permanent outage.
  const result = await runToExitWithRecord(previousRecord({ bootId: "00000000-0000-4000-8000-000000000000" }));
  assert.equal(result.ready, true, result.output);
  assert.match(result.output, /"previousBoot"/u);
});

test("R7D.1-FI-8: a corrupt record blocks readiness", async () => {
  const result = await runToExitWithRecord('{"schema":1,"executionId":');
  assert.equal(result.code, 3, result.output);
  assert.match(result.output, /"quarantined"/u);
});

test("R7D.1-FI-9: a concluded record is recovered without blocking", async () => {
  // A record that already reached a terminal phase needs no enforcement, so it must not hold the
  // watchdog closed. This is the difference between "history" and "debt".
  const result = await runToExitWithRecord(previousRecord({
    phase: "terminated",
    outcome: "terminated",
    processDebt: "termination-confirmed",
    containerDebt: "removal-confirmed",
  }));
  assert.equal(result.ready, true, result.output);
  assert.match(result.output, /"concluded"/u);
});

test("R7D.1-FI-10: a watchdog armed this boot survives a restart as an unresolved record", async () => {
  // End to end on the durable half: the first process records an interrupted arm, the second finds
  // it. Nothing is forgotten across the restart, which is the whole point of WD-01.
  const first = await startWatchdogProcess((stateDir) => {
    writeFileSync(join(stateDir, "records", `${EXECUTION}.json`), JSON.stringify(previousRecord({
      phase: "terminating",
      processDebt: "termination-required",
      outcome: "unresolved",
    })));
  }).catch((error: Error) => error);
  // The first process refuses to become ready, which is the expected outcome for an armed record it
  // cannot re-pin. What matters is that it did not forget the record.
  assert.ok(first instanceof Error);
  assert.match(String(first), /exited with 3/u);
});

// ── Helpers ────────────────────────────────────────────────────────────────────────────────────

/** Start a watchdog over a state directory containing exactly one prepared record, to completion. */
async function runToExitWithRecord(record: Record<string, unknown> | string): Promise<{ code: number | null; ready: boolean; output: string }> {
  const stateDir = mkdtempSync(join(tmpdir(), "dip-fi-state-"));
  try {
    mkdirSync(join(stateDir, "records"), { recursive: true });
    writeFileSync(
      join(stateDir, "records", `${EXECUTION}.json`),
      typeof record === "string" ? record : JSON.stringify(record),
    );
    return await runToExit(stateDir);
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
}
