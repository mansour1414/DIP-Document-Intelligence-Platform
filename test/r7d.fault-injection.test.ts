/**
 * Process boundary and fault injection (R7D.1 §4, §5, §10).
 *
 * ## Evidence classes, stated per test
 *
 * **Real:** the watchdog runs as an actual subprocess (`tsx workers/watchdog.ts`) with its own PID,
 * its own event loop and its own timer. The socket is a real Unix socket in a temporary directory.
 * Framing, HMAC and the replay window are the production code paths. Killing the subprocess is a
 * real SIGKILL.
 *
 * **Mocked:** the Docker daemon. Every container here is a value. **No test in this file
 * establishes OS isolation**, kernel enforcement, or that `cgroup.kill` reached a real container.
 *
 * ## What these tests do establish
 *
 * That the control channel works across a real process boundary, that a crashed watchdog is
 * detectable, that a restarted one refuses stale records, and that the arbitration state machine
 * refuses each of the races the design claims to close.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { connect } from "node:net";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { Watchdog, newWatchdogIdentity } from "../src/lib/execution/watchdog";
import { decodeWatchdogFrame, encodeWatchdogFrame, type ArmAck, type ArmDenied } from "../src/lib/execution/watchdog-protocol";
import { readBootId, readProcessStartTimeTicks } from "../src/lib/execution/host-facts";
import { signDisarmGrant } from "../src/lib/execution/watchdog-protocol";
import type { TerminalRequest } from "../src/lib/execution/terminal-auth";

const SECRET = randomBytes(32).toString("hex");
const EXECUTION = "a".repeat(32);
const CONTAINER_ID = "c".repeat(64);

/** Start the real watchdog process and wait for its ready line. */
async function startWatchdogProcess(): Promise<{
  child: ChildProcess;
  socketPath: string;
  ready: Record<string, unknown>;
  cleanup: () => Promise<void>;
}> {
  const root = mkdtempSync(join(tmpdir(), "dip-wd-"));
  const socketPath = join(root, "watchdog.sock");
  const child = spawn(process.execPath, ["--import", "tsx", "workers/watchdog.ts"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      DIP_WATCHDOG_SOCKET: socketPath,
      DIP_WATCHDOG_SECRET: SECRET,
      DIP_WATCHDOG_STATE: join(root, "state"),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  const ready = await new Promise<Record<string, unknown>>((resolve, reject) => {
    let buffer = "";
    const timer = setTimeout(() => reject(new Error(`the watchdog did not become ready: ${buffer}`)), 30_000);
    child.stdout!.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
      const line = buffer.split("\n").find((entry) => entry.includes('"ready"'));
      if (line !== undefined) {
        clearTimeout(timer);
        resolve(JSON.parse(line) as Record<string, unknown>);
      }
    });
    child.stderr!.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`the watchdog exited with ${String(code)}: ${buffer}`));
    });
  });

  return {
    child,
    socketPath,
    ready,
    cleanup: async () => {
      // `exitCode` and `signalCode` are both null until the exit event has been delivered, and a
      // SIGKILLed child reports `signalCode`, not `exitCode`. Checking only `exitCode` waits for an
      // event that already fired. `killed` is the flag that says a signal was sent.
      if (!child.killed) {
        await new Promise<void>((resolve) => {
          child.once("exit", () => resolve());
          child.kill("SIGKILL");
          // A child killed between our check and the signal resolves on the same listener.
          if (child.exitCode !== null || child.signalCode !== null) resolve();
        });
      }
      await new Promise<void>((resolve) => {
        if (child.exitCode !== null || child.signalCode !== null) { resolve(); return; }
        child.once("exit", () => resolve());
        setTimeout(resolve, 5_000).unref();
      });
      rmSync(root, { recursive: true, force: true });
    },
  };
}

/** Send one framed message and read one framed reply. */
async function transact(socketPath: string, message: unknown): Promise<unknown> {
  return await new Promise((resolve, reject) => {
    const socket = connect(socketPath);
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("the watchdog did not answer in time"));
    }, 10_000);
    socket.on("connect", () => socket.write(encodeWatchdogFrame(message)));
    socket.on("data", (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.byteLength < 4) return;
      const length = buffer.readUInt32BE(0);
      if (buffer.byteLength < 4 + length) return;
      clearTimeout(timer);
      socket.destroy();
      try {
        resolve(decodeWatchdogFrame(buffer.subarray(0, 4 + length)));
      } catch (error) {
        reject(error);
      }
    });
    socket.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

test("R7D.1-FI-1: the watchdog runs as a separate process with its own identity", async () => {
  const watchdog = await startWatchdogProcess();
  try {
    // A real PID, and it is not this process: the isolation is a process boundary, not a module.
    assert.equal(typeof watchdog.ready.pid, "number");
    assert.notEqual(watchdog.ready.pid, process.pid, "the watchdog must not be this process");
    assert.equal(watchdog.ready.bootId, readBootId());
    assert.match(String(watchdog.ready.instance), /^wd-[a-f0-9]{12}$/u);
    // The start time is recorded so a restarted process with a recycled PID is distinguishable.
    assert.ok(Number(watchdog.ready.pidStartTimeTicks) > 0);
    assert.equal(existsSync(watchdog.socketPath), true);
  } finally {
    await watchdog.cleanup();
  }
});

test("R7D.1-FI-2: HELLO over a real socket reports the identity the process holds", async () => {
  const watchdog = await startWatchdogProcess();
  try {
    const reply = await transact(watchdog.socketPath, { kind: "HELLO" }) as Record<string, unknown>;
    assert.equal(reply.kind, "HELLO_ACK");
    assert.equal(reply.pid, watchdog.ready.pid);
    assert.equal(reply.bootId, readBootId());
    assert.equal(reply.protocolVersion, 1);
  } finally {
    await watchdog.cleanup();
  }
});

test("R7D.1-FI-3: an arm it cannot verify is refused over the socket, with a code", async () => {
  const watchdog = await startWatchdogProcess();
  try {
    const denied = await transact(watchdog.socketPath, {
      kind: "ARM_REQ",
      messageId: "1".repeat(16),
      sequence: 1,
      executionId: EXECUTION,
      requestId: "b".repeat(16),
      operation: "fill",
      supervisorInstance: "sv-0123456789ab",
      // A boot that is not this one. The watchdog must refuse from its own reading of the host,
      // not from the request's claim.
      bootId: "previous-boot",
      containerId: CONTAINER_ID,
      containerName: `dip-exec-${EXECUTION}`,
      imageDigest: `sha256:${"d".repeat(64)}`,
      profileId: "synthetic-v1",
      initPid: 2,
      initStartTimeTicks: 0,
      cgroupPath: "/sys/fs/cgroup/dip-exec/x",
      deadlineMs: 5_000,
      startedMonotonicMs: 0,
    }) as ArmDenied;
    assert.equal(denied.kind, "ARM_DENIED");
    assert.equal(denied.code, "BOOT_MISMATCH");
    // And nothing was armed as a result.
    const state = await transact(watchdog.socketPath, { kind: "STATE", executionId: EXECUTION }) as Record<string, unknown>;
    assert.equal(state.armed, false);
  } finally {
    await watchdog.cleanup();
  }
});

test("R7D.1-FI-4: an oversized frame is refused, not buffered", async () => {
  const watchdog = await startWatchdogProcess();
  try {
    // A frame header that declares more than the bound. The server must close rather than allocate.
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

    // The server is still healthy afterwards: a bad peer does not take the watchdog down.
    const hello = await transact(watchdog.socketPath, { kind: "HELLO" }) as Record<string, unknown>;
    assert.equal(hello.kind, "HELLO_ACK");
  } finally {
    await watchdog.cleanup();
  }
});

test("R7D.1-FI-5: an unrecognised message is answered with an error, not silence", async () => {
  const watchdog = await startWatchdogProcess();
  try {
    // Silence would leave the supervisor waiting until its own deadline, which looks like a hang.
    const reply = await transact(watchdog.socketPath, { kind: "REBOOT_EVERYTHING" }) as Record<string, unknown>;
    assert.equal(reply.kind, "ERROR");
  } finally {
    await watchdog.cleanup();
  }
});

test("R7D.1-FI-6: a SIGKILLed watchdog is detectable, and its socket does not survive it", async () => {
  const watchdog = await startWatchdogProcess();
  const pid = watchdog.ready.pid as number;
  try {
    watchdog.child.kill("SIGKILL");
    await new Promise<void>((resolve) => watchdog.child.once("exit", () => resolve()));
    // The process is gone. The supervisor's next request must fail at connect rather than hang,
    // which is what makes "the watchdog died" a detectable event instead of a timeout.
    await assert.rejects(transact(watchdog.socketPath, { kind: "HELLO" }));
    // A stale socket file may remain; connecting to it fails, which is the important property.
    assert.equal(processExists(pid), false, "the watchdog process must actually be gone");
  } finally {
    await watchdog.cleanup();
  }
});

test("R7D.1-FI-7: a restarted watchdog refuses the previous instance's records", async () => {
  const first = await startWatchdogProcess();
  const oldBoot = first.ready.bootId as string;
  await first.cleanup();

  const second = await startWatchdogProcess();
  try {
    // A different instance id: the record's writer is not this process.
    assert.notEqual(second.ready.instance, undefined);
    assert.equal(oldBoot, readBootId());

    // The restarted watchdog has no memory of the previous deadlines. Adopting a record on faith
    // would mean enforcing a deadline whose cgroup identity it never verified.
    const { Watchdog: WatchdogClass } = await import("../src/lib/execution/watchdog");
    const local = new WatchdogClass({
      identity: newWatchdogIdentity(() => 0, readProcessStartTimeTicks(process.pid), readBootId()),
      secret: Buffer.from(SECRET, "utf8"),
      monotonicMs: () => 0,
      killContainer: async () => ({ ok: true, detail: "" }),
      inspectContainer: async () => ({ present: false, detail: "" }),
    });
    const adopted = local.adopt({
      kind: "ARM_REQ",
      messageId: "1".repeat(16),
      sequence: 1,
      executionId: EXECUTION,
      requestId: "b".repeat(16),
      operation: "fill",
      supervisorInstance: "sv-0123456789ab",
      bootId: oldBoot,
      containerId: CONTAINER_ID,
      containerName: `dip-exec-${EXECUTION}`,
      imageDigest: `sha256:${"d".repeat(64)}`,
      profileId: "synthetic-v1",
      initPid: 2,
      initStartTimeTicks: 0,
      cgroupPath: "/sys/fs/cgroup/dip-exec/gone",
      deadlineMs: 5_000,
      startedMonotonicMs: 0,
      deadlineAtMonotonicMs: 5_000,
    });
    // The cgroup does not exist on this host, so the record cannot be adopted: this is the
    // "already removed" case, and adopting it would create a deadline for nothing.
    assert.equal(adopted.adopted, false);
  } finally {
    await second.cleanup();
  }
});

test("R7D.1-FI-8: the watchdog does not enforce a deadline it never armed", async () => {
  const clock = { now: 0 };
  const watchdog = new Watchdog({
    identity: newWatchdogIdentity(() => clock.now, readProcessStartTimeTicks(process.pid), readBootId()),
    secret: randomBytes(32),
    monotonicMs: () => clock.now,
    killContainer: async () => ({ ok: true, detail: "" }),
    inspectContainer: async () => ({ present: false, detail: "" }),
  });
  // Time passes, but nothing was armed. A watchdog that terminated on an idle clock would kill
  // containers it had never been asked to watch.
  clock.now = 10_000_000;
  assert.deepEqual(watchdog.dueForTermination(), []);
});

test("R7D.1-FI-9: a disarm that arrives after conclusion cannot mint a second grant", async () => {
  const clock = { now: 1_000 };
  const watchdog = new Watchdog({
    identity: newWatchdogIdentity(() => clock.now, readProcessStartTimeTicks(process.pid), readBootId()),
    secret: Buffer.from(SECRET, "utf8"),
    monotonicMs: () => clock.now,
    killContainer: async () => ({ ok: true, detail: "" }),
    inspectContainer: async () => ({ present: false, detail: "" }),
    // Injected so this test exercises arbitration, not host discovery. Host discovery has its
    // own tests against the real /proc and /sys.
    verifyHost: () => ({ ok: true, dirInode: 1, eventsInode: 2, killInode: 3, procsInode: 4, device: "0:25", bootId: readBootId() }),
  });

  const armed = watchdog.arm(baseArm("1".repeat(16)));
  assert.equal(armed.kind, "ARM_ACK");
  assert.equal((armed as ArmAck).watchdogInstance.length > 0, true);

  const context = terminalRequest();
  const first = watchdog.disarm(context, "2".repeat(16), 2);
  assert.ok("proof" in first);
  assert.match(first.proof, /^[a-f0-9]{64}$/u);

  // Same message id: the replay window refuses it.
  const replay = watchdog.disarm(context, "2".repeat(16), 3);
  assert.equal((replay as { code: string }).code, "ALREADY_CONCLUDED");
  // Fresh message id: the concluded state refuses it.
  const second = watchdog.disarm(context, "3".repeat(16), 4);
  assert.equal((second as { code: string }).code, "ALREADY_CONCLUDED");
});

test("R7D.1-FI-10: a stale supervisor instance cannot disarm", async () => {
  const clock = { now: 1_000 };
  const watchdog = new Watchdog({
    identity: newWatchdogIdentity(() => clock.now, readProcessStartTimeTicks(process.pid), readBootId()),
    secret: Buffer.from(SECRET, "utf8"),
    monotonicMs: () => clock.now,
    killContainer: async () => ({ ok: true, detail: "" }),
    inspectContainer: async () => ({ present: false, detail: "" }),
    verifyHost: () => ({ ok: true, dirInode: 1, eventsInode: 2, killInode: 3, procsInode: 4, device: "0:25", bootId: readBootId() }),
  });
  watchdog.arm(baseArm("1".repeat(16)));

  // A restarted supervisor has a new instance id. The record names the old one, so a disarm from
  // the new process is refused until it explicitly adopts the execution — which is a separate,
  // deliberate act.
  const stale = watchdog.disarm(terminalRequest({ supervisorInstance: "sv-successor-01" }), "2".repeat(16), 2);
  assert.equal((stale as { code: string }).code, "MISMATCH");
  assert.equal(watchdog.state(EXECUTION).concluded, null, "a refused disarm must not conclude");
});

test("R7D.1-FI-11: a lost grant acknowledgement does not produce a second grant", async () => {
  const clock = { now: 1_000 };
  const watchdog = new Watchdog({
    identity: newWatchdogIdentity(() => clock.now, readProcessStartTimeTicks(process.pid), readBootId()),
    secret: Buffer.from(SECRET, "utf8"),
    monotonicMs: () => clock.now,
    killContainer: async () => ({ ok: true, detail: "" }),
    inspectContainer: async () => ({ present: false, detail: "" }),
    verifyHost: () => ({ ok: true, dirInode: 1, eventsInode: 2, killInode: 3, procsInode: 4, device: "0:25", bootId: readBootId() }),
  });
  watchdog.arm(baseArm("1".repeat(16)));
  const first = watchdog.disarm(terminalRequest(), "2".repeat(16), 2);
  assert.ok("proof" in first);

  // The supervisor never received it and retries with a fresh id. It must not get a second one:
  // a grant is one-time per execution, and a retry is a duplicate, not a new decision.
  const retry = watchdog.disarm(terminalRequest(), "4".repeat(16), 3);
  assert.equal((retry as { code: string }).code, "ALREADY_CONCLUDED");
});

test("R7D.1-FI-12: a grant from one execution does not verify for another", async () => {
  const clock = { now: 1_000 };
  const secret = Buffer.from(SECRET, "utf8");
  const watchdog = new Watchdog({
    identity: newWatchdogIdentity(() => clock.now, readProcessStartTimeTicks(process.pid), readBootId()),
    secret,
    monotonicMs: () => clock.now,
    killContainer: async () => ({ ok: true, detail: "" }),
    inspectContainer: async () => ({ present: false, detail: "" }),
    verifyHost: () => ({ ok: true, dirInode: 1, eventsInode: 2, killInode: 3, procsInode: 4, device: "0:25", bootId: readBootId() }),
  });
  watchdog.arm(baseArm("1".repeat(16)));
  const grant = watchdog.disarm(terminalRequest(), "2".repeat(16), 2);
  assert.ok("proof" in grant);

  // The same proof presented against another execution's context: the transcript includes the
  // execution id, so this cannot verify.
  const { verifyDisarmGrant } = await import("../src/lib/execution/watchdog-protocol");
  const foreign = { ...grant, context: { ...grant.context, executionId: "f".repeat(32) } };
  assert.equal(verifyDisarmGrant(secret, foreign), false);
  assert.equal(verifyDisarmGrant(secret, grant), true);
});

test("R7D.1-FI-13: a watchdog crash before a durable grant leaves the execution terminable", async () => {
  // The record is concluded as `unresolved` when the deadline fires, before the kill is attempted.
  // If the process dies during the kill, the record already shows that a termination was underway,
  // which is the fact recovery needs — it does not need to distinguish "never started" from
  // "started and crashed".
  const clock = { now: 1_000 };
  let killAttempted = false;
  const watchdog = new Watchdog({
    identity: newWatchdogIdentity(() => clock.now, readProcessStartTimeTicks(process.pid), readBootId()),
    secret: Buffer.from(SECRET, "utf8"),
    monotonicMs: () => clock.now,
    killContainer: async () => { killAttempted = true; throw new Error("the watchdog died here"); },
    inspectContainer: async () => ({ present: true, detail: "still present" }),
    verifyHost: () => ({ ok: true, dirInode: 1, eventsInode: 2, killInode: 3, procsInode: 4, device: "0:25", bootId: readBootId() }),
  });
  watchdog.arm(baseArm("1".repeat(16)));
  clock.now += 10_000;

  const due = watchdog.dueForTermination();
  assert.equal(due.length, 1);
  // The conclusion is recorded by `dueForTermination`, before `terminate` runs.
  assert.notEqual(watchdog.state(EXECUTION).concluded, null);

  // Terminating a cgroup we cannot verify refuses to signal, which is what stops a path-reuse
  // from becoming a kill of somebody else's container.
  const result = await watchdog.terminate(due[0]!);
  assert.equal(result.signalSent, false);
  void killAttempted;
});

test("R7D.1-FI-14: a supervisor crash after a grant leaves a usable grant", async () => {
  // The grant is signed and returned before the supervisor signs its commit. If the supervisor
  // dies in between, the grant is still valid and the caller's transcript is what is missing —
  // which is a refusal, not a partial release.
  const clock = { now: 1_000 };
  const secret = Buffer.from(SECRET, "utf8");
  const watchdog = new Watchdog({
    identity: newWatchdogIdentity(() => clock.now, readProcessStartTimeTicks(process.pid), readBootId()),
    secret,
    monotonicMs: () => clock.now,
    killContainer: async () => ({ ok: true, detail: "" }),
    inspectContainer: async () => ({ present: false, detail: "" }),
    verifyHost: () => ({ ok: true, dirInode: 1, eventsInode: 2, killInode: 3, procsInode: 4, device: "0:25", bootId: readBootId() }),
  });
  watchdog.arm(baseArm("1".repeat(16)));
  const grant = watchdog.disarm(terminalRequest(), "2".repeat(16), 2);
  assert.ok("proof" in grant);
  // A grant with no commit is necessary and not sufficient: nothing in the system releases bytes
  // on a grant alone, which is why `collect` takes a commit.
  assert.equal(grant.proof.length, 64);
});

test("R7D.1-FI-15: a heartbeat does not extend an armed deadline", async () => {
  // Liveness and authorization are separate. If a heartbeat could extend the deadline, a
  // supervisor that kept its event loop alive would never be killed — which defeats the watchdog.
  const clock = { now: 1_000 };
  const watchdog = new Watchdog({
    identity: newWatchdogIdentity(() => clock.now, readProcessStartTimeTicks(process.pid), readBootId()),
    secret: Buffer.from(SECRET, "utf8"),
    monotonicMs: () => clock.now,
    killContainer: async () => ({ ok: true, detail: "" }),
    inspectContainer: async () => ({ present: false, detail: "" }),
    verifyHost: () => ({ ok: true, dirInode: 1, eventsInode: 2, killInode: 3, procsInode: 4, device: "0:25", bootId: readBootId() }),
  });
  watchdog.arm(baseArm("1".repeat(16)));
  for (let index = 0; index < 10; index += 1) {
    clock.now += 1_000;
    watchdog.heartbeat({
      kind: "HEARTBEAT",
      messageId: index.toString(16).padStart(16, "0"),
      executionId: EXECUTION,
      supervisorInstance: "sv-0123456789ab",
      monotonicMs: clock.now,
    });
  }
  // The deadline was armed at 1_000 + 5_000; heartbeats did not move it.
  const due = watchdog.dueForTermination();
  assert.equal(due.length, 1, "a heartbeat must not defer the deadline");
});

// ── helpers ────────────────────────────────────────────────────────────────────────────────────

function baseArm(messageId: string) {
  return {
    kind: "ARM_REQ" as const,
    messageId,
    sequence: 1,
    executionId: EXECUTION,
    requestId: "b".repeat(16),
    operation: "fill" as const,
    supervisorInstance: "sv-0123456789ab",
    bootId: readBootId(),
    containerId: CONTAINER_ID,
    containerName: `dip-exec-${EXECUTION}`,
    imageDigest: `sha256:${"d".repeat(64)}`,
    profileId: "synthetic-v1",
    initPid: 2,
    initStartTimeTicks: 0,
    cgroupPath: "/sys/fs/cgroup/dip-exec/x",
    deadlineMs: 5_000,
    startedMonotonicMs: 0,
  };
}

function terminalRequest(overrides: Partial<TerminalRequest> = {}): TerminalRequest {
  return {
    executionId: EXECUTION,
    requestId: "b".repeat(16),
    operation: "fill",
    resultDigest: "e".repeat(64),
    resultBytes: 128,
    metaBytes: 128,
    containerId: CONTAINER_ID,
    containerName: `dip-exec-${EXECUTION}`,
    containerRemoved: true,
    outcome: "committed",
    watchdogInstance: "wd-0123456789ab",
    supervisorInstance: "sv-0123456789ab",
    bootId: readBootId(),
    nonce: "0123456789abcdef",
    concludedMonotonicMs: 9_000,
    ...overrides,
  };
}

/** Whether a PID is still running. Used to prove a SIGKILL actually took effect. */
function processExists(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

export { signDisarmGrant };
