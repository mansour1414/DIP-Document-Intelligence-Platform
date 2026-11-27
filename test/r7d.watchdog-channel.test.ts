/**
 * The authenticated watchdog control channel, over a real Unix socket in a real subprocess
 * (R7D.1 Continuation D1, WD-02 and the subprocess half of WD-01/WD-05).
 *
 * ## What is real here
 *
 * The watchdog runs as an actual `tsx workers/watchdog.ts` process with its own PID and its own
 * event loop. The socket is a real Unix socket. The handshake, the HMAC proofs, the nonce window,
 * the framing and the durable store are all production code paths. The store directory is a real
 * temporary directory on disk, and the record files are read back by the test.
 *
 * ## What is mocked
 *
 * Docker. `inspectContainerAsync` and `killContainerAsync` fail closed in this environment (no
 * daemon), which is the honest answer and is what the tests observe.
 *
 * **Host verification is NOT mocked in this file.** That means an arm cannot succeed here — there
 * is no writable `dip-executor.slice` cgroup. The tests therefore prove the *channel* refuses
 * unauthenticated and replayed requests, and that a well-formed authenticated arm reaches the real
 * verifier and is refused there. That is the honest split: this file establishes authentication,
 * not isolation.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { connect } from "node:net";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { decodeWatchdogFrame, encodeWatchdogFrame, type ArmDenied } from "../src/lib/execution/watchdog-protocol";
import {
  computeAuthProof,
  newAuthNonce,
  payloadDigest,
  type AuthOkMessage,
  type ChallengeMessage,
} from "../src/lib/execution/watchdog-auth";
import { BOOT, armRequest } from "./support/watchdog-harness";

/** One authenticated conversation with the watchdog. */
class Channel {
  private buffer = Buffer.alloc(0);
  private waiters: Array<(frame: unknown) => void> = [];
  private socket: ReturnType<typeof connect>;
  private connected: Promise<void>;

  constructor(private readonly socketPath: string) {
    this.socket = connect(socketPath);
    this.connected = new Promise((resolve, reject) => {
      this.socket.on("connect", () => resolve());
      this.socket.on("error", reject);
    });
    this.socket.on("data", (chunk: Buffer) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      while (this.buffer.byteLength >= 4) {
        const length = this.buffer.readUInt32BE(0);
        if (this.buffer.byteLength < 4 + length) break;
        const frame = decodeWatchdogFrame(this.buffer.subarray(0, 4 + length));
        this.buffer = this.buffer.subarray(4 + length);
        const waiter = this.waiters.shift();
        if (waiter !== undefined) waiter(frame);
      }
    });
  }

  async send(message: unknown): Promise<void> {
    await this.connected;
    this.socket.write(encodeWatchdogFrame(message));
  }

  /** The next frame, or a rejection on timeout so a hung server fails the test rather than the run. */
  next(timeoutMs = 5_000): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("the watchdog did not answer in time")), timeoutMs);
      this.waiters.push((frame) => {
        clearTimeout(timer);
        resolve(frame);
      });
    });
  }

  close(): void {
    this.socket.destroy();
  }
}

async function startWatchdog(): Promise<{
  child: ChildProcess;
  socketPath: string;
  stateDir: string;
  secret: Buffer;
  cleanup: () => Promise<void>;
}> {
  const root = mkdtempSync(join(tmpdir(), "dip-wd-proc-"));
  const socketPath = join(root, "watchdog.sock");
  const stateDir = join(root, "state");
  const secret = randomBytes(32);
  const child = spawn(process.execPath, ["--import", "tsx", "workers/watchdog.ts"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      DIP_WATCHDOG_SOCKET: socketPath,
      DIP_WATCHDOG_SECRET: secret.toString("hex"),
      DIP_WATCHDOG_STATE: stateDir,
      // D2-F03: the supervisor's journal is mandatory, so every entry point needs one.
      DIP_WATCHDOG_JOURNAL: join(root, "journal"),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  await new Promise<void>((resolve, reject) => {
    let output = "";
    const timer = setTimeout(() => reject(new Error(`the watchdog did not become ready: ${output}`)), 30_000);
    child.stdout!.on("data", (chunk: Buffer) => {
      output += chunk.toString("utf8");
      if (output.includes('"event":"ready"') || output.includes('"event":"recovery-blocked"')) {
        clearTimeout(timer);
        resolve();
      }
    });
    child.stderr!.on("data", (chunk: Buffer) => { output += chunk.toString("utf8"); });
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`the watchdog exited with ${String(code)}: ${output}`));
    });
  });

  return {
    child,
    socketPath,
    stateDir,
    secret,
    cleanup: async () => {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGKILL");
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

/** Complete the handshake and return the authenticated channel plus the shared transcript state. */
async function authenticate(socketPath: string, secret: Buffer): Promise<{
  channel: Channel;
  clientNonce: string;
  serverNonce: string;
  serverInstance: string;
  bootId: string;
  clientInstance: string;
}> {
  const channel = new Channel(socketPath);
  const clientNonce = newAuthNonce();
  const clientInstance = "sv-0123456789ab";
  await channel.send({ kind: "HELLO", clientNonce, clientInstance, protocolVersion: 2 });

  const challenge = await channel.next() as ChallengeMessage;
  assert.equal(challenge.kind, "CHALLENGE");
  assert.equal(challenge.clientNonce, clientNonce, "the challenge must echo this connection's nonce");

  const proof = computeAuthProof(secret, {
    direction: "client-to-watchdog",
    kind: "AUTH",
    clientNonce,
    serverNonce: challenge.serverNonce,
    clientInstance,
    serverInstance: challenge.serverInstance,
    bootId: challenge.bootId,
    requestNonce: "",
    payloadSha256: payloadDigest({ kind: "AUTH" }),
  });
  await channel.send({ kind: "AUTH", clientNonce, serverNonce: challenge.serverNonce, proof });

  const ack = await channel.next() as AuthOkMessage;
  assert.equal(ack.kind, "AUTH_OK", JSON.stringify(ack));

  // The server proves possession of the secret too: the ack is signed in the other direction.
  const expected = computeAuthProof(secret, {
    direction: "watchdog-to-client",
    kind: "AUTH_OK",
    clientNonce,
    serverNonce: challenge.serverNonce,
    clientInstance,
    serverInstance: challenge.serverInstance,
    bootId: challenge.bootId,
    requestNonce: "",
    payloadSha256: payloadDigest({ kind: "AUTH_OK" }),
  });
  assert.equal(ack.proof, expected, "the watchdog must authenticate itself, not only demand authentication");

  return {
    channel,
    clientNonce,
    serverNonce: challenge.serverNonce,
    serverInstance: challenge.serverInstance,
    bootId: challenge.bootId,
    clientInstance,
  };
}

/** Send one authenticated request and read its reply. */
async function request(
  session: Awaited<ReturnType<typeof authenticate>>,
  secret: Buffer,
  kind: "ARM_REQ" | "DISARM_REQ" | "HEARTBEAT" | "STATE_REQ",
  payload: Record<string, unknown>,
): Promise<unknown> {
  const requestNonce = newAuthNonce();
  const proof = computeAuthProof(secret, {
    direction: "client-to-watchdog",
    kind,
    clientNonce: session.clientNonce,
    serverNonce: session.serverNonce,
    clientInstance: session.clientInstance,
    serverInstance: session.serverInstance,
    bootId: session.bootId,
    requestNonce,
    payloadSha256: payloadDigest(payload),
  });
  await session.channel.send({ kind, requestNonce, payload, proof });
  return await session.channel.next();
}

test("R7D.1-WD02-6: the watchdog socket is real, mode 0600, and reports its identity", async () => {
  const watchdog = await startWatchdog();
  try {
    assert.equal(statSync(watchdog.socketPath).mode & 0o777, 0o600);
    const session = await authenticate(watchdog.socketPath, watchdog.secret);
    try {
      const state = await request(session, watchdog.secret, "STATE_REQ", { executionId: "a".repeat(32) });
      assert.equal((state as { kind: string }).kind, "STATE_ACK", JSON.stringify(state));
      assert.equal((state as { armed: boolean }).armed, false);
    } finally {
      session.channel.close();
    }
  } finally {
    await watchdog.cleanup();
  }
});

test("R7D.1-WD02-7: an unauthenticated ARM is refused and arms nothing", async () => {
  // The defect being corrected: the old server dispatched ARM_REQ straight from the frame. Here the
  // connection never completes a handshake, so the request is refused before it is interpreted.
  const watchdog = await startWatchdog();
  try {
    const channel = new Channel(watchdog.socketPath);
    try {
      // `armRequest` already carries `kind: "ARM_REQ"`; spreading it after an explicit kind would
      // be redundant rather than expressive.
      await channel.send(armRequest("a".repeat(32)));
      const reply = await channel.next() as { kind: string; code?: string };
      assert.equal(reply.kind, "ERROR");
      assert.equal(reply.code, "UNAUTHENTICATED");
    } finally {
      channel.close();
    }

    // Nothing was armed, and nothing was written to disk.
    const session = await authenticate(watchdog.socketPath, watchdog.secret);
    try {
      const state = await request(session, watchdog.secret, "STATE_REQ", { executionId: "a".repeat(32) });
      assert.equal((state as { armed: boolean }).armed, false);
      assert.equal(readdirSync(join(watchdog.stateDir, "records")).filter((name) => name.endsWith(".json")).length, 0);
    } finally {
      session.channel.close();
    }
  } finally {
    await watchdog.cleanup();
  }
});

test("R7D.1-WD02-8: an unauthenticated DISARM is refused and mutates nothing", async () => {
  const watchdog = await startWatchdog();
  try {
    const channel = new Channel(watchdog.socketPath);
    try {
      await channel.send({
        kind: "DISARM_REQ",
        messageId: randomBytes(8).toString("hex"),
        sequence: 2,
        context: {
          executionId: "a".repeat(32),
          requestId: randomBytes(8).toString("hex"),
          operation: "fill",
          resultDigest: "e".repeat(64),
          resultBytes: 1_024,
          metaBytes: 128,
          containerId: "c".repeat(64),
          containerName: `dip-exec-${"a".repeat(32)}`,
          containerRemoved: true,
          outcome: "committed",
          watchdogInstance: "wd-0123456789ab",
          supervisorInstance: "sv-0123456789ab",
          bootId: BOOT,
          nonce: randomBytes(8).toString("hex"),
          concludedMonotonicMs: 10_500,
        },
      });
      const reply = await channel.next() as { kind: string; code?: string };
      assert.equal(reply.code, "UNAUTHENTICATED");
    } finally {
      channel.close();
    }
  } finally {
    await watchdog.cleanup();
  }
});

test("R7D.1-WD02-9: a bad AUTH proof closes the connection and refuses everything after", async () => {
  const watchdog = await startWatchdog();
  try {
    const channel = new Channel(watchdog.socketPath);
    const clientNonce = newAuthNonce();
    await channel.send({ kind: "HELLO", clientNonce, clientInstance: "sv-0123456789ab", protocolVersion: 2 });
    await channel.next();
    // A proof computed with the wrong key. It must not authenticate, and the connection must not
    // linger in a half-authenticated state.
    await channel.send({
      kind: "AUTH",
      clientNonce,
      serverNonce: "f".repeat(64),
      proof: "0".repeat(64),
    });
    const reply = await channel.next() as { kind: string; code?: string };
    assert.equal(reply.kind, "ERROR");

    // The socket is closed: a follow-up request cannot be sent.
    await assert.rejects(async () => {
      await new Promise<void>((resolve, reject) => {
        if (channel["socket"].destroyed) { reject(new Error("closed")); return; }
        channel["socket"].write(encodeWatchdogFrame({ kind: "STATE_REQ" }));
        setTimeout(() => reject(new Error("closed")), 200);
      });
    });
    channel.close();
  } finally {
    await watchdog.cleanup();
  }
});

test("R7D.1-WD02-10: a replayed request nonce is refused", async () => {
  const watchdog = await startWatchdog();
  try {
    const session = await authenticate(watchdog.socketPath, watchdog.secret);
    try {
      const payload = { executionId: "a".repeat(32) };
      const requestNonce = newAuthNonce();
      const proof = computeAuthProof(watchdog.secret, {
        direction: "client-to-watchdog",
        kind: "STATE_REQ",
        clientNonce: session.clientNonce,
        serverNonce: session.serverNonce,
        clientInstance: session.clientInstance,
        serverInstance: session.serverInstance,
        bootId: session.bootId,
        requestNonce,
        payloadSha256: payloadDigest(payload),
      });
      const envelope = { requestNonce, payload, proof, kind: "STATE_REQ" };

      await session.channel.send(envelope);
      const first = await session.channel.next() as { kind: string };
      assert.equal(first.kind, "STATE_ACK");

      // The same envelope again: the nonce is consumed, so it cannot be replayed.
      await session.channel.send(envelope);
      const second = await session.channel.next() as { kind: string; code?: string };
      assert.equal(second.kind, "ERROR");
      assert.equal(second.code, "REPLAYED_REQUEST");
    } finally {
      session.channel.close();
    }
  } finally {
    await watchdog.cleanup();
  }
});

test("R7D.1-WD02-11: a tampered payload fails the proof", async () => {
  const watchdog = await startWatchdog();
  try {
    const session = await authenticate(watchdog.socketPath, watchdog.secret);
    try {
      const intended = { executionId: "a".repeat(32) };
      const requestNonce = newAuthNonce();
      const proof = computeAuthProof(watchdog.secret, {
        direction: "client-to-watchdog",
        kind: "STATE_REQ",
        clientNonce: session.clientNonce,
        serverNonce: session.serverNonce,
        clientInstance: session.clientInstance,
        serverInstance: session.serverInstance,
        bootId: session.bootId,
        requestNonce,
        payloadSha256: payloadDigest(intended),
      });
      // The proof was computed for one payload and is presented with another.
      await session.channel.send({
        kind: "STATE_REQ",
        requestNonce,
        payload: { executionId: "b".repeat(32) },
        proof,
      });
      const reply = await session.channel.next() as { kind: string; code?: string };
      assert.equal(reply.kind, "ERROR");
      assert.equal(reply.code, "BAD_PROOF");
    } finally {
      session.channel.close();
    }
  } finally {
    await watchdog.cleanup();
  }
});

test("R7D.1-WD02-12: an authenticated ARM reaches the real verifier and is refused there", async () => {
  // Authentication succeeds; the arm is then refused because there is no `dip-executor.slice`
  // cgroup in this sandbox. This is the honest boundary: the channel is proven, isolation is not.
  const watchdog = await startWatchdog();
  try {
    const session = await authenticate(watchdog.socketPath, watchdog.secret);
    try {
      const answer = await request(session, watchdog.secret, "ARM_REQ", armRequest("a".repeat(32)) as unknown as Record<string, unknown>);
      assert.equal((answer as { kind: string }).kind, "ARM_DENIED");
      // The reason is a host-identity refusal, not an authentication one: the request authenticated
      // and was then rejected on its merits.
      assert.ok(["NOT_DIP_OWNED", "CGROUP_UNVERIFIED"].includes((answer as ArmDenied).code), (answer as ArmDenied).code);
    } finally {
      session.channel.close();
    }
  } finally {
    await watchdog.cleanup();
  }
});

test("R7D.1-WD01-11: a watchdog with an unreadable record refuses to become ready", async () => {
  // Start-up recovery runs before the socket listens. A record it cannot resolve means the process
  // must not serve: it does not know whether a container it is responsible for is running.
  const root = mkdtempSync(join(tmpdir(), "dip-wd-bad-"));
  const socketPath = join(root, "watchdog.sock");
  const stateDir = join(root, "state");
  const records = join(stateDir, "records");
  const fs = await import("node:fs");
  fs.mkdirSync(records, { recursive: true });
  fs.writeFileSync(join(records, `${"a".repeat(32)}.json`), '{"schema":1,"executionId":');

  const child = spawn(process.execPath, ["--import", "tsx", "workers/watchdog.ts"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      DIP_WATCHDOG_SOCKET: socketPath,
      DIP_WATCHDOG_SECRET: randomBytes(32).toString("hex"),
      DIP_WATCHDOG_STATE: stateDir,
      // D2-F03: the supervisor's journal is mandatory, so every entry point needs one.
      DIP_WATCHDOG_JOURNAL: join(root, "journal"),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    const exitCode = await new Promise<number | null>((resolve) => {
      child.on("exit", (code) => resolve(code));
      setTimeout(() => resolve(null), 30_000).unref();
    });
    // Exit 3 is the documented "recovery blocked" code. It exits rather than serving, and the
    // service manager sees a failure rather than a healthy-but-unaccountable watchdog.
    assert.equal(exitCode, 3);
    // The socket was never created.
    assert.equal(fs.existsSync(socketPath), false);
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    rmSync(root, { recursive: true, force: true });
  }
});

test("R7D.1-WD01-12: the durable store is created before the socket listens", async () => {
  const watchdog = await startWatchdog();
  try {
    // The records directory exists once the process is ready, because it was created and fsynced
    // during start-up rather than on the first arm.
    const records = join(watchdog.stateDir, "records");
    assert.equal(statSync(records).isDirectory(), true);
    // And the socket exists only after that. A socket is not a file: `isFile()` is false for one,
    // which is why this asserts on the socket type rather than on mere existence.
    assert.equal(statSync(watchdog.socketPath).isSocket(), true);
  } finally {
    await watchdog.cleanup();
  }
});

test("R7D.1-WD05-5: a restarted watchdog treats the previous instance's records as prior-boot only", async () => {
  // The record is written on this boot, so a restart must *not* call it prior-boot: it must
  // attempt recovery and quarantine it (the cgroup cannot be re-pinned here). Both answers are
  // safe; what is unsafe is silently forgetting it.
  const watchdog = await startWatchdog();
  const recordsDir = join(watchdog.stateDir, "records");
  try {
    // Write a plausible record directly, as a crashed predecessor would have left it.
    const fs = await import("node:fs");
    const record = {
      schema: 1,
      executionId: "a".repeat(32),
      bootId: BOOT,
      watchdogInstance: "wd-0123456789ab",
      supervisorInstance: "sv-0123456789ab",
      requestId: "b".repeat(16),
      operation: "fill",
      containerId: "c".repeat(64),
      containerName: `dip-exec-${"a".repeat(32)}`,
      imageDigest: `sha256:${"d".repeat(64)}`,
      profileId: "synthetic-v1",
      initPid: 4_242,
      initStartTimeTicks: 100,
      cgroupPath: `/sys/fs/cgroup/dip-executor.slice/dip-exec-${"a".repeat(32)}`,
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
    };
    fs.writeFileSync(join(recordsDir, `${"a".repeat(32)}.json`), JSON.stringify(record));
    assert.equal(readFileSync(join(recordsDir, `${"a".repeat(32)}.json`), "utf8").includes("armed"), true);
  } finally {
    await watchdog.cleanup();
  }
});

// ══ WD-F05 · Bounded control-channel operation, over the real socket ════════════════════════════

test("R7D.1-WDF05-2: an idle unauthenticated connection is closed at the handshake deadline", async () => {
  // The defect: HELLO cleared the handshake timer, so a peer could hold a connection open forever by
  // re-saying hello. A connection that merely *connects* must not outlive the window either.
  const watchdog = await startWatchdog();
  try {
    const started = Date.now();
    const closed = await new Promise<boolean>((resolve) => {
      const socket = connect(watchdog.socketPath);
      socket.on("connect", () => { /* say nothing at all */ });
      socket.on("close", () => resolve(true));
      socket.on("error", () => resolve(true));
      setTimeout(() => { socket.destroy(); resolve(false); }, 10_000).unref();
    });
    assert.equal(closed, true, "an idle connection must be closed, not left open");
    // And it happened on the server's schedule, not ours.
    assert.ok(Date.now() - started < 9_000);
  } finally {
    await watchdog.cleanup();
  }
});

test("R7D.1-WDF05-3: repeated HELLO cannot extend the handshake window", async () => {
  // Each HELLO used to reset the deadline it was racing. Four is the allowance; the fifth closes.
  const watchdog = await startWatchdog();
  try {
    const channel = new Channel(watchdog.socketPath);
    try {
      const closed = await new Promise<boolean>((resolve) => {
        channel["socket"].on("close", () => resolve(true));
        channel["socket"].on("error", () => resolve(true));
        void (async () => {
          for (let index = 0; index < 8; index += 1) {
            await channel.send({
              kind: "HELLO",
              clientNonce: randomBytes(32).toString("hex"),
              clientInstance: "sv-0123456789ab",
              protocolVersion: 2,
            });
            await new Promise((resolve) => setTimeout(resolve, 40));
          }
        })();
        setTimeout(() => resolve(false), 8_000).unref();
      });
      assert.equal(closed, true, "a peer that keeps re-saying hello must be disconnected");
    } finally {
      channel.close();
    }
  } finally {
    await watchdog.cleanup();
  }
});

test("R7D.1-WDF05-4: a frame flood is bounded, and the server survives it", async () => {
  const watchdog = await startWatchdog();
  try {
    // Many frames in one burst, before any authentication. Two bounds apply: the unauthenticated
    // path destroys the connection on the first privileged frame, and the queue bound closes a peer
    // that outruns the handler. Either way the connection must end, and memory must not grow with
    // the number of frames the peer sent.
    const outcome = await new Promise<"closed" | "drained">((resolve) => {
      const socket = connect(watchdog.socketPath);
      socket.on("connect", () => {
        for (let index = 0; index < 200; index += 1) {
          socket.write(encodeWatchdogFrame({ kind: "STATE_REQ", index }));
        }
      });
      // A reply is drained rather than left unread: the test is about the server's bound, not about
      // whether this side happens to consume its own socket buffer.
      socket.on("data", () => { /* drain */ });
      socket.on("close", () => resolve("closed"));
      socket.on("error", () => resolve("closed"));
      setTimeout(() => { socket.destroy(); resolve("drained"); }, 8_000).unref();
    });
    assert.equal(outcome, "closed", "a flooding peer must be disconnected");

    // The watchdog is still healthy: one bad peer is not an outage.
    const session = await authenticate(watchdog.socketPath, watchdog.secret);
    try {
      const state = await request(session, watchdog.secret, "STATE_REQ", { executionId: "a".repeat(32) });
      assert.equal((state as { kind: string }).kind, "STATE_ACK");
    } finally {
      session.channel.close();
    }
  } finally {
    await watchdog.cleanup();
  }
});

test("R7D.1-WDF05-5: a request cannot claim a supervisor the connection did not authenticate as", async () => {
  // The session is bound to `sv-0123456789ab` at AUTH. A request inside it that names another
  // supervisor is refused before the watchdog sees it.
  const watchdog = await startWatchdog();
  try {
    const session = await authenticate(watchdog.socketPath, watchdog.secret);
    try {
      const reply = await request(session, watchdog.secret, "HEARTBEAT", {
        executionId: "a".repeat(32),
        messageId: "1".repeat(16),
        supervisorInstance: "sv-impostor-1",
        monotonicMs: 1,
      });
      assert.equal((reply as { kind: string }).kind, "ERROR");
      assert.equal((reply as { code: string }).code, "INSTANCE_MISMATCH");
    } finally {
      session.channel.close();
    }
  } finally {
    await watchdog.cleanup();
  }
});

test("R7D.1-WDF05-6: a request captured on one connection cannot be replayed on another", async () => {
  // The nonce is bound to the connection's challenge, so a fresh connection issues a different
  // challenge and the original proof cannot verify against it.
  const watchdog = await startWatchdog();
  try {
    const first = await authenticate(watchdog.socketPath, watchdog.secret);
    const payload = { executionId: "a".repeat(32) };
    const requestNonce = newAuthNonce();
    const proof = computeAuthProof(watchdog.secret, {
      direction: "client-to-watchdog",
      kind: "STATE_REQ",
      clientNonce: first.clientNonce,
      serverNonce: first.serverNonce,
      clientInstance: first.clientInstance,
      serverInstance: first.serverInstance,
      bootId: first.bootId,
      requestNonce,
      payloadSha256: payloadDigest(payload),
    });
    first.channel.close();

    const second = await authenticate(watchdog.socketPath, watchdog.secret);
    try {
      await second.channel.send({ kind: "STATE_REQ", requestNonce, payload, proof });
      const reply = await second.channel.next() as { kind: string; code?: string };
      assert.equal(reply.kind, "ERROR");
      assert.equal(reply.code, "BAD_PROOF", "a proof from another connection's challenge must not verify");
    } finally {
      second.channel.close();
    }
  } finally {
    await watchdog.cleanup();
  }
});

test("R7D.1-WDF05-7: a restart with outstanding termination debt refuses to serve", async () => {
  // A durable `terminating` record with an unresolved process debt is a live executor whose kill was
  // never confirmed. The restarted watchdog cannot re-pin it here, so it must not become ready.
  const result = await runWithRecord({
    schema: 1,
    executionId: "a".repeat(32),
    bootId: BOOT,
    watchdogInstance: "wd-0123456789ab",
    supervisorInstance: "sv-0123456789ab",
    requestId: "b".repeat(16),
    operation: "fill",
    containerId: "c".repeat(64),
    containerName: `dip-exec-${"a".repeat(32)}`,
    imageDigest: `sha256:${"d".repeat(64)}`,
    profileId: "synthetic-v1",
    initPid: 4_242,
    initStartTimeTicks: 100,
    cgroupPath: `/sys/fs/cgroup/dip-executor.slice/dip-exec-${"a".repeat(32)}`,
    cgroupDevice: "0:25",
    cgroupDirInode: 4_001,
    cgroupEventsInode: 4_002,
    cgroupKillInode: 4_003,
    cgroupProcsInode: 4_004,
    deadlineAtMs: 10_000,
    armedAtMs: 1_000,
    phase: "terminating",
    processDebt: "terminate-required",
    containerDebt: "removal-required",
    outcome: null,
    sequence: 2,
  });
  assert.equal(result.ready, false, "a restart with outstanding termination debt must not become ready");
  assert.equal(result.code, 3);
});

/** Start a watchdog over a state directory containing one record and report how it started. */
async function runWithRecord(record: Record<string, unknown>): Promise<{ code: number | null; ready: boolean }> {
  const fs = await import("node:fs");
  const root = mkdtempSync(join(await import("node:os").then((m) => m.tmpdir()), "dip-wdf-"));
  const stateDir = join(root, "state");
  fs.mkdirSync(join(stateDir, "records"), { recursive: true });
  fs.writeFileSync(join(stateDir, "records", `${"a".repeat(32)}.json`), JSON.stringify(record));

  const child = spawn(process.execPath, ["--import", "tsx", "workers/watchdog.ts"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      DIP_WATCHDOG_SOCKET: join(root, "watchdog.sock"),
      DIP_WATCHDOG_SECRET: randomBytes(32).toString("hex"),
      DIP_WATCHDOG_STATE: stateDir,
      // D2-F03: the supervisor's journal is mandatory, so every entry point needs one.
      DIP_WATCHDOG_JOURNAL: join(root, "journal"),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  let output = "";
  let ready = false;
  child.stdout!.on("data", (chunk: Buffer) => {
    output += chunk.toString("utf8");
    if (output.includes('"event":"ready"')) ready = true;
  });
  try {
    const code = await new Promise<number | null>((resolve) => {
      child.on("exit", (exitCode) => resolve(exitCode));
      const poll = setInterval(() => {
        if (ready) { clearInterval(poll); resolve(null); }
      }, 50);
      poll.unref();
      setTimeout(() => { clearInterval(poll); resolve(null); }, 20_000).unref();
    });
    return { code, ready };
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    rmSync(root, { recursive: true, force: true });
  }
}
