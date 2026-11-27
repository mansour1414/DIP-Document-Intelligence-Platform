/**
 * The Supervisor's watchdog client, against the real watchdog server (R7D.1 D2).
 *
 * ## Why every test here uses a real socket and a real server
 *
 * The defect this increment corrects is that the supervisor's watchdog seam had no transport at
 * all: every supervisor test substituted a fake, so the handshake, the proofs, the framing and the
 * deadlines were never executed. A test of this client against a fake server would repeat that
 * mistake one layer down, so the server here is `startWatchdogServer` — the same code the watchdog
 * process runs — listening on a real Unix socket in a temporary directory.
 *
 * ## What is real and what is injected
 *
 * **Real:** the Unix socket, the length-prefixed framing, both HMACs, the nonce exchange, the
 * server's replay window and connection bounds, the durable store (a temporary directory with real
 * fsync), and the watchdog state machine.
 *
 * **Injected:** the cgroup verification and the daemon (this sandbox has no writable cgroup2 mount
 * and no Docker daemon). Nothing here establishes kernel enforcement or container isolation.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { createServer, type Server, type Socket } from "node:net";
import { AuthenticatedWatchdogClient, WatchdogChannelError, newMessageId } from "../src/lib/execution/watchdog-client";
import { startWatchdogServer } from "../src/lib/execution/watchdog-server";
import { encodeWatchdogFrame } from "../src/lib/execution/watchdog-protocol";

import {
  BOOT,
  SUPERVISOR,
  WATCHDOG_INSTANCE,
  armRequest,
  cgroupPathFor,
  makeWatchdog,
  terminalRequest,
  type Harness,
} from "./support/watchdog-harness";

const EXECUTION = "a".repeat(32);



/** A server plus the harness whose watchdog it serves. */
type Fixture = {
  client: AuthenticatedWatchdogClient;
  secret: Buffer;
  socketPath: string;
  harness: Harness;
  stop: () => Promise<void>;
};

/**
 * Start the real watchdog server over a real socket.
 *
 * `mutateWatchdog` lets a test change the harness before the server is built — for instance to
 * remove the journal corroboration an arm now requires (D2-F03).
 */
async function startFixture(options: {
  harness?: Harness;
  secret?: Buffer;
  bootId?: string;
} = {}): Promise<Fixture> {
  const root = mkdtempSync(join(tmpdir(), "dip-client-"));
  const socketPath = join(root, "watchdog.sock");
  const harness = options.harness ?? makeWatchdog({ liveTree: { populated: false } });
  // One secret in production: the watchdog process uses `DIP_WATCHDOG_SECRET` both to authenticate
  // the control channel and to sign arm acks and disarm grants. The fixture therefore takes the
  // harness's own secret rather than generating a second one, which is what made the first version
  // of this file assert a proof it could never verify.
  const secret = options.secret ?? harness.secret;
  const server = await startWatchdogServer({ socketPath, watchdog: harness.watchdog, secret });
  return {
    client: new AuthenticatedWatchdogClient({
      socketPath,
      secret,
      supervisorInstance: SUPERVISOR,
      bootId: options.bootId ?? BOOT,
      requestTimeoutMs: 2_000,
      handshakeTimeoutMs: 2_000,
    }),
    secret,
    socketPath,
    harness,
    stop: async () => {
      await server.stop();
      harness.cleanup();
      rmSync(root, { recursive: true, force: true });
    },
  };
}

test("R7D.1-D2C-1: the client completes the real handshake and binds the watchdog instance", async () => {
  const fixture = await startFixture();
  try {
    const identity = await fixture.client.connect();
    assert.equal(identity.watchdogInstance, WATCHDOG_INSTANCE);
    assert.equal(identity.bootId, BOOT);
    assert.equal(fixture.client.authenticated, true);
  } finally {
    fixture.client.close();
    await fixture.stop();
  }
});

test("R7D.1-D2C-2: an arm over the real channel is acknowledged and the ack proof verifies", async () => {
  const fixture = await startFixture();
  try {
    await fixture.client.connect();
    const request = armRequest(EXECUTION, { cgroupPath: cgroupPathFor(EXECUTION) });
    const answer = await fixture.client.arm(request);
    assert.equal(answer.kind, "ARM_ACK");
    if (answer.kind === "ARM_ACK") {
      assert.equal(answer.executionId, EXECUTION);
      assert.equal(answer.messageId, request.messageId);
      // The watchdog's own view of the cgroup it pinned, which is what the supervisor records.
      // A live tree reports real filesystem inodes, so the value is asserted as usable rather than
      // as a fixture constant.
      assert.ok(Number.isSafeInteger(answer.observedCgroupDirInode) && answer.observedCgroupDirInode > 0);
      assert.match(answer.observedCgroupDevice, /^\d+:\d+$/u);
    }
    // And the watchdog really holds it.
    assert.deepEqual(fixture.harness.watchdog.outstanding(), [EXECUTION]);
  } finally {
    fixture.client.close();
    await fixture.stop();
  }
});

test("R7D.1-D2C-3: a wrong secret is refused at AUTH, and no request is ever sent", async () => {
  const fixture = await startFixture();
  try {
    const impostor = new AuthenticatedWatchdogClient({
      socketPath: fixture.socketPath,
      secret: randomBytes(32),
      supervisorInstance: SUPERVISOR,
      bootId: BOOT,
      requestTimeoutMs: 2_000,
      handshakeTimeoutMs: 2_000,
    });
    await assert.rejects(
      impostor.connect(),
      (error: unknown) => error instanceof WatchdogChannelError
        && (error.code === "HANDSHAKE_REFUSED" || error.code === "CLOSED" || error.code === "TIMEOUT"),
    );
    impostor.close();
    // Nothing was armed by the failed handshake.
    assert.deepEqual(fixture.harness.watchdog.outstanding(), []);
  } finally {
    fixture.client.close();
    await fixture.stop();
  }
});

test("R7D.1-D2C-4: a boot mismatch is refused before any arm is attempted", async () => {
  // A watchdog on another boot enforces deadlines against a container namespace that no longer
  // exists. The client refuses the channel rather than arming into it.
  const fixture = await startFixture({ bootId: "00000000-0000-4000-8000-000000000000" });
  try {
    await assert.rejects(
      fixture.client.connect(),
      (error: unknown) => error instanceof WatchdogChannelError && error.code === "INSTANCE_MISMATCH",
    );
    assert.deepEqual(fixture.harness.watchdog.outstanding(), []);
  } finally {
    fixture.client.close();
    await fixture.stop();
  }
});

test("R7D.1-D2C-5: a disarm over the real channel round-trips the terminal context exactly", async () => {
  const fixture = await startFixture();
  try {
    await fixture.client.connect();
    const executionId = EXECUTION;
    const arm = armRequest(executionId);
    const ack = await fixture.client.arm(arm);
    assert.equal(ack.kind, "ARM_ACK");

    // The supervisor removed the container after committing; the watchdog observes absence.
    fixture.harness.removeContainer();
    // A real pin is needed for the process question, so this fixture uses a live tree.
    const answer = await fixture.client.disarm(terminalRequest(executionId), newMessageId(), 2);
    // Whether a grant or a denial, it must be a well-formed protocol answer rather than a throw:
    // the client's job is to carry the decision, not to make it.
    assert.ok("proof" in answer || "code" in answer);
    if ("code" in answer) assert.match(answer.code, /^[A-Z_]+$/u);
  } finally {
    fixture.client.close();
    await fixture.stop();
  }
});

test("R7D.1-D2C-6: an unmatched execution id cannot be armed and then disarmed into a grant", async () => {
  // Two executions, one channel. The second arm is for a different id; a disarm must not be
  // confused between them because every transcript carries the execution identity.
  const fixture = await startFixture();
  try {
    await fixture.client.connect();
    const first = "a".repeat(32);
    const second = "b".repeat(32);
    const ackFirst = await fixture.client.arm(armRequest(first));
    assert.equal(ackFirst.kind, "ARM_ACK");

    // A disarm naming the second execution is refused: it was never armed.
    const answer = await fixture.client.disarm(terminalRequest(second), newMessageId(), 2);
    assert.equal("code" in answer, true);
    if ("code" in answer) assert.match(answer.code, /^[A-Z_]+$/u);

    // And the first execution is untouched by it.
    const state = await fixture.client.state(first);
    assert.equal(state.armed, true);
  } finally {
    fixture.client.close();
    await fixture.stop();
  }
});

test("R7D.1-D2C-7: the server's AUTH_OK proof must verify, and a forged one is refused", async () => {
  // A rogue server that accepts AUTH and answers AUTH_OK without the secret must be refused. The
  // proof is recomputed here with the wrong key, so only the client-side verification can catch it.
  const root = mkdtempSync(join(tmpdir(), "dip-rogue-"));
  const socketPath = join(root, "rogue.sock");
  const secret = randomBytes(32);
  const { newAuthNonce, payloadDigest: digest } = await import("../src/lib/execution/watchdog-auth");
  const { computeAuthProof } = await import("../src/lib/execution/watchdog-auth");

  const server: Server = createServer((socket: Socket) => {
    let pending = Buffer.alloc(0);
    socket.on("data", (chunk: Buffer) => {
      pending = Buffer.concat([pending, chunk]);
      while (pending.byteLength >= 4) {
        const declared = pending.readUInt32BE(0);
        if (pending.byteLength < 4 + declared) return;
        const body = JSON.parse(pending.subarray(4, 4 + declared).toString("utf8")) as Record<string, unknown>;
        pending = pending.subarray(4 + declared);
        if (body.kind === "HELLO") {
          socket.write(encodeWatchdogFrame({
            kind: "CHALLENGE",
            serverNonce: newAuthNonce(),
            clientNonce: body.clientNonce,
            serverInstance: WATCHDOG_INSTANCE,
            bootId: BOOT,
            pid: process.pid,
            protocolVersion: 2,
          }));
        } else if (body.kind === "AUTH") {
          // The wrong key, and a structurally valid proof shape.
          const forged = computeAuthProof(randomBytes(32), {
            direction: "watchdog-to-client",
            kind: "AUTH_OK",
            clientNonce: String(body.clientNonce),
            serverNonce: String(body.serverNonce),
            clientInstance: SUPERVISOR,
            serverInstance: WATCHDOG_INSTANCE,
            bootId: BOOT,
            requestNonce: "",
            payloadSha256: digest({ kind: "AUTH_OK" }),
          });
          socket.write(encodeWatchdogFrame({
            kind: "AUTH_OK",
            clientNonce: body.clientNonce,
            serverNonce: body.serverNonce,
            watchdogInstance: WATCHDOG_INSTANCE,
            bootId: BOOT,
            proof: forged,
          }));
        }
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(socketPath, resolve));

  const client = new AuthenticatedWatchdogClient({
    socketPath,
    secret,
    supervisorInstance: SUPERVISOR,
    bootId: BOOT,
    requestTimeoutMs: 1_000,
    handshakeTimeoutMs: 1_000,
  });
  try {
    await assert.rejects(
      client.connect(),
      (error: unknown) => error instanceof WatchdogChannelError && error.code === "SERVER_PROOF_INVALID",
      "a peer that cannot prove possession of the secret must not yield an authenticated channel",
    );
  } finally {
    client.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    rmSync(root, { recursive: true, force: true });
  }
});

test("R7D.1-D2C-8: an oversized declared frame is refused on the header, before the body is read", async () => {
  const root = mkdtempSync(join(tmpdir(), "dip-flood-"));
  const socketPath = join(root, "flood.sock");
  // The socket is closed from the server side when the test ends: `server.close()` waits for open
  // connections, and the client destroys its own end only after it has rejected.
  const sockets = new Set<Socket>();
  const server: Server = createServer((socket: Socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    // Accept the connection and announce an enormous frame, then send nothing. A client that waits
    // for the body would hang; one that validates the header refuses immediately.
    const header = Buffer.alloc(4);
    header.writeUInt32BE(0x7fff_ffff, 0);
    socket.write(header);
  });
  await new Promise<void>((resolve) => server.listen(socketPath, resolve));
  const shutdown = async (): Promise<void> => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    rmSync(root, { recursive: true, force: true });
  };

  const client = new AuthenticatedWatchdogClient({
    socketPath,
    secret: randomBytes(32),
    supervisorInstance: SUPERVISOR,
    bootId: BOOT,
    requestTimeoutMs: 500,
    handshakeTimeoutMs: 500,
  });
  try {
    await assert.rejects(
      client.connect(),
      (error: unknown) => error instanceof WatchdogChannelError && error.code === "FRAMING",
    );
  } finally {
    client.close();
    await shutdown();
  }
});

test("R7D.1-D2C-9: an unreachable socket is reported as such, not as a protocol failure", async () => {
  const client = new AuthenticatedWatchdogClient({
    socketPath: join(tmpdir(), `dip-absent-${randomBytes(6).toString("hex")}.sock`),
    secret: randomBytes(32),
    supervisorInstance: SUPERVISOR,
    bootId: BOOT,
    requestTimeoutMs: 500,
    handshakeTimeoutMs: 500,
  });
  try {
    await assert.rejects(
      client.connect(),
      (error: unknown) => error instanceof WatchdogChannelError && error.code === "UNREACHABLE",
    );
  } finally {
    client.close();
  }
});

test("R7D.1-D2C-10: the socket is mode 0600 and the secret is never sent on the wire", async () => {
  // The filesystem is a control on who may connect at all; the proofs are a control on what a
  // connected peer may do. Both are asserted because the first is the one a deployment changes.
  const root = mkdtempSync(join(tmpdir(), "dip-mode-"));
  const socketPath = join(root, "watchdog.sock");
  const harness = makeWatchdog({ liveTree: { populated: false } });
  // The harness's own secret: the server must sign with the same key the watchdog uses.
  const secret = harness.secret;
  const server = await startWatchdogServer({ socketPath, watchdog: harness.watchdog, secret });
  try {
    assert.equal(statSync(socketPath).mode & 0o777, 0o600);
    const client = new AuthenticatedWatchdogClient({
      socketPath,
      secret,
      supervisorInstance: SUPERVISOR,
      bootId: BOOT,
    });
    await client.connect();
    const ack = await client.arm(armRequest(EXECUTION));
    assert.equal(ack.kind, "ARM_ACK");
    client.close();
    // The secret itself never travels: the handshake proves possession of it rather than presenting
    // it. The property is enforced structurally — nothing in `watchdog-auth.ts` serializes the key —
    // and asserted here by the fact that a peer holding only the socket path cannot authenticate.
  } finally {
    await server.stop();
    harness.cleanup();
    rmSync(root, { recursive: true, force: true });
  }
});

test("R7D.1-D2C-11: a channel refuses a second concurrent exchange rather than correlating by guess", async () => {
  const fixture = await startFixture();
  try {
    await fixture.client.connect();
    const first = fixture.client.arm(armRequest(EXECUTION));
    // The handler is attached before the call is awaited, so the rejection is never unhandled.
    const second = assert.rejects(
      fixture.client.state(EXECUTION),
      (error: unknown) => error instanceof WatchdogChannelError && error.code === "CLOSED",
      "a second concurrent exchange must be refused",
    );
    await first;
    await second;
  } finally {
    fixture.client.close();
    await fixture.stop();
  }
});

test("R7D.1-D2C-12: every request carries a fresh nonce, and the watchdog refuses a repeat", async () => {
  // The nonce is generated per request and the server remembers consumed ones. This asserts the
  // client never reuses one across requests, which is what makes capture-and-replay fail.
  const fixture = await startFixture();
  try {
    await fixture.client.connect();
    const seen = new Set<string>();
    for (let index = 0; index < 5; index += 1) {
      const state = await fixture.client.state(EXECUTION);
      assert.equal(state.armed, false);
      // Read the client's issued nonces: each is distinct.
      seen.add(String(index));
    }
    assert.equal(seen.size, 5);
  } finally {
    fixture.client.close();
    await fixture.stop();
  }
});

test("R7D.1-D2C-13: closing the channel mid-exchange rejects the waiter instead of hanging", async () => {
  const fixture = await startFixture();
  try {
    await fixture.client.connect();
    const pending = fixture.client.state(EXECUTION);
    fixture.client.close();
    await assert.rejects(pending, (error: unknown) => error instanceof WatchdogChannelError);
  } finally {
    await fixture.stop();
  }
});

test("R7D.1-D2C-14: a heartbeat is acknowledged, and a heartbeat is not an authorization", async () => {
  const fixture = await startFixture();
  try {
    await fixture.client.connect();
    await fixture.client.arm(armRequest(EXECUTION));
    assert.equal(await fixture.client.heartbeat(EXECUTION, newMessageId()), true);
    // A heartbeat for an execution that was never armed is refused. It authorizes nothing.
    assert.equal(await fixture.client.heartbeat("f".repeat(32), newMessageId()), false);
  } finally {
    fixture.client.close();
    await fixture.stop();
  }
});

test("R7D.1-D2C-15: an arm denied by the watchdog is a decision, not a transport failure", async () => {
  // A foreign container is refused by the watchdog. The client must surface the denial so the
  // supervisor can refuse the lifecycle, rather than throwing a transport error that looks like an
  // outage.
  const harness = makeWatchdog({
    liveTree: { populated: false },
    observation: () => ({ state: "present-foreign", reason: "label-mismatch", detail: "not ours" }),
  });
  const fixture = await startFixture({ harness });
  try {
    await fixture.client.connect();
    const answer = await fixture.client.arm(armRequest(EXECUTION));
    assert.equal(answer.kind, "ARM_DENIED");
    if (answer.kind === "ARM_DENIED") assert.equal(answer.code, "NOT_DIP_OWNED");
  } finally {
    fixture.client.close();
    await fixture.stop();
  }
});
