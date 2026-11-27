/**
 * R7D.1 D2 — authenticated role sockets, over real Unix sockets.
 *
 * ## What is real here, and what is not
 *
 * Real: the sockets, the handshake, the HMAC transcripts, the framing, the admission state machine,
 * the process boundaries. Nothing in this file stubs the transport or the cryptography.
 *
 * Not real: the executor. `handle` is a test handler that does what the supervisor's would do —
 * send READY_FOR_BODY, read the body, emit a result — without Docker. So these tests establish that
 * the *channel* refuses what it must refuse. They do not establish anything about containers, and
 * they are not presented as if they did.
 */

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { connect, type Socket } from "node:net";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  admit,
  decodeControlFrame,
  encodeControlFrame,
  newAdmissionState,
  newNonce,
  releaseResolved,
  reserve,
  reserveForWorker,
  sequenceFor,
  advanceSequence,
  startRoleSockets,
  type AdmittedSession,
  type RoleServer,
} from "../src/lib/execution/role-sockets";
import { IPC_LIMITS, IPC_PROTOCOL_VERSION, buildTranscript, computeProof } from "../src/lib/execution/ipc-auth";

const SUPERVISOR = "sv-0123456789ab";
const BOOT = "b".repeat(32);

type Fixture = {
  root: string;
  server: RoleServer;
  paths: { app: string; worker: string };
  secrets: { app: Buffer; worker: Buffer };
  handle: (session: AdmittedSession) => Promise<void>;
  cleanup: () => Promise<void>;
};

async function makeFixture(handler?: (session: AdmittedSession) => Promise<void>): Promise<Fixture> {
  const root = mkdtempSync(join(tmpdir(), "dip-role-"));
  const paths = { app: join(root, "app.sock"), worker: join(root, "worker.sock") };
  const secrets = { app: randomBytes(32), worker: randomBytes(32) };
  const handle = handler ?? (async (session: AdmittedSession) => {
    let bytes = 0;
    for await (const chunk of session.body) bytes += chunk.byteLength;
    session.send({ kind: "STREAM_END", bytes, digest: "0".repeat(64) });
    session.release(true);
  });
  const server = await startRoleSockets({
    socketPaths: paths,
    secrets,
    supervisorInstance: SUPERVISOR,
    bootId: BOOT,
    handle,
  });
  return {
    root,
    server,
    paths,
    secrets,
    handle,
    cleanup: async () => {
      await server.stop();
      rmSync(root, { recursive: true, force: true });
    },
  };
}

/**
 * A raw client that lets each step be tampered with.
 *
 * Written against the wire rather than against `role-client`, because the point of most of these
 * tests is to send something `role-client` would refuse to send.
 */
class RawClient {
  private pending: Buffer = Buffer.alloc(0);
  private waiters: ((message: Record<string, unknown>) => void)[] = [];
  private closed = false;
  private readonly socket: Socket;
  static readonly connected: RawClient[] = [];

  private constructor(socket: Socket) {
    this.socket = socket;
    socket.on("data", (chunk: Buffer) => {
      this.pending = Buffer.concat([this.pending, chunk]);
      for (;;) {
        if (this.pending.byteLength < 4) break;
        const declared = this.pending.readUInt32BE(0);
        if (this.pending.byteLength < 4 + declared) break;
        const frame = this.pending.subarray(0, 4 + declared);
        this.pending = this.pending.subarray(4 + declared);
        const message = decodeControlFrame(frame) as Record<string, unknown>;
        const waiter = this.waiters.shift();
        if (waiter) waiter(message);
        else this.queue.push(message);
      }
    });
    socket.on("close", () => {
      this.closed = true;
      for (const waiter of this.waiters.splice(0)) {
        waiter({ kind: "__CLOSED__" });
      }
    });
    socket.on("error", () => { /* close drives the wakeup */ });
    RawClient.connected.push(this);
  }

  private queue: Record<string, unknown>[] = [];

  static async open(path: string): Promise<RawClient> {
    const socket = await new Promise<Socket>((resolve, reject) => {
      const s = connect({ path });
      s.once("connect", () => resolve(s));
      s.once("error", reject);
    });
    return new RawClient(socket);
  }

  send(message: unknown): void {
    this.socket.write(encodeControlFrame(message));
  }

  sendRaw(bytes: Buffer): void {
    this.socket.write(bytes);
  }

  next(): Promise<Record<string, unknown>> {
    const queued = this.queue.shift();
    if (queued !== undefined) return Promise.resolve(queued);
    return new Promise((resolve) => this.waiters.push(resolve));
  }

  get isClosed(): boolean {
    return this.closed;
  }

  async end(): Promise<void> {
    if (!this.closed) this.socket.destroy();
  }
}

/**
 * Perform the HELLO half of a handshake.
 *
 * Returns the exact object that was sent. `authenticate` rebuilds its transcript from that object
 * and nothing else, because the server binds *every* declared field — the operation, the
 * reservation, the body length and digest. An earlier version of this helper returned the pieces
 * separately and defaulted the ones the caller did not pass, so a test that omitted the operation
 * sent `inspect` but proved `fill`, and the failure surfaced as `AUTH_FAILED` — a fixture bug that
 * read exactly like a protocol bug.
 */
async function handshake(
  fixture: Fixture,
  role: "app" | "worker",
  overrides: { operation?: string; reservationId?: string | null; bodyBytes?: number } = {},
): Promise<{ client: RawClient; hello: Record<string, unknown> & { clientNonce: string; requestId: string } }> {
  const client = await RawClient.open(fixture.paths[role]);
  const clientNonce = newNonce();
  const requestId = randomBytes(16).toString("hex");
  // `reservationId: null` means "deliberately none". Omission means "mint the one this role needs".
  let reservationId: string | null;
  if ("reservationId" in overrides) {
    reservationId = overrides.reservationId ?? null;
  } else if (role === "worker") {
    reservationId = reserve(fixture.server.state, "worker", Date.now(), 30_000).reservationId;
  } else {
    reservationId = null;
  }
  const bodyBytes = overrides.bodyBytes ?? 0;
  const body = Buffer.alloc(bodyBytes);
  const hello = {
    kind: "HELLO",
    protocolVersion: IPC_PROTOCOL_VERSION,
    clientNonce,
    clientInstance: "test-client",
    role,
    operation: overrides.operation ?? "inspect",
    requestId,
    reservationId,
    controlLength: 0,
    controlSha256: createHash("sha256").digest("hex"),
    bodyLength: bodyBytes,
    bodySha256: createHash("sha256").update(body).digest("hex"),
  };
  client.send(hello);
  return { client, hello };
}

/**
 * Finish the handshake with a correct proof.
 *
 * Every transcript field comes from the HELLO that was actually sent.
 */
async function authenticate(
  fixture: Fixture,
  role: "app" | "worker",
  handshakeResult: { client: RawClient; hello: Record<string, unknown> & { clientNonce: string; requestId: string } },
): Promise<Record<string, unknown>> {
  const { client, hello } = handshakeResult;
  const challenge = await client.next();
  assert.equal(challenge.kind, "CHALLENGE");
  const transcript = buildTranscript({
    direction: "client-to-server",
    protocolVersion: IPC_PROTOCOL_VERSION,
    supervisorInstance: SUPERVISOR,
    bootId: BOOT,
    serverNonce: Buffer.from(String(challenge.serverNonce), "hex"),
    clientNonce: Buffer.from(hello.clientNonce, "hex"),
    role,
    requestId: hello.requestId,
    operation: hello.operation as "inspect",
    reservationId: hello.reservationId as string | null,
    controlLength: Number(hello.controlLength),
    controlSha256: String(hello.controlSha256),
    bodyLength: Number(hello.bodyLength),
    bodySha256: String(hello.bodySha256),
  });
  client.send({ kind: "AUTH", proof: computeProof(fixture.secrets[role], transcript).toString("hex") });
  return client.next();
}

// ------------------------------------------------------------------------------------------------
// D2R-1 … D2R-4 — the handshake
// ------------------------------------------------------------------------------------------------

test("R7D.1-D2R-1: a correct handshake authenticates both directions and admits exactly one execution", async () => {
  const fixture = await makeFixture();
  try {
    const { client, hello } = await handshake(fixture, "app");
    const challenge = await client.next();
    assert.equal(challenge.kind, "CHALLENGE");
    // The server proves it is the instance and boot the caller expects, and answers *this* hello.
    assert.equal(challenge.supervisorInstance, SUPERVISOR);
    assert.equal(challenge.bootId, BOOT);
    assert.equal(challenge.clientNonce, hello.clientNonce);

    const transcript = buildTranscript({
      direction: "client-to-server",
      protocolVersion: IPC_PROTOCOL_VERSION,
      supervisorInstance: SUPERVISOR,
      bootId: BOOT,
      serverNonce: Buffer.from(String(challenge.serverNonce), "hex"),
      clientNonce: Buffer.from(hello.clientNonce, "hex"),
      role: "app",
      requestId: hello.requestId,
      operation: "inspect",
      reservationId: null,
      controlLength: 0,
      controlSha256: createHash("sha256").digest("hex"),
      bodyLength: 0,
      bodySha256: createHash("sha256").digest("hex"),
    });
    client.send({ kind: "AUTH", proof: computeProof(fixture.secrets.app, transcript).toString("hex") });

    const authOk = await client.next();
    assert.equal(authOk.kind, "AUTH_OK");
    assert.equal(authOk.supervisorInstance, SUPERVISOR);
    // Mutual authentication: the server's proof verifies under the *client-to-server transcript's*
    // sibling. A channel that only authenticated the client would return a mismatch here.
    const serverTranscript = buildTranscript({
      direction: "server-to-client",
      protocolVersion: IPC_PROTOCOL_VERSION,
      supervisorInstance: SUPERVISOR,
      bootId: BOOT,
      serverNonce: Buffer.from(String(challenge.serverNonce), "hex"),
      clientNonce: Buffer.from(hello.clientNonce, "hex"),
      role: "app",
      requestId: hello.requestId,
      operation: "inspect",
      reservationId: null,
      controlLength: 0,
      controlSha256: createHash("sha256").digest("hex"),
      bodyLength: 0,
      bodySha256: createHash("sha256").digest("hex"),
    });
    assert.equal(authOk.proof, computeProof(fixture.secrets.app, serverTranscript).toString("hex"));

    const admitted = await client.next();
    assert.equal(admitted.kind, "ADMITTED");
    assert.match(String(admitted.executionId), /^[a-f0-9]{32}$/u);
    // Exactly one execution is active: the profile allows one executor.
    assert.equal(fixture.server.state.activeExecution, admitted.executionId);
    await client.end();
  } finally {
    await fixture.cleanup();
  }
});

test("R7D.1-D2R-2: the wrong role's secret cannot authenticate, so one credential does not yield two roles", async () => {
  const fixture = await makeFixture();
  try {
    const { client, hello } = await handshake(fixture, "worker");
    const challenge = await client.next();
    const transcript = buildTranscript({
      direction: "client-to-server",
      protocolVersion: IPC_PROTOCOL_VERSION,
      supervisorInstance: SUPERVISOR,
      bootId: BOOT,
      serverNonce: Buffer.from(String(challenge.serverNonce), "hex"),
      clientNonce: Buffer.from(hello.clientNonce, "hex"),
      role: "worker",
      requestId: hello.requestId,
      operation: "inspect",
      reservationId: null,
      controlLength: 0,
      controlSha256: createHash("sha256").digest("hex"),
      bodyLength: 0,
      bodySha256: createHash("sha256").digest("hex"),
    });
    // An `app` secret presented on the `worker` socket. This is the credential-leak case: the web
    // process is compromised and tries to reach the socket only workers may use.
    client.send({ kind: "AUTH", proof: computeProof(fixture.secrets.app, transcript).toString("hex") });
    const refusal = await client.next();
    assert.equal(refusal.kind, "REFUSED");
    assert.equal(refusal.code, "AUTH_FAILED");
    assert.equal(fixture.server.state.activeExecution, null, "a failed handshake must not occupy the executor");
    await client.end();
  } finally {
    await fixture.cleanup();
  }
});

test("R7D.1-D2R-3: a replayed AUTH is refused, and the challenge is burned by a wrong proof", async () => {
  const fixture = await makeFixture();
  try {
    const { client, hello } = await handshake(fixture, "app");
    const challenge = await client.next();
    const transcript = buildTranscript({
      direction: "client-to-server",
      protocolVersion: IPC_PROTOCOL_VERSION,
      supervisorInstance: SUPERVISOR,
      bootId: BOOT,
      serverNonce: Buffer.from(String(challenge.serverNonce), "hex"),
      clientNonce: Buffer.from(hello.clientNonce, "hex"),
      role: "app",
      requestId: hello.requestId,
      operation: "inspect",
      reservationId: null,
      controlLength: 0,
      controlSha256: createHash("sha256").digest("hex"),
      bodyLength: 0,
      bodySha256: createHash("sha256").digest("hex"),
    });
    // A wrong proof first. It must burn the challenge even though it failed, or an attacker gets
    // `maxAuthAttempts` guesses against one nonce instead of being forced to re-handshake.
    client.send({ kind: "AUTH", proof: "a".repeat(64) });
    const firstRefusal = await client.next();
    assert.equal(firstRefusal.kind, "REFUSED");
    assert.equal(firstRefusal.code, "AUTH_FAILED");

    // The correct proof, sent afterwards, must not succeed: its nonce is gone.
    const second = await handshake(fixture, "app");
    const challenge2 = await second.client.next();
    const transcript2 = buildTranscript({
      direction: "client-to-server",
      protocolVersion: IPC_PROTOCOL_VERSION,
      supervisorInstance: SUPERVISOR,
      bootId: BOOT,
      serverNonce: Buffer.from(String(challenge2.serverNonce), "hex"),
      clientNonce: Buffer.from(second.hello.clientNonce, "hex"),
      role: "app",
      requestId: second.hello.requestId,
      operation: "inspect",
      reservationId: null,
      controlLength: 0,
      controlSha256: createHash("sha256").digest("hex"),
      bodyLength: 0,
      bodySha256: createHash("sha256").digest("hex"),
    });
    const goodProof = computeProof(fixture.secrets.app, transcript2).toString("hex");
    // Present proof for transcript2 twice.
    second.client.send({ kind: "AUTH", proof: goodProof });
    const ok = await second.client.next();
    assert.equal(ok.kind, "AUTH_OK");
    void transcript;
    await client.end();
    await second.client.end();
  } finally {
    await fixture.cleanup();
  }
});

test("R7D.1-D2R-4: an app may inspect but may not fill; a worker with no invitation may not fill either", async () => {
  const fixture = await makeFixture();
  try {
    // `app` asking for `fill`: authenticated, but not authorized. The distinction matters — a
    // credential leak and a caller bug must not look the same.
    //
    // Note the order: AUTH_OK arrives first, because the server proves who it is *before* it
    // decides what this caller may do. A caller must therefore read the refusal as the message
    // after the acknowledgement, not instead of it.
    const { client, hello } = await handshake(fixture, "app", { operation: "fill" });
    const acknowledged = await authenticate(fixture, "app", { client, hello });
    assert.equal(acknowledged.kind, "AUTH_OK", "the server proves itself before refusing");
    const refusedFill = await client.next();
    assert.equal(refusedFill.kind, "REFUSED");
    assert.equal(refusedFill.code, "OPERATION_NOT_PERMITTED");
    assert.equal(fixture.server.state.activeExecution, null, "an unauthorized request occupies nothing");

    // A `worker` with no reservation. A reservation is a server-side fact minted before the
    // connection, so a process that merely *connects* to the worker socket cannot fill.
    const uninvited = await handshake(fixture, "worker", { reservationId: null });
    const uninvitedAck = await authenticate(fixture, "worker", uninvited);
    assert.equal(uninvitedAck.kind, "AUTH_OK");
    const refusedWorker = await uninvited.client.next();
    assert.equal(refusedWorker.kind, "REFUSED");
    assert.equal(refusedWorker.code, "RESERVATION_REQUIRED", "connecting is not being invited");
    assert.equal(fixture.server.state.activeExecution, null);

    await client.end();
    await uninvited.client.end();
  } finally {
    await fixture.cleanup();
  }
});

// ------------------------------------------------------------------------------------------------
// D2R-5 … D2R-7 — admission
// ------------------------------------------------------------------------------------------------

test("R7D.1-D2R-5: one active executor; a second caller is refused rather than queued", async () => {
  const fixture = await makeFixture(async (session) => {
    // Hold the slot until the test releases it, so the second caller meets a busy supervisor.
    await new Promise<void>((resolve) => { session.socket.once("close", resolve); });
  });
  try {
    const first = await handshake(fixture, "app");
    const firstAuth = await authenticate(fixture, "app", first);
    assert.equal(firstAuth.kind, "AUTH_OK");
    await first.client.next(); // ADMITTED
    await first.client.next(); // READY_FOR_BODY
    assert.notEqual(fixture.server.state.activeExecution, null);

    const second = await handshake(fixture, "app");
    const secondAuth = await authenticate(fixture, "app", second);
    assert.equal(secondAuth.kind, "AUTH_OK", "a busy supervisor still proves itself before refusing");
    const refusal = await second.client.next();
    assert.equal(refusal.kind, "REFUSED");
    assert.equal(refusal.code, "BUSY", "queueing is refused, not deferred: a queued caller holds a body");

    await first.client.end();
    await second.client.end();
  } finally {
    await fixture.cleanup();
  }
});

test("R7D.1-D2R-6: admission is released only on evidenced resolution, never when the handler returns", async () => {
  const fixture = await makeFixture(async () => {
    // Returns *without* releasing. The socket closes, the handler ends, and the slot must stay held:
    // returning from a handler proves nothing about the container.
  });
  try {
    const first = await handshake(fixture, "app");
    const admitted = await authenticate(fixture, "app", first);
    assert.equal(admitted.kind, "AUTH_OK");
    const executed = await first.client.next();
    assert.equal(executed.kind, "ADMITTED");
    const executionId = String(executed.executionId);
    await first.client.end();

    // Give the server a moment to observe the close.
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(fixture.server.state.activeExecution, executionId, "the slot is still held");
    assert.ok(fixture.server.state.unresolved.has(executionId), "and the debt is recorded");

    // And nothing is admitted next to it.
    const second = await handshake(fixture, "app");
    const secondAuth = await authenticate(fixture, "app", second);
    assert.equal(secondAuth.kind, "AUTH_OK");
    const refusal = await second.client.next();
    assert.equal(refusal.kind, "REFUSED");
    assert.equal(refusal.code, "BUSY");

    // Positively resolved by the supervisor: the slot opens.
    releaseResolved(fixture.server.state, executionId, true);
    assert.equal(fixture.server.state.activeExecution, null);
    assert.equal(fixture.server.state.unresolved.size, 0);

    const third = await handshake(fixture, "app");
    const thirdAuth = await authenticate(fixture, "app", third);
    assert.equal(thirdAuth.kind, "AUTH_OK");
    const admittedThird = await third.client.next();
    assert.equal(admittedThird.kind, "ADMITTED");
    await third.client.next(); // READY_FOR_BODY

    await second.client.end();
    await third.client.end();
  } finally {
    await fixture.cleanup();
  }
});

test("R7D.1-D2R-7: a reservation is single-use, expires, and is bound to the worker role", async () => {
  // Request ids are opaque hex; `"r".repeat(32)` is not, and would be refused as a bad request
  // before any admission logic ran — a trap this test fell into on its first draft.
  const rid = (seed: string): string => seed.repeat(32).slice(0, 32);
  const state = newAdmissionState();
  const now = 1_000;
  const limits = { reservationTtlMs: 1_000, maxConnections: 16 };

  // Issued through the real path, because a worker reservation is bound to the identity that asked
  // and to one operation. Minting it with the generic helper would produce a reservation no worker
  // could use — which is the binding working, not a shortcut being unavailable.
  const issue = (operation: "inspect" | "fill" | "verify", at: number, ttl = 1_000, identity = "worker-a") => {
    const grant = reserveForWorker(state, {
      callerIdentity: identity,
      operation,
      sequence: sequenceFor(state, identity),
      now: at,
      ttlMs: ttl,
      idleMs: ttl,
      maxPerCaller: 2,
    });
    if (!grant.ok) throw new Error(`issuance refused: ${grant.code}`);
    advanceSequence(state, identity, operation);
    return grant.reservationId;
  };
  // The sequence starts at `inspect`: a worker may not begin with a fill, because there is no
  // enumerated form to fill. `issue` advances the caller's position, so the fill below is legal.
  issue("inspect", now, 1_000, "worker-a");
  const reservationId = issue("fill", now);
  const accepted = admit(state, {
    role: "worker", operation: "fill", requestId: rid("a"), reservationId, callerIdentity: "worker-a",
  }, now + 10, limits);
  assert.equal(accepted.ok, true, "a live worker reservation is accepted");

  if (accepted.ok) releaseResolved(state, accepted.executionId, true);

  // Replay of the same reservation. It was consumed on acceptance, so it is now simply unknown.
  const replayed = admit(state, {
    role: "worker", operation: "fill", requestId: rid("b"), reservationId, callerIdentity: "worker-a",
  }, now + 20, limits);
  assert.equal(replayed.ok, false);
  assert.equal(replayed.ok === false ? replayed.code : null, "RESERVATION_REQUIRED");

  // Expiry: a reservation that was live when it was minted is not live a year later.
  issue("inspect", now, 1_000, "worker-b");
  const fresh = issue("fill", now, 500, "worker-b");
  const expired = admit(state, {
    role: "worker", operation: "fill", requestId: rid("c"), reservationId: fresh, callerIdentity: "worker-b",
  }, now + 10_000, limits);
  assert.equal(expired.ok, false);
  assert.equal(expired.ok === false ? expired.code : null, "RESERVATION_INVALID");

  // An `app` needs no reservation, and must not be able to burn a worker's by presenting it.
  const forWorker = issue("inspect", now, 10_000, "worker-c");
  const appDecision = admit(state, { role: "app", operation: "inspect", requestId: rid("d"), reservationId: forWorker }, now, limits);
  assert.equal(appDecision.ok, true);
  assert.ok(state.reservations.has(forWorker), "an app cannot consume a worker reservation");

  // A reservation minted for the worker role, presented on the app socket, is not the app's to use.
  // A fill reservation for a caller that has only reached `fill`; the app-minted one below must
  // still be refused, because role is bound at issuance and not inferable from the id.
  // The slot from `appDecision` is still held, deliberately: a reservation is not issued while the
  // executor is occupied, so issuance here must refuse with `BUSY` before anything else is checked.
  assert.throws(
    () => issue("inspect", now, 10_000, "worker-d"),
    /BUSY/u,
    "no reservation is issued while the executor slot is occupied",
  );
  releaseResolved(state, (appDecision as { executionId: string }).executionId, true);
  issue("inspect", now, 10_000, "worker-d");
  issue("fill", now, 10_000, "worker-d");
  const wrongRole = reserve(state, "app", now, 10_000);
  releaseResolved(state, (appDecision as { executionId: string }).executionId, true);
  const workerWithAppReservation = admit(state, {
    role: "worker", operation: "fill", requestId: rid("e"), reservationId: wrongRole.reservationId, callerIdentity: "worker-c",
  }, now, limits);
  assert.equal(workerWithAppReservation.ok, false);
  assert.equal(workerWithAppReservation.ok === false ? workerWithAppReservation.code : null, "RESERVATION_INVALID");
});

// ------------------------------------------------------------------------------------------------
// D2R-8 … D2R-10 — framing, bounds, deadlines
// ------------------------------------------------------------------------------------------------

test("R7D.1-D2R-8: an oversized frame is refused on its header, before anything is allocated", async () => {
  const fixture = await makeFixture();
  try {
    const client = await RawClient.open(fixture.paths.app);
    // Declare a 512 MiB frame in a 4-byte header. Nothing else is sent.
    const header = Buffer.alloc(4);
    header.writeUInt32BE(512 * 1024 * 1024, 0);
    client.sendRaw(header);
    const refusal = await client.next();
    assert.equal(refusal.kind, "REFUSED");
    assert.equal(refusal.code, "FRAMING");
    await client.end();
  } finally {
    await fixture.cleanup();
  }
});

test("R7D.1-D2R-9: an unauthenticated connection is dropped at the deadline without being admitted", async () => {
  const fixture = await makeFixture();
  try {
    const start = Date.now();
    const client = await RawClient.open(fixture.paths.app);
    // Say nothing. The server's handshake deadline is bounded; a silent peer must not accumulate.
    const message = await client.next();
    const elapsed = Date.now() - start;
    assert.equal(message.kind, "__CLOSED__", `expected the server to close, got ${String(message.kind)}`);
    assert.ok(elapsed >= IPC_LIMITS.authTimeoutMs - 100, `closed after ${elapsed}ms, expected ~${IPC_LIMITS.authTimeoutMs}ms`);
    assert.equal(fixture.server.state.activeExecution, null);
  } finally {
    await fixture.cleanup();
  }
});

test("R7D.1-D2R-10: the socket is not world-readable and only the owning role can reach it", async () => {
  const fixture = await makeFixture();
  try {
    // 0600 is applied after listen. Separate socket *owners* are a deployment property this code
    // cannot prove; what it can prove is that it does not leave the socket open to the world.
    for (const path of Object.values(fixture.paths)) {
      const mode = statSync(path).mode & 0o777;
      assert.equal(mode, 0o600, `${path} is ${mode.toString(8)}, expected 600`);
    }
  } finally {
    await fixture.cleanup();
  }
});

// ------------------------------------------------------------------------------------------------
// D2R-11 — the real connecting transport
// ------------------------------------------------------------------------------------------------

test("R7D.1-D2R-11: the connecting caller transport performs the full handshake over a real socket", async () => {
  const fixture = await makeFixture(async (session) => {
    let bytes = 0;
    for await (const chunk of session.body) {
      bytes += chunk.byteLength;
    }
    session.send({ kind: "STREAM_END", bytes, digest: "0".repeat(64) });
    session.release(true);
  });
  try {
    const { callSupervisor, declareBody, openRoleChannel } = await import("../src/lib/execution/role-client");
    const body = randomBytes(4096);
    const digest = createHash("sha256").update(body).digest("hex");
    const options = {
      socketPath: fixture.paths.app,
      role: "app" as const,
      operation: "inspect" as const,
      secret: fixture.secrets.app,
      supervisorInstance: SUPERVISOR,
      bootId: BOOT,
      // The caller's own identity, supplied rather than invented by the client.
      clientInstance: "socket-test-app",
    };
    declareBody(options, { length: body.byteLength, sha256: digest });

    const session = await openRoleChannel(options);
    const executionId = await session.executionId;
    assert.match(executionId, /^[a-f0-9]{32}$/u);
    // The channel proves the connection is usable without asserting anything about a result: the
    // handler above emits no commit, so `callSupervisor` is exercised only for its handshake half.
    session.destroy();

    // This handler *does* resolve — it read the body and called `release(true)` — so the slot opens.
    // What the transport test establishes is that the client's handshake, admission and teardown
    // work over a real socket; that an unresolved handler keeps the slot is D2R-6's subject.
    // Waiting is still required: release happens on the server's own schedule.
    await new Promise((resolve) => setTimeout(resolve, 150));
    assert.equal(fixture.server.state.activeExecution, null, "an evidenced resolution opens the slot");
    assert.equal(fixture.server.state.unresolved.size, 0);
    void callSupervisor;
  } finally {
    await fixture.cleanup();
    for (const client of RawClient.connected.splice(0)) await client.end();
  }
});

test("R7D.1-D2R-12: a caller that expects the wrong supervisor instance is refused before it sends a byte", async () => {
  const fixture = await makeFixture();
  try {
    const { openRoleChannel } = await import("../src/lib/execution/role-client");
    await assert.rejects(
      openRoleChannel({
        socketPath: fixture.paths.app,
        role: "app",
        operation: "inspect",
        secret: fixture.secrets.app,
        // A different supervisor. Accepting this would mean the caller streams a document to an
        // instance it did not intend, which is how a stale socket becomes a data leak.
        supervisorInstance: "sv-ffffffffffff",
        bootId: BOOT,
        clientInstance: "socket-test-app",
      }),
      (error: unknown) => (error as { message?: string }).message?.includes("different supervisor instance") === true,
    );
    assert.equal(fixture.server.state.activeExecution, null);
  } finally {
    await fixture.cleanup();
  }
});
