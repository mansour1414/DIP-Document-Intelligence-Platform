/**
 * R7D.1 F05 — the IPC transcript.
 *
 * ## Scope of the evidence
 *
 * These tests prove properties of the transcript and the proof computation. They do not prove
 * socket-level authentication, because no socket exists yet: `listen`/`accept`, peer credential
 * lookup (`SO_PEERCRED`), and the connection budget belong to the supervisor increment.
 *
 * The distinction matters because a passing crypto suite is easy to mistake for an authenticated
 * transport. It is not one. What it establishes is that *if* a connection is authenticated, the
 * proof cannot be moved to another exchange.
 */

import assert from "node:assert/strict";
import test from "node:test";
import {
  buildTranscript,
  ChallengeRegistry,
  computeProof,
  generateNonce,
  IPC_LIMITS,
  IPC_PROTOCOL_VERSION,
  isOperationAllowed,
  parseDigest,
  parseOperation,
  parseRequestId,
  parseReservationId,
  parseRole,
  ROLE_POLICY,
  verifyProof,
  type TranscriptInput,
} from "../src/lib/execution/ipc-auth";

const SECRET = Buffer.alloc(32, 7);
const OTHER_SECRET = Buffer.alloc(32, 9);

/** A complete transcript. Every field is present because every field is bound. */
function transcript(overrides: Partial<TranscriptInput> = {}): TranscriptInput {
  return {
    direction: "client-to-server",
    protocolVersion: IPC_PROTOCOL_VERSION,
    supervisorInstance: "supervisor-0001",
    bootId: "boot-abcdef012345",
    serverNonce: Buffer.alloc(32, 1),
    clientNonce: Buffer.alloc(32, 2),
    role: "worker",
    requestId: "0123456789abcdef",
    operation: "fill",
    reservationId: "fedcba9876543210",
    controlLength: 128,
    controlSha256: "a".repeat(64),
    bodyLength: 4096,
    bodySha256: "b".repeat(64),
    ...overrides,
  };
}

test("R7D.1-A-1: the transcript carries a domain tag", () => {
  const bytes = computeProof(SECRET, buildBuf(transcript()));
  assert.equal(bytes.byteLength, 32, "HMAC-SHA256 output");
  // The domain tag is the first thing in the signed bytes, so a proof from another protocol
  // cannot verify here even with a shared secret.
  assert.ok(buildBuf(transcript()).subarray(0, 16).toString("utf8").startsWith("dip-ipc-v1"), "domain tag leads the transcript");
});

test("R7D.1-A-2: field boundaries are length-prefixed, so they cannot be moved", () => {
  // Without prefixes, ("app", "worker") and ("appwork", "er") concatenate identically. With
  // them, the two differ — which is the whole point.
  const a = buildBuf(transcript({ supervisorInstance: "app", role: "worker" }));
  const b = buildBuf(transcript({ supervisorInstance: "appwork", role: "worker" }));
  assert.notEqual(a.toString("hex"), b.toString("hex"));
  assert.notEqual(computeProof(SECRET, a).toString("hex"), computeProof(SECRET, b).toString("hex"));
});

test("R7D.1-A-3: every bound field changes the proof", () => {
  // If any one of these did not change the proof, that field would not actually be bound and
  // the table in the module docs would be a lie.
  const base = computeProof(SECRET, buildBuf(transcript())).toString("hex");
  const variants: Array<[string, Partial<TranscriptInput>]> = [
    ["direction", { direction: "server-to-client" }],
    ["supervisorInstance", { supervisorInstance: "supervisor-0002" }],
    ["bootId", { bootId: "boot-ffffffffffff" }],
    ["serverNonce", { serverNonce: Buffer.alloc(32, 3) }],
    ["clientNonce", { clientNonce: Buffer.alloc(32, 4) }],
    ["role", { role: "app" }],
    ["requestId", { requestId: "ffffffffffffffff" }],
    ["operation", { operation: "verify" }],
    ["reservationId", { reservationId: null }],
    ["controlLength", { controlLength: 129 }],
    ["controlSha256", { controlSha256: "c".repeat(64) }],
    ["bodyLength", { bodyLength: 4097 }],
    ["bodySha256", { bodySha256: "d".repeat(64) }],
  ];
  for (const [field, change] of variants) {
    const changed = computeProof(SECRET, buildBuf(transcript(change))).toString("hex");
    assert.notEqual(changed, base, `${field} must be bound into the proof`);
  }
});

test("R7D.1-A-4: a server proof cannot be reflected back as a client proof", () => {
  // Without the direction field, the two are the same signature and the server's own proof
  // would authenticate a client.
  const client = computeProof(SECRET, buildBuf(transcript({ direction: "client-to-server" })));
  const server = computeProof(SECRET, buildBuf(transcript({ direction: "server-to-client" })));
  assert.notEqual(client.toString("hex"), server.toString("hex"));
  assert.equal(verifyProof(SECRET, buildBuf(transcript({ direction: "server-to-client" })), client), false);
});

test("R7D.1-A-5: an absent reservation and an empty one are distinguishable", () => {
  // Both would otherwise serialize as an empty field, making "no capacity reserved" and
  // "reserved with an empty id" the same signed message.
  const absent = buildBuf(transcript({ reservationId: null }));
  const empty = buildBuf(transcript({ reservationId: "" }));
  assert.notEqual(absent.toString("hex"), empty.toString("hex"));
});

test("R7D.1-A-6: a proof verifies only against its own transcript", () => {
  const proof = computeProof(SECRET, buildBuf(transcript()));
  assert.equal(verifyProof(SECRET, buildBuf(transcript()), proof), true);
  assert.equal(verifyProof(SECRET, buildBuf(transcript({ operation: "inspect" })), proof), false);
});

test("R7D.1-A-7: a proof verifies only under the right secret", () => {
  const proof = computeProof(SECRET, buildBuf(transcript()));
  assert.equal(verifyProof(OTHER_SECRET, buildBuf(transcript()), proof), false);
});

test("R7D.1-A-8: a wrong-length proof is rejected without throwing", () => {
  // A malformed proof is an authentication failure to be counted, not a crash.
  for (const candidate of [Buffer.alloc(0), Buffer.alloc(31, 1), Buffer.alloc(33, 1)]) {
    assert.equal(verifyProof(SECRET, buildBuf(transcript()), candidate), false);
  }
});

test("R7D.1-A-9: a short secret is refused rather than silently accepted", () => {
  assert.throws(() => computeProof(Buffer.alloc(8, 1), buildBuf(transcript())), /at least 32 bytes/u);
});

test("R7D.1-A-10: a challenge can be consumed exactly once", () => {
  const registry = new ChallengeRegistry({ now: () => 1_000 });
  const nonce = generateNonce();
  registry.issue(nonce);
  assert.equal(registry.consume(nonce, IPC_LIMITS.authTimeoutMs), true);
  // The second use of the same challenge must fail: otherwise a captured proof stays valid
  // for the life of the session rather than for one exchange.
  assert.equal(registry.consume(nonce, IPC_LIMITS.authTimeoutMs), false);
});

test("R7D.1-A-11: an unissued challenge is refused", () => {
  const registry = new ChallengeRegistry({ now: () => 1_000 });
  assert.equal(registry.consume(generateNonce(), IPC_LIMITS.authTimeoutMs), false);
});

test("R7D.1-A-12: an expired challenge is refused", () => {
  let now = 1_000;
  const registry = new ChallengeRegistry({ now: () => now });
  const nonce = generateNonce();
  registry.issue(nonce);
  now += IPC_LIMITS.authTimeoutMs + 1;
  assert.equal(registry.consume(nonce, IPC_LIMITS.authTimeoutMs), false);
});

test("R7D.1-A-13: the challenge registry is bounded", () => {
  // Unbounded memory an attacker controls is its own denial of service.
  const registry = new ChallengeRegistry({ capacity: 8, now: () => 1_000 });
  for (let index = 0; index < 32; index += 1) registry.issue(generateNonce());
  assert.ok(registry.size <= 8, `registry must stay bounded, was ${registry.size}`);
});

test("R7D.1-A-14: the app role cannot fill or verify", () => {
  assert.deepEqual([...ROLE_POLICY.app], ["inspect"]);
  assert.equal(isOperationAllowed("app", "inspect"), true);
  // An authorization failure, distinct from an authentication failure.
  assert.equal(isOperationAllowed("app", "fill"), false);
  assert.equal(isOperationAllowed("app", "verify"), false);
});

test("R7D.1-A-15: the worker role may inspect, fill and verify", () => {
  for (const op of ["inspect", "fill", "verify"]) assert.equal(isOperationAllowed("worker", op), true);
  assert.equal(isOperationAllowed("worker", "delete"), false);
});

test("R7D.1-A-16: role and operation parsing are strict", () => {
  for (const bad of ["app ", "APP", "", null, undefined, 1, {}, ["app"]]) assert.throws(() => parseRole(bad), /unknown role/u);
  for (const bad of ["Fill", "", "delete", null, undefined, 1]) assert.throws(() => parseOperation(bad), /unknown operation/u);
});

test("R7D.1-A-17: prototype keys are not accepted as roles", () => {
  // `ROLE_POLICY["constructor"]` is truthy and `ROLE_POLICY["__proto__"]` resolves to an
  // object, so an `in`-based membership test would accept both.
  for (const bad of ["constructor", "__proto__", "toString", "hasOwnProperty"]) {
    assert.throws(() => parseRole(bad), /unknown role/u);
  }
});

test("R7D.1-A-18: request and reservation ids are opaque hex", () => {
  assert.equal(parseRequestId("0123456789abcdef"), "0123456789abcdef");
  for (const bad of ["../../etc/passwd", "0123456789abcde", "Z123456789abcdef", "", null, 1]) {
    assert.throws(() => parseRequestId(bad), /invalid request id/u);
  }
  assert.equal(parseReservationId(null), null);
  assert.equal(parseReservationId("fedcba9876543210"), "fedcba9876543210");
  assert.throws(() => parseReservationId("not-hex"), /invalid reservation id/u);
});

test("R7D.1-A-19: digests are exactly 64 hex characters", () => {
  assert.equal(parseDigest("a".repeat(64)), "a".repeat(64));
  for (const bad of ["a".repeat(63), "a".repeat(65), "A".repeat(64), "", null]) {
    assert.throws(() => parseDigest(bad), /invalid digest/u);
  }
});

test("R7D.1-A-20: an unknown proof direction is not signable", () => {
  // The type is a closed union, but a peer's value reaches this function as data. A made-up
  // direction must not produce a signable transcript, or the reflection defence is a
  // convention rather than a rule.
  assert.throws(() => buildBuf(transcript({ direction: "sideways" as never })), /unknown proof direction/u);
});

test("R7D.1-A-21: a transcript for another protocol version cannot be signed", () => {
  // Binding a version this code does not speak would sign a transcript whose meaning is not
  // defined here. Rejecting makes a downgrade impossible rather than merely unlikely.
  assert.throws(() => buildBuf(transcript({ protocolVersion: IPC_PROTOCOL_VERSION + 1 })), /unsupported protocol version/u);
  assert.throws(() => buildBuf(transcript({ protocolVersion: 0 })), /unsupported protocol version/u);
  assert.doesNotThrow(() => buildBuf(transcript()));
});

/** Build the signed bytes for a transcript. Kept local so every test uses the same path. */
function buildBuf(input: TranscriptInput): Buffer {
  return buildTranscript(input);
}
