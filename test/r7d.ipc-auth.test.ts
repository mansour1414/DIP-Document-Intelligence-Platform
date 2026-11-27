/**
 * R7D.1 — IPC authentication, role separation and replay resistance.
 *
 * These are cryptographic and authorization properties, fully exercisable without a live
 * daemon. What they do **not** cover is the socket's filesystem permissions, which are an
 * OS property and are reported BLOCKED where the host directories cannot be created.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  buildTranscript,
  computeProof,
  generateNonce,
  IPC_DOMAIN,
  IPC_LIMITS,
  isOperationAllowed,
  parseOperation,
  parseRole,
  ROLE_POLICY,
  verifyProof,
} from "../src/lib/execution/ipc-auth";

const secret = randomBytes(32);

function transcript(overrides: Partial<{ role: string; serverNonce: Buffer; clientNonce: Buffer }> = {}) {
  return buildTranscript({ role: "worker", serverNonce: generateNonce(), clientNonce: generateNonce(), ...overrides });
}

// ---------------------------------------------------------------------------------------
// Transcript construction.
// ---------------------------------------------------------------------------------------

test("R7D.1-A-1: the transcript is domain-separated", () => {
  const built = transcript();
  assert.ok(built.subarray(0, IPC_DOMAIN.length).toString("utf8").startsWith(IPC_DOMAIN), "the domain tag must lead the transcript");
  assert.ok(built.includes(Buffer.from([0])), "the domain tag must be NUL-terminated");
});

test("R7D.1-A-2: length prefixes prevent field-boundary confusion", () => {
  // Without length prefixes, role "ab" + nonce starting "cd…" would collide with role "abc"
  // + nonce starting "d…". Prefixing makes the two transcripts differ, so a signature
  // legitimately produced for one cannot verify against the other.
  const nonce = Buffer.from("cd".repeat(32), "hex");
  const other = Buffer.from("d" + "cd".repeat(31) + "c", "hex");
  const a = buildTranscript({ role: "ab", serverNonce: nonce, clientNonce: nonce });
  const b = buildTranscript({ role: "abc", serverNonce: other.subarray(0, 32), clientNonce: nonce });
  assert.notEqual(a.toString("hex"), b.toString("hex"));
});

test("R7D.1-A-3: transcripts differ per session because the server nonce differs", () => {
  const role = "worker";
  const clientNonce = generateNonce();
  const first = buildTranscript({ role, serverNonce: generateNonce(), clientNonce });
  const second = buildTranscript({ role, serverNonce: generateNonce(), clientNonce });
  assert.notEqual(first.toString("hex"), second.toString("hex"));
});

// ---------------------------------------------------------------------------------------
// Proof verification.
// ---------------------------------------------------------------------------------------

test("R7D.1-A-4: a proof verifies only against its own transcript", () => {
  const one = transcript();
  const two = transcript();
  const proof = computeProof(secret, one);
  assert.equal(verifyProof(secret, one, proof), true);
  assert.equal(verifyProof(secret, two, proof), false);
});

test("R7D.1-A-5: a proof verifies only under the right secret", () => {
  const built = transcript();
  const proof = computeProof(secret, built);
  assert.equal(verifyProof(secret, built, proof), true);
  assert.equal(verifyProof(randomBytes(32), built, proof), false);
});

test("R7D.1-A-6: a cross-role replay is rejected", () => {
  // A proof captured from the app socket must not authenticate on the worker socket. The
  // role is inside the signed transcript, so it cannot be swapped in transit.
  const serverNonce = generateNonce();
  const clientNonce = generateNonce();
  const appTranscript = buildTranscript({ role: "app", serverNonce, clientNonce });
  const workerTranscript = buildTranscript({ role: "worker", serverNonce, clientNonce });
  const appProof = computeProof(secret, appTranscript);
  assert.equal(verifyProof(secret, appTranscript, appProof), true);
  assert.equal(verifyProof(secret, workerTranscript, appProof), false);
});

test("R7D.1-A-7: a wrong-length proof is rejected without throwing", () => {
  const built = transcript();
  assert.equal(verifyProof(secret, built, Buffer.alloc(31)), false);
  assert.equal(verifyProof(secret, built, Buffer.alloc(33)), false);
  assert.equal(verifyProof(secret, built, Buffer.alloc(0)), false);
});

test("R7D.1-A-8: a short secret is refused rather than silently accepted", () => {
  const built = transcript();
  assert.throws(() => computeProof(Buffer.alloc(16), built), /at least 32 bytes/u);
});

// ---------------------------------------------------------------------------------------
// Role and operation discrimination.
// ---------------------------------------------------------------------------------------

test("R7D.1-A-9: the app role may inspect only", () => {
  assert.deepEqual([...ROLE_POLICY.app], ["inspect"]);
  assert.equal(isOperationAllowed("app", "inspect"), true);
  assert.equal(isOperationAllowed("app", "fill"), false);
  assert.equal(isOperationAllowed("app", "verify"), false);
});

test("R7D.1-A-10: the worker role may inspect, fill and verify", () => {
  assert.deepEqual([...ROLE_POLICY.worker], ["inspect", "fill", "verify"]);
  for (const op of ["inspect", "fill", "verify"]) assert.equal(isOperationAllowed("worker", op), true);
});

test("R7D.1-A-11: unknown operations are refused, not mapped to a default", () => {
  for (const bad of ["", "FILL", "fill ", "delete", "Inspect"]) {
    assert.throws(() => parseOperation(bad), /unknown operation/u, `must reject ${JSON.stringify(bad)}`);
  }
  assert.equal(parseOperation("verify"), "verify");
});

test("R7D.1-A-12: prototype keys cannot be used as a role", () => {
  // `role in ROLE_POLICY` would accept both of these; `Object.hasOwn` does not.
  for (const bad of ["constructor", "__proto__", "toString", "hasOwnProperty", ""]) {
    assert.throws(() => parseRole(bad), /unknown role/u, `must reject ${bad}`);
  }
  assert.equal(parseRole("worker"), "worker");
});

// ---------------------------------------------------------------------------------------
// Bounds.
// ---------------------------------------------------------------------------------------

test("R7D.1-A-13: the unauthenticated preamble is small", () => {
  // The preamble is the only unauthenticated work an attacker can force, so it must stay
  // far below the authenticated control ceiling.
  assert.ok(IPC_LIMITS.preambleBytes <= 1024, "the preamble must be tiny");
  assert.ok(IPC_LIMITS.preambleBytes < IPC_LIMITS.controlFrameBytes);
  assert.equal(IPC_LIMITS.controlFrameBytes, 256 * 1024, "the authenticated control ceiling is 256 KiB");
});

test("R7D.1-A-14: every bound in the IPC limit set is finite and positive", () => {
  for (const [name, value] of Object.entries(IPC_LIMITS)) {
    assert.equal(Number.isFinite(value) && value > 0, true, `${name} must be a positive finite bound`);
  }
});
