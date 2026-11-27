/**
 * Authenticated role-specific Unix sockets (R7D.1 §9).
 *
 * ## What this authenticates, and what it does not
 *
 * It authenticates **possession of a scoped credential**. It does not authenticate OS peer
 * identity: a process that can read the worker's credential file can impersonate the worker,
 * and no amount of HMAC handshaking changes that. Filesystem permissions and separate groups
 * are what make that hard; the handshake is what makes an *already-legitimate* connection
 * unforgeable and replay-resistant. Both are needed and neither is sufficient.
 *
 * ## The transcript
 *
 * Both sides sign a **domain-separated, length-prefixed** transcript:
 *
 *     "dip-ipc-v1\0" || u32 len(role) || role || u32 len(serverNonce) || serverNonce
 *                   || u32 len(clientNonce) || clientNonce
 *
 * Length-prefixing is not decoration. Concatenating `"app" + "worker"` and
 * `"appwork" + "er"` produces the same bytes, so an unprefixed transcript lets a peer move
 * a field boundary and have a signature it legitimately produced for one message verify
 * against another. Domain separation stops a signature made for one protocol (or one
 * purpose) being replayed into this one.
 *
 * ## Why the server sends the nonce
 *
 * The challenge is generated **fresh per connection** by the server and must be unique. A
 * client-chosen nonce lets an attacker replay a captured client nonce against a new server
 * session; a server-chosen one makes every session's transcript distinct. The server does
 * not accept a connection whose transcript it did not originate.
 *
 * ## Constant-time comparison
 *
 * `timingSafeEqual` on equal-length buffers, with the length checked first. Comparing
 * digests rather than raw MACs would also work, but comparing the MACs directly is simpler
 * and `timingSafeEqual` already requires identical lengths.
 */

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/** Version tag mixed into every transcript. Bumping it invalidates old signatures. */
export const IPC_DOMAIN = "dip-ipc-v1";

/** Roles, and the operations each may invoke. */
export const ROLE_POLICY = Object.freeze({
  /** The web/API process. Inspect only — it renders forms, it does not fill them. */
  app: Object.freeze(["inspect"] as const),
  /** The document worker. Inspect, fill and verify. */
  worker: Object.freeze(["inspect", "fill", "verify"] as const),
});

export type IpcRole = keyof typeof ROLE_POLICY;
export type IpcOperation = "inspect" | "fill" | "verify";

/** Wire-level constants. Every one is a bound, not a suggestion. */
export const IPC_LIMITS = Object.freeze({
  /**
   * Unauthenticated preamble bytes accepted before the handshake completes.
   *
   * Small on purpose: the preamble is the only thing an unauthenticated peer can make the
   * server do work for, so it must be too small to be worth exploiting.
   */
  preambleBytes: 512,
  /** Largest authenticated control frame after the handshake. */
  controlFrameBytes: 256 * 1024,
  /** Concurrent connections per role socket. */
  maxConnectionsPerRole: 16,
  /** Authentication attempts per connection before the socket is closed. */
  maxAuthAttempts: 3,
  /** How long a connection may sit idle, in either state. */
  idleTimeoutMs: 5_000,
  /** How long the handshake may take from accept to authenticated. */
  authTimeoutMs: 2_000,
  /** Distinct active execution ids a single authenticated connection may hold. */
  maxActiveExecutionsPerConnection: 4,
});

/** Nonce width. 32 bytes is the block size of SHA-256 and far past guessing. */
const NONCE_BYTES = 32;

export function generateNonce(): Buffer {
  return randomBytes(NONCE_BYTES);
}

/**
 * Encode the signed transcript.
 *
 * Exported so the test suite can assert the exact byte layout, including the property that
 * moving a field boundary changes the bytes.
 */
export function buildTranscript(parts: { role: string; serverNonce: Buffer; clientNonce: Buffer }): Buffer {
  const role = Buffer.from(parts.role, "utf8");
  const chunks: Buffer[] = [Buffer.from(`${IPC_DOMAIN}\0`, "utf8")];
  for (const field of [role, parts.serverNonce, parts.clientNonce]) {
    const length = Buffer.alloc(4);
    length.writeUInt32BE(field.byteLength, 0);
    chunks.push(length, field);
  }
  return Buffer.concat(chunks);
}

/** Compute the expected proof for a transcript under a shared secret. */
export function computeProof(secret: Buffer, transcript: Buffer): Buffer {
  if (secret.byteLength < 32) {
    // A short secret is not a policy the caller can negotiate; it is a mistake worth
    // failing on. 32 bytes is the minimum key length for HMAC-SHA256.
    throw new Error("IPC secret must be at least 32 bytes");
  }
  return createHmac("sha256", secret).update(transcript).digest();
}

/**
 * Constant-time verification of a peer's proof.
 *
 * Returns `false` rather than throwing on length mismatch, because a malformed proof is an
 * authentication failure, not an exception: it must be counted against the attempt budget
 * and reported the same way a wrong proof is.
 */
export function verifyProof(secret: Buffer, transcript: Buffer, presented: Buffer): boolean {
  if (presented.byteLength !== 32) return false;
  const expected = computeProof(secret, transcript);
  return timingSafeEqual(expected, presented);
}

/**
 * Decide whether a role may invoke an operation.
 *
 * Separate from authentication on purpose. A properly authenticated `app` connection asking
 * for `fill` is not a handshake failure — it is an authorization failure, and the two must
 * be reported differently so a credential leak is distinguishable from a bug in the caller.
 */
export function isOperationAllowed(role: IpcRole, operation: string): boolean {
  const allowed: readonly string[] = ROLE_POLICY[role];
  return allowed.includes(operation);
}

/**
 * Strict operation discrimination.
 *
 * Rejects anything that is not exactly one of the three known operations. A `switch` with a
 * default that falls through to `inspect` would let an unknown operation inherit inspect's
 * permissions, which is the sort of default that turns a typo into an authorization bypass.
 */
export function parseOperation(value: unknown): IpcOperation {
  if (value === "inspect" || value === "fill" || value === "verify") return value;
  throw new Error("unknown operation");
}

/**
 * Validate a role name read from the wire.
 *
 * Rejects prototype keys: `ROLE_POLICY["constructor"]` would otherwise be truthy and
 * `ROLE_POLICY["__proto__"]` resolves to an object, so a naive `role in ROLE_POLICY` check
 * accepts both.
 */
export function parseRole(value: unknown): IpcRole {
  // `Object.hasOwn` rather than `in`, precisely because of the prototype keys above.
  if (typeof value === "string" && Object.hasOwn(ROLE_POLICY, value)) return value as IpcRole;
  throw new Error("unknown role");
}
