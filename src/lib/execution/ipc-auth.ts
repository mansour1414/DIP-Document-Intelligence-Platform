/**
 * Authenticated role-specific Unix sockets (R7D.1, corrected per review F05).
 *
 * ## What this authenticates, and what it does not
 *
 * It authenticates **possession of a scoped credential**, and it binds that authentication to
 * the exact exchange being authorized. It does not authenticate OS peer identity: a process
 * that can read the worker's credential file can impersonate the worker. Filesystem
 * permissions and separate groups are what make that hard; the transcript is what makes an
 * already-legitimate connection unforgeable and replay-resistant. Both are needed.
 *
 * The tests below this module prove the cryptographic and transcript properties. They do
 * **not** prove socket-level authentication, because there is no socket yet — that belongs to
 * the supervisor increment, and describing helper tests as proof of the socket lifecycle would
 * be exactly the overclaim the review asked to avoid.
 *
 * ## What the transcript binds, and why each field is there
 *
 * The first version bound only the role and two nonces. A signature over that says "someone
 * holding the credential participated in a session with this role", which is far weaker than it
 * sounds: it does not say *which* operation was authorized, *over what bytes*, or *for which
 * request*, so a captured proof from an inspect could be re-used to authorize a fill.
 *
 * The transcript now covers:
 *
 * | Field | Why |
 * | --- | --- |
 * | domain tag | stops a signature from another protocol or purpose verifying here |
 * | direction | stops a server proof being reflected back as a client proof |
 * | protocol version | stops a downgrade to a weaker transcript |
 * | supervisor instance | pins the session to one control-plane incarnation |
 * | boot id | stops a proof from a previous boot being replayed after a restart |
 * | server nonce | fresh per connection; makes every session's transcript unique |
 * | client nonce | binds the client's own contribution, so neither side picks both |
 * | role | stops cross-role use |
 * | request id | binds the authorization to one exchange |
 * | operation | stops re-use across operations |
 * | reservation id | binds the exchange to admitted capacity |
 * | control length + digest | stops the control frame being swapped |
 * | body length + digest | stops the document being swapped |
 *
 * ## Why length prefixes
 *
 * Concatenating `"app" + "worker"` and `"appwork" + "er"` produces identical bytes. Without
 * prefixes, a peer can move a field boundary and have a signature it legitimately produced for
 * one message verify against another. Every variable-length field is preceded by its u32 length.
 *
 * ## One-time challenge consumption
 *
 * A nonce may authorize exactly one transcript. `ChallengeRegistry` enforces that, because
 * without it a captured proof remains valid for the lifetime of the session rather than for the
 * single exchange it was produced for.
 */

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/** Version tag mixed into every transcript. Bumping it invalidates old signatures. */
export const IPC_DOMAIN = "dip-ipc-v1";

/** The protocol version the transcript binds. */
export const IPC_PROTOCOL_VERSION = 1;

/** Which side produced a proof. Bound into the transcript so a proof cannot be reflected. */
export type ProofDirection = "client-to-server" | "server-to-client";

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
  /** Distinct request ids remembered for replay rejection. */
  maxRememberedRequests: 1_024,
  /**
   * Bytes a single connection may have buffered for a peer that is not draining.
   *
   * ## Why a byte ceiling and not a promise
   *
   * `socket.write()` returns `false` when the kernel buffer is full and then buffers the rest in
   * this process. A producer that ignores that return value — as the streaming path did — turns a
   * bounded pipe into an unbounded queue, and the queue is charged to the supervisor's heap rather
   * than the peer's. The streaming contract bounds the *document*; this bounds the *transport*, and
   * without it the first bound is decorative.
   *
   * Sized above one maximum control frame (256 KiB) so a legitimate large frame is never refused,
   * and far below the profile's memory ceiling so a stalled peer cannot approach it.
   */
  maxSendBufferBytes: 1024 * 1024,
});

/** Nonce width. 32 bytes is the SHA-256 block size and far past guessing. */
const NONCE_BYTES = 32;

/** The minimum secret length HMAC-SHA256 accepts as a key. */
const MIN_SECRET_BYTES = 32;

export function generateNonce(): Buffer {
  return randomBytes(NONCE_BYTES);
}

/**
 * Everything a proof is bound to.
 *
 * Required rather than optional throughout: an optional field is one a caller can forget, and a
 * transcript missing a field silently authenticates less than the protocol claims.
 */
export type TranscriptInput = {
  direction: ProofDirection;
  protocolVersion: number;
  supervisorInstance: string;
  bootId: string;
  serverNonce: Buffer;
  clientNonce: Buffer;
  role: IpcRole;
  requestId: string;
  operation: IpcOperation;
  /** Present when the exchange is bound to admitted capacity. */
  reservationId: string | null;
  controlLength: number;
  controlSha256: string;
  bodyLength: number;
  bodySha256: string;
};

/**
 * Encode the signed transcript.
 *
 * Fixed-order length-prefixed fields. Exported so the suite can assert the byte layout,
 * including the property that moving a field boundary changes the bytes.
 */
export function buildTranscript(input: TranscriptInput): Buffer {
  // The direction is a closed union in the type system, but a peer's value reaches this
  // function as data. A made-up direction must not produce a signable transcript, or the
  // reflection defence would be a convention rather than a rule.
  if (input.direction !== "client-to-server" && input.direction !== "server-to-client") {
    throw new Error("unknown proof direction");
  }
  if (!Number.isSafeInteger(input.protocolVersion) || input.protocolVersion !== IPC_PROTOCOL_VERSION) {
    // Binding a version this code does not speak would sign a transcript whose meaning is not
    // defined here. Rejecting is how a downgrade stays impossible instead of merely unlikely.
    throw new Error("unsupported protocol version");
  }
  const chunks: Buffer[] = [];
  const push = (field: Buffer): void => {
    const length = Buffer.alloc(4);
    length.writeUInt32BE(field.byteLength, 0);
    chunks.push(length, field);
  };
  const pushText = (value: string): void => push(Buffer.from(value, "utf8"));

  // The domain tag is the only fixed-prefix element, and it is NUL-terminated so it cannot run
  // into the first length prefix.
  chunks.push(Buffer.from(`${IPC_DOMAIN}\0`, "utf8"));
  pushText(input.direction);
  pushText(String(input.protocolVersion));
  pushText(input.supervisorInstance);
  pushText(input.bootId);
  push(input.serverNonce);
  push(input.clientNonce);
  pushText(input.role);
  pushText(input.requestId);
  pushText(input.operation);
  // A sentinel rather than an empty field, so "absent" and "present but empty" differ.
  pushText(input.reservationId ?? "\u0000none");
  pushText(String(input.controlLength));
  pushText(input.controlSha256);
  pushText(String(input.bodyLength));
  pushText(input.bodySha256);
  return Buffer.concat(chunks);
}

/** Compute the expected proof for a transcript under a shared secret. */
export function computeProof(secret: Buffer, transcript: Buffer): Buffer {
  if (secret.byteLength < MIN_SECRET_BYTES) {
    // A short secret is not a policy the caller can negotiate; it is a mistake worth failing on.
    throw new Error(`IPC secret must be at least ${MIN_SECRET_BYTES} bytes`);
  }
  return createHmac("sha256", secret).update(transcript).digest();
}

/**
 * Constant-time verification of a peer's proof.
 *
 * Returns `false` rather than throwing on length mismatch: a malformed proof is an
 * authentication failure, to be counted against the attempt budget like any other.
 */
export function verifyProof(secret: Buffer, transcript: Buffer, presented: Buffer): boolean {
  if (presented.byteLength !== 32) return false;
  const expected = computeProof(secret, transcript);
  return timingSafeEqual(expected, presented);
}

/**
 * One-time challenge registry.
 *
 * A nonce authorizes exactly one transcript. Without consumption, a proof captured from a
 * legitimate exchange stays valid for as long as the nonce is remembered, which turns a
 * one-time challenge into a password.
 *
 * Bounded: remembering every nonce forever is a memory leak an attacker controls. The oldest
 * entry is evicted, so the window is finite — which is correct, because a challenge older than
 * the authentication timeout should not be redeemable at all.
 */
export class ChallengeRegistry {
  private readonly issued = new Map<string, { consumed: boolean; issuedAtMs: number }>();
  private readonly capacity: number;
  private readonly now: () => number;

  constructor(options: { capacity?: number; now?: () => number } = {}) {
    this.capacity = options.capacity ?? 4_096;
    this.now = options.now ?? (() => Date.now());
  }

  /** Record a freshly issued challenge. */
  issue(nonce: Buffer): void {
    const key = nonce.toString("hex");
    this.issued.set(key, { consumed: false, issuedAtMs: this.now() });
    if (this.issued.size > this.capacity) {
      // Evict the oldest. Map preserves insertion order.
      const oldest = this.issued.keys().next();
      if (!oldest.done) this.issued.delete(oldest.value);
    }
  }

  /**
   * Consume a challenge, returning false if it was never issued, already used, or too old.
   *
   * Consumption happens before proof verification, so a wrong proof still burns the challenge.
   * The alternative lets an attacker retry proofs against one nonce inside the attempt budget.
   */
  consume(nonce: Buffer, maxAgeMs: number): boolean {
    const key = nonce.toString("hex");
    const entry = this.issued.get(key);
    if (!entry) return false;
    this.issued.delete(key);
    if (entry.consumed) return false;
    return this.now() - entry.issuedAtMs <= maxAgeMs;
  }

  get size(): number {
    return this.issued.size;
  }
}

/**
 * Decide whether a role may invoke an operation.
 *
 * Separate from authentication on purpose. A properly authenticated `app` connection asking for
 * `fill` is not a handshake failure — it is an authorization failure, and the two must be
 * reportable differently so a credential leak is distinguishable from a caller bug.
 */
export function isOperationAllowed(role: IpcRole, operation: string): boolean {
  const allowed: readonly string[] = ROLE_POLICY[role];
  return allowed.includes(operation);
}

/**
 * Strict operation discrimination.
 *
 * A `switch` whose default falls through to `inspect` lets a typo inherit inspect's permissions,
 * which is how an authorization bypass gets introduced by accident.
 */
export function parseOperation(value: unknown): IpcOperation {
  if (value === "inspect" || value === "fill" || value === "verify") return value;
  throw new Error("unknown operation");
}

/**
 * Validate a role name read from the wire.
 *
 * `Object.hasOwn` rather than `in`, because `ROLE_POLICY["constructor"]` is truthy and
 * `ROLE_POLICY["__proto__"]` resolves to an object, so a naive membership test accepts both.
 */
export function parseRole(value: unknown): IpcRole {
  if (typeof value === "string" && Object.hasOwn(ROLE_POLICY, value)) return value as IpcRole;
  throw new Error("unknown role");
}

/** Validate a request id: opaque hex, so it cannot carry a path or a payload. */
export function parseRequestId(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{16,64}$/u.test(value)) throw new Error("invalid request id");
  return value;
}

/** Validate an optional reservation id, using the same opaque-hex rule. */
export function parseReservationId(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== "string" || !/^[a-f0-9]{16,64}$/u.test(value)) throw new Error("invalid reservation id");
  return value;
}

/** Validate a SHA-256 digest as it appears on the wire. */
export function parseDigest(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/u.test(value)) throw new Error("invalid digest");
  return value;
}
