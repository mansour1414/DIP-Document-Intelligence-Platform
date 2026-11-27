/**
 * Mutual authentication for the Supervisor ↔ Watchdog control channel (Continuation D1, WD-02).
 *
 * ## The defect this replaces
 *
 * The server dispatched `ARM_REQ`, `HEARTBEAT` and `DISARM_REQ` straight from the decoded frame.
 * Signing the *reply* is not authentication of the *request*: any process that could connect to
 * the socket could arm a deadline, disarm a live execution, or read execution state. The HMAC on
 * the answer proved only that the watchdog had spoken, not that anyone had asked it anything.
 *
 * ## The protocol
 *
 * ```
 *   client ── HELLO { clientNonce, clientInstance } ─────────────▶ server
 *   client ◀── CHALLENGE { serverNonce, serverInstance, bootId, pid } ── server
 *   client ── AUTH { proof("client-to-watchdog" over both nonces + instances) } ──▶ server
 *   client ◀── AUTH_OK { proof("watchdog-to-client" over the same transcript) } ── server
 *   ── thereafter every request carries its own proof and its own nonce ──
 * ```
 *
 * ## Why each element is there
 *
 * - **Fresh per-connection challenge.** Both sides contribute a 32-byte nonce, so neither can
 *   force a transcript it has seen before. A replayed `HELLO` gets a different `CHALLENGE` and
 *   cannot produce an `AUTH` proof for it.
 * - **Direction separation.** The transcript begins with a direction tag. A proof computed for
 *   `client-to-watchdog` cannot be presented as `watchdog-to-client`, so a peer cannot echo an
 *   authentication proof back as an acknowledgement and have it accepted.
 * - **Type binding.** The message kind is in the transcript. A `DISARM` proof cannot be re-labelled
 *   as an `ARM`.
 * - **Payload digest binding.** The transcript covers a SHA-256 of the exact serialized payload.
 *   A request cannot be altered in transit, and a proof for one payload cannot authorize another.
 * - **Per-request nonce.** Every authenticated request carries its own nonce, remembered until it
 *   expires, so a captured request cannot be replayed even inside its connection.
 *
 * ## What this does not do
 *
 * It does not make the socket's file permissions irrelevant. `SO_PEERCRED` verification of the
 * connecting process is a further layer that requires reading `SO_PEERCRED` from the accepted
 * socket and comparing it against an allowlist; that is not implemented here and is listed as a
 * remaining control. Authentication here proves possession of the shared secret, which is enough
 * to refuse every unauthenticated caller but does not by itself establish *which* authorized
 * process connected.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/** Domain tag for the control channel. Distinct from the terminal transcripts, deliberately. */
export const WATCHDOG_AUTH_DOMAIN = "dip-watchdog-control-v2";

/** Direction of a proof. A proof in one direction never verifies in the other. */
export type AuthDirection = "client-to-watchdog" | "watchdog-to-client";

/** Message kinds that carry their own proof. `HELLO`, `CHALLENGE` and `AUTH` are the handshake. */
export type AuthenticatedKind =
  | "AUTH"
  | "AUTH_OK"
  | "ARM_REQ"
  | "DISARM_REQ"
  | "HEARTBEAT"
  | "STATE_REQ";

/** Nonce width. 32 bytes, the same as the terminal transcripts. */
const NONCE_BYTES = 32;

/** Minimum key length. HMAC-SHA256 accepts shorter, but a short shared secret is a guessable one. */
const MIN_SECRET_BYTES = 32;

/** Produce a fresh nonce. */
export function newAuthNonce(): string {
  return randomBytes(NONCE_BYTES).toString("hex");
}

/**
 * The transcript.
 *
 * Length-prefixed so that no field can be shifted into another: without prefixes,
 * `("ab", "c")` and `("a", "bc")` produce the same bytes and two different messages would share a
 * proof.
 */
function transcript(input: {
  direction: AuthDirection;
  kind: AuthenticatedKind;
  clientNonce: string;
  serverNonce: string;
  clientInstance: string;
  serverInstance: string;
  bootId: string;
  requestNonce: string;
  payloadSha256: string;
}): Buffer {
  const parts: Buffer[] = [Buffer.from(`${WATCHDOG_AUTH_DOMAIN}\0`, "utf8")];
  const push = (value: string): void => {
    const bytes = Buffer.from(value, "utf8");
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.byteLength, 0);
    parts.push(length, bytes);
  };
  push(input.direction);
  push(input.kind);
  push(input.clientNonce);
  push(input.serverNonce);
  push(input.clientInstance);
  push(input.serverInstance);
  push(input.bootId);
  push(input.requestNonce);
  push(input.payloadSha256);
  return Buffer.concat(parts);
}

/** SHA-256 of a payload, which is what binds a proof to exact content. */
export function payloadDigest(payload: unknown): string {
  // A canonical serialization is required: `JSON.stringify` over an object with the same keys in a
  // different order produces different bytes, and the proof would then depend on insertion order.
  return createHash("sha256").update(canonicalJson(payload), "utf8").digest("hex");
}

/**
 * Deterministic JSON with sorted keys.
 *
 * Two peers must serialize the same payload to the same bytes or the digests disagree and every
 * request fails signature verification for a reason that looks like tampering.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, entry]) => entry !== undefined)
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
  return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`).join(",")}}`;
}

/** Compute a proof for one message. */
export function computeAuthProof(secret: Buffer, input: Parameters<typeof transcript>[0]): string {
  if (secret.byteLength < MIN_SECRET_BYTES) throw new Error("the control secret is shorter than the minimum");
  return createHmac("sha256", secret).update(transcript(input)).digest("hex");
}

/**
 * Verify a proof in constant time.
 *
 * A malformed proof returns `false` rather than throwing: a peer that sends nonsense is an
 * authentication failure, not a server error, and the difference must not be visible to it.
 */
export function verifyAuthProof(secret: Buffer, input: Parameters<typeof transcript>[0], presented: string): boolean {
  if (secret.byteLength < MIN_SECRET_BYTES) return false;
  if (typeof presented !== "string" || !/^[a-f0-9]{64}$/u.test(presented)) return false;
  const expected = createHmac("sha256", secret).update(transcript(input)).digest();
  const received = Buffer.from(presented, "hex");
  if (expected.byteLength !== received.byteLength) return false;
  return timingSafeEqual(expected, received);
}

/** A per-connection authenticated session, as the server holds it. */
export type ServerSession = {
  clientNonce: string;
  serverNonce: string;
  clientInstance: string;
  serverInstance: string;
  bootId: string;
  authenticated: boolean;
  /** Request nonces already consumed on this connection. */
  consumedNonces: Set<string>;
  createdAtMs: number;
  /**
   * Authenticated supervisor identity.
   *
   * WD-F05: the supervisor instance that completed the handshake. Every request through this
   * connection is bound to it, so a connection authenticated by one supervisor cannot carry a
   * request that names another. It is set only at authentication and never re-derived from a
   * request payload.
   */
  boundSupervisor: string | null;
};

/** A per-connection session, as the client holds it. */
export type ClientSession = {
  clientNonce: string;
  serverNonce: string;
  clientInstance: string;
  serverInstance: string;
  bootId: string;
  authenticated: boolean;
  /** Outbound request nonces, so a client can detect its own collision. */
  issuedNonces: Set<string>;
};

/** Sent in reply to a failed handshake or a bad proof, then the connection is closed. */
export const AUTH_FAILED_CLOSE_MESSAGE = Object.freeze({ kind: "ERROR", code: "AUTH_FAILED" });

/** The handshake messages. Deliberately not the same type as the legacy frames. */
export type HelloMessage = { kind: "HELLO"; clientNonce: string; clientInstance: string; protocolVersion: 2 };
export type ChallengeMessage = {
  kind: "CHALLENGE";
  serverNonce: string;
  clientNonce: string;
  serverInstance: string;
  bootId: string;
  pid: number;
  protocolVersion: 2;
};
export type AuthMessage = { kind: "AUTH"; clientNonce: string; serverNonce: string; proof: string };
export type AuthOkMessage = {
  kind: "AUTH_OK";
  clientNonce: string;
  serverNonce: string;
  watchdogInstance: string;
  bootId: string;
  proof: string;
};

/** Validate a `HELLO`. Throws on anything that is not exactly the expected shape. */
export function assertHello(value: unknown): HelloMessage {
  if (typeof value !== "object" || value === null) throw new Error("HELLO is not an object");
  const record = value as Record<string, unknown>;
  if (record.kind !== "HELLO") throw new Error("not a HELLO");
  if (record.protocolVersion !== 2) throw new Error("HELLO declares an unsupported protocol version");
  if (typeof record.clientNonce !== "string" || !/^[a-f0-9]{64}$/u.test(record.clientNonce)) {
    throw new Error("HELLO clientNonce is not acceptable");
  }
  if (typeof record.clientInstance !== "string" || !/^[a-z0-9-]{4,64}$/u.test(record.clientInstance)) {
    throw new Error("HELLO clientInstance is not acceptable");
  }
  return { kind: "HELLO", clientNonce: record.clientNonce, clientInstance: record.clientInstance, protocolVersion: 2 };
}

/** Validate an `AUTH`. */
export function assertAuth(value: unknown): AuthMessage {
  if (typeof value !== "object" || value === null) throw new Error("AUTH is not an object");
  const record = value as Record<string, unknown>;
  if (record.kind !== "AUTH") throw new Error("not an AUTH");
  for (const field of ["clientNonce", "serverNonce"] as const) {
    if (typeof record[field] !== "string" || !/^[a-f0-9]{64}$/u.test(record[field] as string)) {
      throw new Error(`AUTH ${field} is not acceptable`);
    }
  }
  if (typeof record.proof !== "string" || !/^[a-f0-9]{64}$/u.test(record.proof)) {
    throw new Error("AUTH proof is not acceptable");
  }
  return {
    kind: "AUTH",
    clientNonce: record.clientNonce as string,
    serverNonce: record.serverNonce as string,
    proof: record.proof,
  };
}

/** Validate an authenticated request envelope. */
export function assertAuthenticatedRequest(value: unknown): {
  kind: AuthenticatedKind;
  requestNonce: string;
  payload: Record<string, unknown>;
  proof: string;
} {
  if (typeof value !== "object" || value === null) throw new Error("the request is not an object");
  const record = value as Record<string, unknown>;
  const allowed: AuthenticatedKind[] = ["ARM_REQ", "DISARM_REQ", "HEARTBEAT", "STATE_REQ"];
  if (typeof record.kind !== "string" || !(allowed as string[]).includes(record.kind)) {
    throw new Error(`the request kind ${String(record.kind)} is not authenticated`);
  }
  if (typeof record.requestNonce !== "string" || !/^[a-f0-9]{64}$/u.test(record.requestNonce)) {
    throw new Error("the request nonce is not acceptable");
  }
  if (typeof record.proof !== "string" || !/^[a-f0-9]{64}$/u.test(record.proof)) {
    throw new Error("the request proof is not acceptable");
  }
  if (typeof record.payload !== "object" || record.payload === null || Array.isArray(record.payload)) {
    throw new Error("the request payload is not an object");
  }
  return {
    kind: record.kind as AuthenticatedKind,
    requestNonce: record.requestNonce,
    payload: record.payload as Record<string, unknown>,
    proof: record.proof,
  };
}
