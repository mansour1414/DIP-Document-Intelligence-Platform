/**
 * Authenticated terminal authorization (R7D.1, corrected per C-F02).
 *
 * ## The defect this replaces
 *
 * The provisional stream could issue its own terminal grant: it checked its own seal, set a
 * boolean, and then accepted the resulting object back as proof. That is a component vouching
 * for itself. The review named the three consequences directly — repeated calls could mint new
 * grants, provenance was not cryptographically verifiable, and `consumed` was caller-visible
 * mutable state that a caller could simply reset.
 *
 * ## The trust model now
 *
 * ```
 *   executor ──result frame──▶ supervisor          (untrusted bytes, validated framing)
 *                                  │
 *                                  │ authenticated DISARM_REQ  (full validated context)
 *                                  ▼
 *                             watchdog               (independent process, own event loop)
 *                                  │
 *                                  │ authenticated DISARM_GRANTED  (one-time, bound)
 *                                  ▼
 *   trusted caller ◀── TERMINAL_COMMIT ── supervisor (re-verifies the grant itself)
 * ```
 *
 * The supervisor does not *relay* the watchdog's grant as an opaque token. It verifies the
 * watchdog's HMAC over the exact context first, and then issues its own commit to the caller,
 * signed under the caller's connection transcript. A caller therefore checks a supervisor
 * signature, and the supervisor could only produce it after checking a watchdog signature.
 *
 * ## Why the grant binds everything it binds
 *
 * A grant saying "execution X succeeded" would be enough to publish whatever bytes happened to be
 * on hand. It would authorise a document that had been swapped, or one whose metadata had been
 * adjusted after the frame was validated. So the grant is computed over a transcript containing
 * the execution and request identity, the operation, the digest and length of the *validated*
 * result frame, the container identity and lifecycle outcome, and the watchdog's own instance and
 * deadline facts.
 *
 * ## Replay
 *
 * Grants are one-time by construction: each is consumed against the execution it names, and the
 * watchdog refuses a second disarm for an execution that has already granted. The nonce inside
 * the transcript is fresh per exchange, so an old transcript cannot be re-presented even if its
 * signature is genuine.
 */

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/** Domain separation. A signature from another protocol must not verify here. */
export const TERMINAL_DOMAIN = "dip-terminal-v1";

/** The protocol version the transcript binds. A downgrade is a version mismatch, not a fallback. */
export const TERMINAL_VERSION = 1;

/** Which side produced a proof, bound so a proof cannot be reflected back. */
export type TerminalDirection =
  | "supervisor-to-watchdog"      // DISARM_REQ
  | "watchdog-to-supervisor"      // DISARM_GRANTED / DENIED
  | "supervisor-to-caller";       // TERMINAL_COMMIT

/** How the execution ended. A closed vocabulary; the grant says which one was observed. */
export type TerminalOutcome = "committed" | "refused" | "timeout" | "cancelled" | "failed";

/**
 * Everything a terminal decision is bound to.
 *
 * Required throughout. An optional field is one a caller can forget, and a transcript missing a
 * field would silently authenticate less than this module documents.
 */
export type TerminalContext = {
  direction: TerminalDirection;
  /** Opaque execution id. */
  executionId: string;
  /** The caller's request id, so a commit cannot be applied to another request. */
  requestId: string;
  operation: "inspect" | "fill" | "verify";
  /**
   * Digest and length of the *validated* result frame — the exact byte sequence the supervisor
   * accepted, not the digest the executor claimed.
   */
  resultDigest: string;
  resultBytes: number;
  /** Metadata length, so the framing is bound too. */
  metaBytes: number;
  /** Exact container identity. An empty string where no container was ever created. */
  containerId: string;
  containerName: string;
  /** Whether the container was positively confirmed absent. */
  containerRemoved: boolean;
  outcome: TerminalOutcome;
  /** Watchdog instance that concluded, and its monotonic deadline reading. */
  watchdogInstance: string;
  /** Supervisor instance that asked. */
  supervisorInstance: string;
  /** Boot identity, so a grant from a previous boot cannot verify after a restart. */
  bootId: string;
  /** Fresh per exchange; makes every transcript unique. */
  nonce: string;
  /** Monotonic clock reading at conclusion, in milliseconds. */
  concludedMonotonicMs: number;
};

/** The wire form. A flat record, because it is signed as a length-prefixed sequence. */
export type TerminalRequest = Omit<TerminalContext, "direction">;

/** A watchdog grant, as the supervisor receives it. */
export type TerminalGrantMessage = {
  /** Echoes the request context, so the supervisor can verify it covers what it asked. */
  context: TerminalRequest;
  /** HMAC over the watchdog-direction transcript. */
  proof: string;
  /** The watchdog's own identity, so a grant from another instance is detectable. */
  watchdogInstance: string;
};

/** A watchdog refusal. Carries a closed code, never free text. */
export type TerminalDeniedMessage = {
  executionId: string;
  requestId: string;
  code: "EXPIRED" | "TERMINATED" | "CANCELLED" | "UNCERTAIN" | "ALREADY_CONCLUDED" | "UNKNOWN_EXECUTION" | "MISMATCH";
  watchdogInstance: string;
};

/** The commit the supervisor issues to a trusted caller. */
export type TerminalCommitMessage = {
  context: TerminalRequest;
  /** HMAC over the supervisor-to-caller transcript. */
  proof: string;
  /** Explicitly records that a watchdog grant was verified, not merely that output exists. */
  watchdogInstance: string;
};

const NONCE_BYTES = 32;
const MIN_SECRET_BYTES = 32;

export function generateTerminalNonce(): string {
  return randomBytes(NONCE_BYTES).toString("hex");
}

/**
 * Encode the signed transcript.
 *
 * Length-prefixed throughout, for the reason the IPC transcript is: concatenating `"ab" + "c"`
 * and `"a" + "bc"` produce identical bytes, so without prefixes a peer can move a field boundary
 * and have a signature it legitimately produced for one message verify against another.
 */
export function buildTerminalTranscript(context: TerminalContext): Buffer {
  if (context.direction !== "supervisor-to-watchdog"
    && context.direction !== "watchdog-to-supervisor"
    && context.direction !== "supervisor-to-caller") {
    throw new Error("unknown terminal direction");
  }
  const parts: Buffer[] = [Buffer.from(`${TERMINAL_DOMAIN}\0`, "utf8")];
  const push = (value: string | number | boolean): void => {
    const bytes = Buffer.from(String(value), "utf8");
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.byteLength, 0);
    parts.push(length, bytes);
  };
  push(context.direction);
  push(TERMINAL_VERSION);
  push(context.executionId);
  push(context.requestId);
  push(context.operation);
  push(context.resultDigest);
  push(context.resultBytes);
  push(context.metaBytes);
  push(context.containerId);
  push(context.containerName);
  push(context.containerRemoved);
  push(context.outcome);
  push(context.watchdogInstance);
  push(context.supervisorInstance);
  push(context.bootId);
  push(context.nonce);
  push(context.concludedMonotonicMs);
  return Buffer.concat(parts);
}

/** Compute a proof. A short secret is a mistake worth failing on, not a policy to negotiate. */
export function computeTerminalProof(secret: Buffer, context: TerminalContext): string {
  if (secret.byteLength < MIN_SECRET_BYTES) throw new Error("terminal secret must be at least 32 bytes");
  return createHmac("sha256", secret).update(buildTerminalTranscript(context)).digest("hex");
}

/**
 * Verify a peer's proof in constant time.
 *
 * Returns `false` on a malformed proof rather than throwing: a bad signature is an
 * authentication failure to be counted, not a crash.
 */
export function verifyTerminalProof(secret: Buffer, context: TerminalContext, presented: string): boolean {
  if (typeof presented !== "string" || !/^[a-f0-9]{64}$/u.test(presented)) return false;
  const expected = computeTerminalProof(secret, context);
  const left = Buffer.from(expected, "hex");
  const right = Buffer.from(presented, "hex");
  if (left.byteLength !== right.byteLength) return false;
  return timingSafeEqual(left, right);
}

/**
 * Validate the shape of a context arriving from a peer.
 *
 * Every field is checked because this record is used to authorize publishing a document. A
 * missing or malformed field is not a cosmetic problem: `resultBytes: 0` would authorize an
 * empty document.
 */
export function assertTerminalContext(value: unknown, what = "terminal context"): TerminalRequest {
  const fail = (detail: string): never => {
    throw new Error(`${what} is invalid: ${detail}`);
  };
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("not an object");
  const record = value as Record<string, unknown>;

  const hex = (name: string, min: number, max: number): string => {
    const raw = record[name];
    if (typeof raw !== "string" || !new RegExp(`^[a-f0-9]{${min},${max}}$`, "u").test(raw)) fail(`${name} is not hex`);
    return raw as string;
  };
  const text = (name: string, pattern: RegExp): string => {
    const raw = record[name];
    if (typeof raw !== "string" || !pattern.test(raw)) fail(`${name} is not acceptable`);
    return raw as string;
  };
  const positive = (name: string): number => {
    const raw = record[name];
    if (typeof raw !== "number" || !Number.isSafeInteger(raw) || raw < 0) fail(`${name} is not a non-negative integer`);
    return raw as number;
  };

  const operation = record.operation;
  if (operation !== "inspect" && operation !== "fill" && operation !== "verify") fail("operation is not supported");

  // A cgroup path may not climb. Recovery joins this path into filesystem operations, and a
  // component that walks upward would let a record point at a directory it does not own.
  const cgroupPath = record.cgroupPath;
  if (cgroupPath !== undefined) {
    if (typeof cgroupPath !== "string" || cgroupPath.split("/").includes("..")) fail("cgroupPath may not traverse");
  }

  const outcome = record.outcome;
  if (outcome !== "committed" && outcome !== "refused" && outcome !== "timeout"
    && outcome !== "cancelled" && outcome !== "failed") {
    fail("outcome is not in the closed set");
  }
  if (typeof record.containerRemoved !== "boolean") fail("containerRemoved is not a boolean");

  return {
    executionId: hex("executionId", 32, 32),
    requestId: hex("requestId", 16, 64),
    operation: operation as TerminalRequest["operation"],
    resultDigest: hex("resultDigest", 64, 64),
    resultBytes: positive("resultBytes"),
    metaBytes: positive("metaBytes"),
    containerId: text("containerId", /^$|^[a-f0-9]{64}$/u),
    containerName: text("containerName", /^dip-exec-[a-f0-9]{32}$/u),
    containerRemoved: record.containerRemoved as boolean,
    outcome: outcome as TerminalOutcome,
    watchdogInstance: text("watchdogInstance", /^[a-z0-9-]{4,64}$/u),
    supervisorInstance: text("supervisorInstance", /^[a-z0-9-]{4,64}$/u),
    bootId: text("bootId", /^[a-z0-9-]{4,64}$/u),
    nonce: hex("nonce", 16, 128),
    concludedMonotonicMs: positive("concludedMonotonicMs"),
  };
}

/**
 * Why a commit may not be accepted.
 *
 * Kept as a closed set so the caller can log a code rather than parse a message, and so the
 * supervisor's refusal is testable.
 */
export type CommitRejection =
  | "NO_GRANT"
  | "GRANT_INVALID"
  | "GRANT_EXECUTION_MISMATCH"
  | "GRANT_REQUEST_MISMATCH"
  | "GRANT_DIGEST_MISMATCH"
  | "GRANT_LENGTH_MISMATCH"
  | "GRANT_NOT_REMOVED"
  | "GRANT_OUTCOME_NOT_COMMITTED"
  | "GRANT_BOOT_MISMATCH"
  | "GRANT_ALREADY_USED";

/** What the supervisor knows, against which a grant is checked. */
export type ExpectedCommit = {
  executionId: string;
  requestId: string;
  operation: "inspect" | "fill" | "verify";
  resultDigest: string;
  resultBytes: number;
  metaBytes: number;
  containerId: string;
  containerName: string;
  bootId: string;
  supervisorInstance: string;
};

/**
 * Check that a verified grant actually authorizes *this* result.
 *
 * Signature verification proves the watchdog said something; it does not prove the watchdog said
 * it about these bytes. Every field is compared against what the supervisor independently knows,
 * because a valid signature over the wrong context is exactly what a replay looks like.
 */
export function checkGrantAgainst(expected: ExpectedCommit, granted: TerminalRequest): CommitRejection | null {
  if (granted.executionId !== expected.executionId) return "GRANT_EXECUTION_MISMATCH";
  if (granted.requestId !== expected.requestId) return "GRANT_REQUEST_MISMATCH";
  if (granted.operation !== expected.operation) return "GRANT_EXECUTION_MISMATCH";
  if (granted.resultDigest !== expected.resultDigest) return "GRANT_DIGEST_MISMATCH";
  if (granted.resultBytes !== expected.resultBytes) return "GRANT_LENGTH_MISMATCH";
  if (granted.metaBytes !== expected.metaBytes) return "GRANT_LENGTH_MISMATCH";
  if (granted.containerId !== expected.containerId) return "GRANT_EXECUTION_MISMATCH";
  if (granted.containerName !== expected.containerName) return "GRANT_EXECUTION_MISMATCH";
  if (granted.bootId !== expected.bootId) return "GRANT_BOOT_MISMATCH";
  if (granted.supervisorInstance !== expected.supervisorInstance) return "GRANT_EXECUTION_MISMATCH";
  if (!granted.containerRemoved) return "GRANT_NOT_REMOVED";
  // Only a committed execution authorizes publication. A refusal is a perfectly good terminal
  // outcome and it must not release a document — this is the line the boolean grant could not
  // express, because "the caller said true" has no opinion about what happened.
  if (granted.outcome !== "committed") return "GRANT_OUTCOME_NOT_COMMITTED";
  return null;
}
