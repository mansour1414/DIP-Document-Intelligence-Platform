/**
 * Verification of the authenticated terminal chain (R7D.1, C-F02).
 *
 * ## The chain
 *
 * ```
 *   Watchdog ──DISARM_GRANTED (HMAC, watchdog key)──▶ Supervisor
 *   Supervisor ──TERMINAL_COMMIT (HMAC, caller key)──▶ Trusted caller
 * ```
 *
 * Two signatures, two keys, two directions. The caller never sees the watchdog's key and cannot
 * mint a watchdog grant; the supervisor never sees the caller's key and cannot mint a commit the
 * caller would accept. Each link verifies only its own end, which is what stops either side from
 * being the sole authority over publication.
 *
 * ## Why the caller verifies rather than trusting the supervisor
 *
 * A supervisor that has been compromised, or that has a bug, can send anything it likes. If the
 * caller accepted "the supervisor said OK", the security boundary would be the supervisor's good
 * behaviour rather than the caller's verification. The commit binds the result digest, both
 * identities, the operation and the container outcome, so the caller can refuse a commit that
 * does not describe the bytes it actually holds.
 *
 * ## What neither signature proves
 *
 * That the container was isolated, that its limits were enforced, or that the document renders
 * correctly. Those are separate claims with separate evidence and none is established by an HMAC.
 */

import {
  assertTerminalContext,
  computeTerminalProof,
  verifyTerminalProof,
  type TerminalContext,
  type TerminalCommitMessage,
  type TerminalGrantMessage,
  type TerminalOutcome,
  type TerminalRequest,
} from "./terminal-auth";
import type { VerifiedTerminalCommit } from "./provisional-stream";

/** A refusal to authorize. Closed codes, because the caller branches on them. */
export type CommitFailure =
  | { ok: false; code: "MISSING_GRANT" }
  | { ok: false; code: "BAD_WATCHDOG_PROOF"; detail: string }
  | { ok: false; code: "GRANT_MISMATCH"; detail: string }
  | { ok: false; code: "NOT_ELIGIBLE"; detail: string }
  | { ok: false; code: "BAD_COMMIT_PROOF"; detail: string };

export type CommitResult =
  | { ok: true; commit: VerifiedTerminalCommit; message: TerminalCommitMessage }
  | CommitFailure;

/** What the supervisor knows independently, against which the grant is checked. */
export type CommitExpectation = {
  executionId: string;
  requestId: string;
  operation: "inspect" | "fill" | "verify";
  /** Digest of the validated result frame the supervisor actually accepted. */
  resultDigest: string;
  resultBytes: number;
  metaBytes: number;
  containerId: string;
  containerName: string;
  bootId: string;
  supervisorInstance: string;
  watchdogInstance: string;
};

/**
 * Verify the Watchdog's grant.
 *
 * Signature first, then the binding. The order matters for the error a caller sees: a bad
 * signature is an authentication failure, while a valid signature over a mismatched context is
 * either a bug or a replay attempt, and those are different incidents.
 */
export function verifyWatchdogGrant(
  watchdogSecret: Buffer,
  expectation: CommitExpectation,
  grant: TerminalGrantMessage | null,
  nowMonotonicMs: number,
): CommitResult | CommitFailure {
  if (grant === null) return { ok: false, code: "MISSING_GRANT" };

  let granted: TerminalRequest;
  try {
    granted = assertTerminalContext(grant.context, "watchdog grant context");
  } catch (error) {
    return { ok: false, code: "BAD_WATCHDOG_PROOF", detail: error instanceof Error ? error.message : "invalid context" };
  }

  // The grant must name the watchdog this supervisor armed, or a different watchdog's valid
  // signature would authorize this execution.
  if (grant.watchdogInstance !== expectation.watchdogInstance || granted.watchdogInstance !== expectation.watchdogInstance) {
    return { ok: false, code: "BAD_WATCHDOG_PROOF", detail: "the grant came from a different watchdog instance" };
  }

  const context: TerminalContext = { ...granted, direction: "watchdog-to-supervisor" };
  if (!verifyTerminalProof(watchdogSecret, context, grant.proof)) {
    return { ok: false, code: "BAD_WATCHDOG_PROOF", detail: "the watchdog proof did not verify" };
  }

  // Signature is genuine. Now: is it about *this* execution and *these* bytes?
  const mismatch = bindGrant(expectation, granted);
  if (mismatch !== null) return { ok: false, code: "GRANT_MISMATCH", detail: mismatch };

  // Only a committed execution with a positively removed container may publish.
  if (granted.outcome !== "committed") {
    return { ok: false, code: "NOT_ELIGIBLE", detail: `outcome was ${granted.outcome}` };
  }
  if (!granted.containerRemoved) {
    return { ok: false, code: "NOT_ELIGIBLE", detail: "the container was not confirmed removed" };
  }

  return {
    ok: true,
    commit: {
      executionId: granted.executionId,
      requestId: granted.requestId,
      operation: granted.operation,
      resultDigest: granted.resultDigest,
      resultBytes: granted.resultBytes,
      metaBytes: granted.metaBytes,
      outcome: granted.outcome,
      containerRemoved: granted.containerRemoved,
      watchdogInstance: granted.watchdogInstance,
      verifiedAtMonotonicMs: nowMonotonicMs,
    },
    message: {
      // The commit echoes the same context but is signed in the other direction, so a caller
      // cannot present a grant it captured as if it were a commit.
      context: granted,
      proof: "",
      watchdogInstance: granted.watchdogInstance,
    },
  };
}

/**
 * Bind a verified grant to what the supervisor knows.
 *
 * Every field is compared. A valid signature over the wrong context is exactly what a replay
 * looks like, so signature verification alone is not enough to authorize publication.
 */
function bindGrant(expectation: CommitExpectation, granted: TerminalRequest): string | null {
  if (granted.executionId !== expectation.executionId) return "a different execution";
  if (granted.requestId !== expectation.requestId) return "a different request";
  if (granted.operation !== expectation.operation) return "a different operation";
  if (granted.resultDigest !== expectation.resultDigest) return "a different result digest";
  if (granted.resultBytes !== expectation.resultBytes) return "a different result length";
  if (granted.metaBytes !== expectation.metaBytes) return "different metadata length";
  if (granted.containerId !== expectation.containerId) return "a different container";
  if (granted.containerName !== expectation.containerName) return "a different container name";
  if (granted.bootId !== expectation.bootId) return "a different boot";
  if (granted.supervisorInstance !== expectation.supervisorInstance) return "a different supervisor instance";
  return null;
}

/**
 * Issue the commit the caller will verify.
 *
 * Signed under the caller's key in the caller's direction, so the supervisor cannot produce a
 * message the caller would accept for a different caller, and a captured commit cannot be
 * re-signed by anything that does not hold that key.
 */
export function signTerminalCommit(
  callerSecret: Buffer,
  commit: VerifiedTerminalCommit,
  expectation: CommitExpectation,
  nonce: string,
  concludedMonotonicMs: number,
): TerminalCommitMessage {
  const context: TerminalContext = {
    direction: "supervisor-to-caller",
    executionId: commit.executionId,
    requestId: commit.requestId,
    operation: commit.operation,
    resultDigest: commit.resultDigest,
    resultBytes: commit.resultBytes,
    metaBytes: commit.metaBytes,
    containerId: expectation.containerId,
    containerName: expectation.containerName,
    containerRemoved: commit.containerRemoved,
    outcome: commit.outcome,
    watchdogInstance: commit.watchdogInstance,
    supervisorInstance: expectation.supervisorInstance,
    bootId: expectation.bootId,
    nonce,
    concludedMonotonicMs,
  };
  return {
    context: stripDirection(context),
    proof: computeTerminalProof(callerSecret, context),
    watchdogInstance: commit.watchdogInstance,
  };
}

/**
 * Verify a commit, as the trusted caller does.
 *
 * The caller checks three things the supervisor cannot fake without the caller's key: the
 * signature, that the commit is about the execution the caller asked for, and that it describes
 * the bytes the caller is holding. Only then does it return a `VerifiedTerminalCommit` that
 * `collect` will accept.
 */
export function verifyTerminalCommit(
  callerSecret: Buffer,
  message: TerminalCommitMessage | null,
  expected: {
    executionId: string;
    requestId: string;
    operation: "inspect" | "fill" | "verify";
    resultDigest: string;
    resultBytes: number;
    metaBytes: number;
    bootId: string;
    supervisorInstance: string;
  },
  nowMonotonicMs: number,
): CommitResult {
  if (message === null) return { ok: false, code: "MISSING_GRANT" };

  let context: TerminalRequest;
  try {
    context = assertTerminalContext(message.context, "terminal commit context");
  } catch (error) {
    return { ok: false, code: "BAD_COMMIT_PROOF", detail: error instanceof Error ? error.message : "invalid context" };
  }

  const signed: TerminalContext = { ...context, direction: "supervisor-to-caller" };
  if (!verifyTerminalProof(callerSecret, signed, message.proof)) {
    return { ok: false, code: "BAD_COMMIT_PROOF", detail: "the commit proof did not verify" };
  }

  if (context.executionId !== expected.executionId) return { ok: false, code: "GRANT_MISMATCH", detail: "a different execution" };
  if (context.requestId !== expected.requestId) return { ok: false, code: "GRANT_MISMATCH", detail: "a different request" };
  if (context.operation !== expected.operation) return { ok: false, code: "GRANT_MISMATCH", detail: "a different operation" };
  if (context.resultDigest !== expected.resultDigest) return { ok: false, code: "GRANT_MISMATCH", detail: "a different result digest" };
  if (context.resultBytes !== expected.resultBytes) return { ok: false, code: "GRANT_MISMATCH", detail: "a different result length" };
  if (context.metaBytes !== expected.metaBytes) return { ok: false, code: "GRANT_MISMATCH", detail: "different metadata length" };
  if (context.bootId !== expected.bootId) return { ok: false, code: "GRANT_MISMATCH", detail: "a different boot" };
  if (context.supervisorInstance !== expected.supervisorInstance) return { ok: false, code: "GRANT_MISMATCH", detail: "a different supervisor instance" };
  if (context.outcome !== "committed") return { ok: false, code: "NOT_ELIGIBLE", detail: `outcome was ${context.outcome}` };
  if (!context.containerRemoved) return { ok: false, code: "NOT_ELIGIBLE", detail: "the container was not confirmed removed" };

  return {
    ok: true,
    commit: {
      executionId: context.executionId,
      requestId: context.requestId,
      operation: context.operation,
      resultDigest: context.resultDigest,
      resultBytes: context.resultBytes,
      metaBytes: context.metaBytes,
      outcome: context.outcome satisfies TerminalOutcome,
      containerRemoved: context.containerRemoved,
      watchdogInstance: context.watchdogInstance,
      verifiedAtMonotonicMs: nowMonotonicMs,
    },
    message,
  };
}

function stripDirection(context: TerminalContext): TerminalRequest {
  const { direction: _direction, ...rest } = context;
  return rest;
}
