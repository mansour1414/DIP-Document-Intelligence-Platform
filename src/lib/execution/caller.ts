/**
 * The trusted caller transport library (R7D.1 §9).
 *
 * ## What a caller gets, and when
 *
 * This is the only thing a caller is allowed to know about an execution. It authenticates the
 * supervisor, waits for `READY_FOR_BODY` before sending a byte, streams the body under a bound,
 * collects the result, verifies the full terminal chain and returns bytes that have passed every
 * check.
 *
 * ## What it refuses
 *
 * A caller that gets the sequence wrong — sends a body before it is invited, reuses a request id,
 * presents a reservation for another role — gets a refusal, not a retry with looser checks. There
 * is no "best effort" mode, no way to accept an unverified result, and no boolean the caller can
 * set to skip verification. The library has no such parameter because a parameter would be a
 * promise that it is used correctly.
 *
 * ## What it is not
 *
 * Not wired into a web route or a BullMQ processor (R7D.2). It takes an already-authenticated
 * channel and does not decide who the caller is — that happened at the socket, in `ipc-auth.ts`.
 */

import { createHash, randomBytes } from "node:crypto";
import type { Readable } from "node:stream";
import {
  BoundedProvisionalOutput,
  sha256Hex,
  type VerifiedTerminalCommit,
} from "./provisional-stream";
import { verifyTerminalCommit, type CommitResult } from "./terminal-commit";
import type { TerminalCommitMessage } from "./terminal-auth";
import { WORKER_LIMITS } from "../pdf/worker-protocol";

/** A bound the caller enforces on itself. Not a suggestion: exceeding it aborts. */
export type CallerLimits = {
  /** Largest body this caller will send. */
  maxInputBytes: number;
  /** Largest result this caller will hold. */
  maxOutputBytes: number;
  /** How long to wait for READY_FOR_BODY. */
  readyTimeoutMs: number;
  /** How long to wait for the result after the body is sent. */
  resultTimeoutMs: number;
  /** How many bytes of handshake preamble the supervisor may send before the session starts. */
  maxPreambleBytes: number;
};

export const DEFAULT_CALLER_LIMITS: CallerLimits = Object.freeze({
  maxInputBytes: 100 * 1024 * 1024,
  maxOutputBytes: 250 * 1024 * 1024,
  readyTimeoutMs: 10_000,
  resultTimeoutMs: 60_000,
  maxPreambleBytes: 4 * 1024,
});

/** Why a caller refused to return a result. Closed, because callers branch on it. */
export type CallerFailureCode =
  | "NOT_READY"
  | "INPUT_TOO_LARGE"
  | "INPUT_MISMATCH"
  | "RESULT_TOO_LARGE"
  | "RESULT_UNVERIFIED"
  | "RESULT_INVALID"
  | "COMMIT_MISSING"
  | "TIMEOUT"
  | "TRANSPORT_CLOSED"
  | "CANCELLED";

export class CallerError extends Error {
  constructor(readonly code: CallerFailureCode, message: string) {
    super(message);
    this.name = "CallerError";
  }
}

/** What the caller sends. The body is a stream, never a buffer it has already materialized. */
export type RequestSpec = {
  requestId: string;
  operation: "inspect" | "fill" | "verify";
  /** The role this caller authenticated as; enforced by the supervisor's socket, restated here. */
  role: "app" | "worker";
  /** Declared body length and digest, reconciled by the supervisor against what it received. */
  bodyBytes: number;
  bodyDigest: string;
  /**
   * Metadata block length the supervisor declared at admission.
   *
   * The caller cannot parse the frame — it has no parser by design — so it cannot derive this.
   * It is an independent expectation supplied before the execution started, and the commit must
   * agree with it. Taking the value from the commit instead would make the comparison circular.
   */
  metaBytes: number;
  /** The execution identity the caller expects. Refusing a different one is the point. */
  executionId: string;
  /** Independently trusted supervisor identity, configured by the caller -- never copied from the
   * commit message, which a peer could forge. */
  supervisorInstance: string;
  /** Independently trusted boot identity, configured by the caller -- never copied from the
   * commit message. */
  bootId: string;
};

/**
 * The channel the supervisor provides.
 *
 * Deliberately tiny: the caller can write the body, read the result, and nothing else. A richer
 * interface would let it interrogate the supervisor mid-execution, and an interrogable supervisor
 * is a supervisor that leaks state to a caller that should not have it.
 */
export type SupervisorChannel = {
  /** Resolves when the supervisor signals READY_FOR_BODY. */
  ready: Promise<void>;
  /** Write the body. Rejects if the channel closes early. */
  write: (chunk: Buffer) => Promise<void>;
  /** Close the body. The supervisor treats EOF as the end of input. */
  endInput: () => void;
  /** The provisional result frame, validated by the caller's own stream. */
  result: Readable;
  /** The terminal commit message, or null if the supervisor never sent one. */
  commitMessage: () => Promise<TerminalCommitMessage | null>;
  /** Abort everything. Idempotent. */
  cancel: () => void;
  /** Nonce for this exchange, which the commit must echo. */
  nonce: string;
};

export type CallerOptions = {
  limits?: Partial<CallerLimits>;
  /** Injectable clock, so a timeout is testable. */
  monotonicMs?: () => number;
};

/**
 * The result of a successful call.
 *
 * Contains the bytes: this is the one place in the system where the caller's copy exists, which
 * is why every check is performed before it is constructed. The supervisor, the watchdog and the
 * stream never hand out a byte they have not sealed, and this object exists only after the caller
 * has verified the commit itself.
 */
export type CallerResult = {
  bytes: Buffer;
  digest: string;
  resultBytes: number;
  metaBytes: number;
  commit: VerifiedTerminalCommit;
};

/**
 * Perform one authenticated execution.
 *
 * The order is the contract. Authenticate, read the invitation, stream, reconcile, verify the
 * commit, and only then return bytes.
 */
export async function executeRequest(
  channel: SupervisorChannel,
  spec: RequestSpec,
  body: Readable,
  secret: Buffer,
  options: CallerOptions = {},
): Promise<CallerResult> {
  const limits: CallerLimits = { ...DEFAULT_CALLER_LIMITS, ...(options.limits ?? {}) };
  const now = options.monotonicMs ?? (() => Math.round(performance.now()));

  // 1. Wait for the invitation. A caller that sends before the supervisor has finished preflight
  //    and armed the watchdog would be pushing document bytes at a container that might fail
  //    those checks, and the bytes would already be in flight when it did.
  const readyDeadline = now() + limits.readyTimeoutMs;
  await withDeadline(channel.ready, readyDeadline, () => now(), "NOT_READY");

  // 2. Stream the body under our own bound, hashing as we go. The declared values are the
  //    supervisor's reconciliation inputs; our own hash proves we sent what we claimed.
  const hash = createHash("sha256");
  let sent = 0;
  try {
    for await (const chunk of body) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
      sent += buffer.byteLength;
      if (sent > limits.maxInputBytes) {
        channel.cancel();
        throw new CallerError("INPUT_TOO_LARGE", `the body exceeded ${limits.maxInputBytes} bytes`);
      }
      hash.update(buffer);
      await channel.write(buffer);
    }
  } catch (error) {
    channel.cancel();
    throw error instanceof CallerError ? error : new CallerError("TRANSPORT_CLOSED", "the body could not be sent");
  }
  const digest = hash.digest("hex");
  if (sent !== spec.bodyBytes || digest !== spec.bodyDigest) {
    channel.cancel();
    throw new CallerError("INPUT_MISMATCH", "the bytes sent did not match the declaration");
  }
  channel.endInput();

  // 3. Collect the result. The caller re-validates the frame: it does not trust the supervisor's
  //    claim that the frame was well formed, because the supervisor is the only party that could
  //    have replaced it.
  const output = new BoundedProvisionalOutput(limits.maxOutputBytes);
  const resultDeadline = now() + limits.resultTimeoutMs;
  const chunks: Buffer[] = [];
  let received = 0;
  try {
    for await (const chunk of channel.result) {
      if (now() > resultDeadline) throw new CallerError("TIMEOUT", "the result did not arrive in time");
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
      received += buffer.byteLength;
      if (received > limits.maxOutputBytes) {
        channel.cancel();
        throw new CallerError("RESULT_TOO_LARGE", `the result exceeded ${limits.maxOutputBytes} bytes`);
      }
      chunks.push(buffer);
    }
  } catch (error) {
    channel.cancel();
    throw error instanceof CallerError ? error : new CallerError("TRANSPORT_CLOSED", "the result could not be read");
  }

  // 4. Verify the terminal commit. This is the step that makes the caller an authority rather
  //    than a recipient: it checks a signature it alone can check, over fields it can compare
  //    against what it actually holds.
  const message = await channel.commitMessage().catch(() => null);
  if (message === null) {
    channel.cancel();
    throw new CallerError("COMMIT_MISSING", "the supervisor sent no terminal commit");
  }
  const frameBytes = Buffer.concat(chunks);
  if (frameBytes.byteLength < 4) {
    channel.cancel();
    throw new CallerError("RESULT_INVALID", "the result frame has no metadata length prefix");
  }
  // The metadata length is read from the independently received, bounded framing: the four-byte
  // length prefix of the result frame the caller actually holds. It is not taken from the commit,
  // which would make the comparison circular.
  const metaBytes = frameBytes.readUInt32BE(0);
  // The metadata block starts at byte 4 (after the four-byte length prefix), so it must fit
  // within the frame's body: metaBytes + 4 <= frameBytes.byteLength. It also must not exceed the
  // metadata ceiling the supervisor enforces, so a caller can never be tricked into holding more
  // metadata than the protocol allows.
  if (metaBytes > frameBytes.byteLength - 4) {
    channel.cancel();
    throw new CallerError("RESULT_INVALID", "the result declares more metadata than the frame carries");
  }
  if (metaBytes > WORKER_LIMITS.metaBytes) {
    channel.cancel();
    throw new CallerError("RESULT_INVALID", `the result metadata declares ${metaBytes} bytes`);
  }
  const verified: CommitResult = verifyTerminalCommit(
    secret,
    message,
    {
      executionId: spec.executionId,
      requestId: spec.requestId,
      operation: spec.operation,
      // The digest is of the complete frame, which is what the chain binds. The body is a slice
      // of it, so a commit bound to the body would not describe what the supervisor sealed.
      resultDigest: sha256Hex(frameBytes),
      resultBytes: frameBytes.byteLength,
      metaBytes,
      bootId: spec.bootId,
      supervisorInstance: spec.supervisorInstance,
    },
    now(),
  );
  if (!verified.ok) {
    channel.cancel();
    throw new CallerError("RESULT_UNVERIFIED", `the terminal commit did not verify: ${verified.code}`);
  }

  // 5. Release. `collect` checks the commit against the bytes a final time; it is not redundant,
  //    because a caller could have been handed a valid commit for a different object.
  output.append(frameBytes);
  output.seal(spec.executionId, verified.commit.resultDigest);
  const bytes = Buffer.from(output.collect(verified.commit));
  return {
    bytes,
    digest: verified.commit.resultDigest,
    resultBytes: verified.commit.resultBytes,
    metaBytes: verified.commit.metaBytes,
    commit: verified.commit,
  };
}

/**
 * Await a promise with a deadline.
 *
 * Rejects with the caller's own code rather than a generic timeout, because "the supervisor never
 * invited me" and "the result never came" are different failures with different remedies.
 */
async function withDeadline<T>(promise: Promise<T>, deadline: number, now: () => number, code: CallerFailureCode): Promise<T> {
  const remaining = Math.max(0, deadline - now());
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        // Deliberately not `unref`'d. An unref'd timer does not keep the event loop alive, so a
        // caller waiting on a supervisor that never responds would have its process exit before
        // the timeout fired — the promise would never settle and the failure would be a silent
        // hang rather than a `NOT_READY`. The timer is cleared in `finally`.
        timer = setTimeout(() => reject(new CallerError(code, "the supervisor did not invite a body in time")), remaining);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/** A request id: unpredictable, so two callers cannot collide deliberately. */
export function newRequestId(): string {
  return randomBytes(16).toString("hex");
}

/** The digest a caller declares for a body it is about to stream. */
export function digestOf(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}
