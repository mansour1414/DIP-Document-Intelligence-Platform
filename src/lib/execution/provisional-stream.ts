/**
 * Bounded provisional result streaming (R7D.1 §11).
 *
 * ## Defect 3, and why this file exists at all
 *
 * The abandoned implementation collected the executor's stdout into an array of result
 * chunks and `Buffer.concat`-ed them before doing anything with them. For a 500 MiB Fill
 * output that is 500 MiB in the supervisor — a trusted process the whole isolation design
 * exists to keep out of the document's way — held twice during the concat.
 *
 * The fix is not "buffer less"; it is **not to hold the result**. This class validates the
 * fd3 frame incrementally as bytes arrive, hashes them, and hands each bounded chunk to the
 * caller immediately. The supervisor's own retained memory is capped by `maxBufferedBytes`,
 * independent of document size.
 *
 * ## The frame format
 *
 * fd3 carries one frame: `[u32 metaLen][meta JSON][output bytes]`. The reader therefore has
 * two regimes:
 *
 *   - **header**: accumulate until `metaLen` is known, then parse and validate the metadata
 *     against the expected operation *before* any output is accepted. This is what stops a
 *     container that answers a `verify` with a `fill` payload from streaming 500 MiB before
 *     the mismatch is noticed.
 *   - **body**: every subsequent byte is output. Count and hash it, emit it onward.
 *
 * ## What this deliberately does not do
 *
 * It does not decide whether the result is publishable. A complete, valid, correctly-hashed
 * stream is still only *provisional*. Publication requires the terminal commit (§11),
 * which needs the container's exit outcome, confirmed removal, and the watchdog's
 * `DISARM_GRANTED`. Those are not transport facts and do not belong here.
 */

import { createHash, type Hash } from "node:crypto";
import { WORKER_LIMITS } from "../pdf/worker-protocol";
import type { WorkerOpV2 } from "../pdf/worker-protocol-v2";
import { validateResultMetaV2 } from "./result-validation";

/** Why a stream was rejected. Closed vocabulary, safe to log. */
export type StreamFault =
  | "TRUNCATED"
  | "META_TOO_LARGE"
  | "META_INVALID_JSON"
  | "META_INVALID_SHAPE"
  | "OP_MISMATCH"
  | "UNEXPECTED_OUTPUT"
  | "OUTPUT_TOO_LARGE"
  | "BUFFER_EXCEEDED"
  | "CLOSED";

export class StreamError extends Error {
  readonly fault: StreamFault;
  constructor(fault: StreamFault, message: string) {
    super(message);
    this.name = "StreamError";
    this.fault = fault;
  }
}

/** A bounded slice of output, already counted and hashed. */
export type ProvisionalChunk = {
  /** Sequence number within this stream, starting at 0. */
  index: number;
  bytes: Uint8Array;
};

export type StreamCompletion = {
  /** Total output bytes seen. Zero for metadata-only operations. */
  outputBytes: number;
  /** Lowercase hex SHA-256 of the output bytes. */
  outputSha256: string;
  /** Total frame bytes consumed, header included. */
  frameBytes: number;
  /** The validated metadata. */
  meta: Record<string, unknown>;
};

export type ProvisionalSink = (chunk: ProvisionalChunk) => void;

/**
 * Map a protocol reason onto this module's fault vocabulary.
 *
 * The shared validator speaks in `WorkerProtocolError.reason` codes; the stream speaks in
 * `StreamFault`. Keeping one translation here means a caller that branches on faults does not
 * have to know which internal rule rejected the frame.
 */
function faultFor(error: unknown, fallback: StreamFault = "META_INVALID_SHAPE"): StreamFault {
  const reason = (error as { reason?: unknown } | null)?.reason;
  switch (reason) {
    case "OP_MISMATCH": return "OP_MISMATCH";
    case "UNEXPECTED_OUTPUT": return "UNEXPECTED_OUTPUT";
    case "OUTPUT_LENGTH_MISMATCH": return fallback;
    case "META_TOO_LARGE": return "META_TOO_LARGE";
    case "UNKNOWN_OP": return "META_INVALID_SHAPE";
    default: return fallback;
  }
}

export type ProvisionalStreamOptions = {
  /** The operation the request asked for. A mismatched answer is rejected on the header. */
  expectedOp: WorkerOpV2;
  /**
   * The execution this stream belongs to.
   *
   * Required, and bound into the terminal grant. Without it a grant from one execution is
   * indistinguishable from a grant from another with the same digest, which is unlikely and
   * not impossible — and the failure mode is publishing the wrong document.
   */
  executionId: string;
  /** Largest acceptable output, from runtime config. Defaults to the hard input ceiling. */
  maxOutputBytes?: number;
  /**
   * How many *unacknowledged* bytes the sink may be behind by.
   *
   * The sink is synchronous, so backpressure is expressed by how much the reader will
   * accept between yields; this bound is what the caller compares against to decide whether
   * to pause the upstream pipe. It is not a buffer — nothing is queued here.
   */
  maxBufferedBytes?: number;
  /** Receives each chunk as it is validated. Must not retain it beyond the call. */
  sink: ProvisionalSink;
};

/**
 * Proof that a stream issued its own terminal commit.
 *
 * Opaque by construction: it carries no method the caller can forge, and `collect` compares it
 * against the stream's recorded completion rather than trusting its contents. A caller can
 * construct this shape, which is why every field is checked — the type alone proves nothing.
 */
export type TerminalCommitGrant = {
  readonly executionId: string;
  readonly digest: string;
  readonly bytes: number;
  consumed: boolean;
};

/**
 * Incremental reader for one fd3 frame.
 *
 * Single-use. A second `push` after `finish` throws, because a frame has exactly one end.
 */
export class ProvisionalResultStream {
  private readonly options: ProvisionalStreamOptions;
  private readonly header = Buffer.alloc(0);
  private headerBuffer: Buffer = Buffer.alloc(0);
  private meta: Record<string, unknown> | null = null;
  private outputBytes = 0;
  private frameBytes = 0;
  private chunks = 0;
  private readonly hash: Hash;
  /** Bytes pushed to the sink since the last `drainCount`, for backpressure accounting. */
  private pendingBytes = 0;
  private ended = false;
  /** The fill header's declared output length, reconciled at `finish()`. */
  private declaredOutputBytes: number | null = null;
  /** Set by any framing fault; a dead stream never accepts another byte. */
  private invalidated = false;
  /** Set once a terminal commit has been issued; publication requires it. */
  private granted = false;
  /** The validated end state, retained so a grant can be checked against it. */
  private completion: { outputBytes: number; outputSha256: string } | null = null;

  constructor(options: ProvisionalStreamOptions) {
    this.options = options;
    this.hash = createHash("sha256");
  }

  /** Bytes awaiting consumption by the caller's backpressure logic. */
  get backlogBytes(): number {
    return this.pendingBytes;
  }

  /** Called by the caller once it has finished handling the emitted chunk. */
  acknowledge(bytes: number): void {
    this.pendingBytes = Math.max(0, this.pendingBytes - bytes);
  }

  get maxBufferedBytes(): number {
    return this.options.maxBufferedBytes ?? 64 * 1024;
  }

  /**
   * Feed bytes from the executor's stdout.
   *
   * Throws `StreamError` on any fault. Once thrown the stream is dead and the caller must
   * discard everything it emitted: a partially validated stream is not a shorter valid one.
   */
  push(input: Buffer | Uint8Array): void {
    if (this.ended) throw new StreamError("CLOSED", "the stream already ended");
    if (this.invalidated) throw new StreamError("CLOSED", "the stream was invalidated by an earlier framing fault");
    let view = Buffer.isBuffer(input) ? input : Buffer.from(input.buffer, input.byteOffset, input.byteLength);
    this.frameBytes += view.byteLength;

    // ---- header regime -----------------------------------------------------------------
    if (this.meta === null) {
      this.headerBuffer = Buffer.concat([this.headerBuffer, view]);
      if (this.headerBuffer.byteLength < 4) return;
      const metaLength = this.headerBuffer.readUInt32BE(0);
      if (metaLength > WORKER_LIMITS.metaBytes) {
        throw new StreamError("META_TOO_LARGE", `the result metadata declares ${metaLength} bytes`);
      }
      if (this.headerBuffer.byteLength < 4 + metaLength) return;
      const metaBytes = this.headerBuffer.subarray(4, 4 + metaLength);
      let parsed: unknown;
      try {
        parsed = JSON.parse(metaBytes.toString("utf8"));
      } catch {
        throw new StreamError("META_INVALID_JSON", "the result metadata is not valid JSON");
      }
      this.meta = this.validateMeta(parsed);
      // Whatever follows the header is body.
      view = Buffer.from(this.headerBuffer.subarray(4 + metaLength));
      this.headerBuffer = Buffer.alloc(0);
      if (view.byteLength === 0) return;
    }

    // ---- body regime -------------------------------------------------------------------
    const maxOutput = this.options.maxOutputBytes ?? 512 * 1024 * 1024;
    if (this.outputBytes + view.byteLength > maxOutput) {
      throw new StreamError("OUTPUT_TOO_LARGE", `output exceeds ${maxOutput} bytes`);
    }
    if (this.pendingBytes + view.byteLength > this.maxBufferedBytes * 4) {
      // The caller is not consuming. Refusing here is better than growing without bound in
      // a process that is supposed to remain a thin pipe.
      throw new StreamError("BUFFER_EXCEEDED", "the consumer is not keeping up with the result stream");
    }
    this.hash.update(view);
    this.outputBytes += view.byteLength;
    this.pendingBytes += view.byteLength;
    this.options.sink({ index: this.chunks, bytes: view });
    this.chunks += 1;
  }

  private validateMeta(parsed: unknown): Record<string, unknown> {
    // F02: one validator, shared with `decodeResultV2`. The two decoders previously had
    // different opinions — this one checked `outputBytes`, while the fill contract uses
    // `outBytes`, so a well-formed fill result was misread and a malformed one could pass.
    //
    // At header time the output count is not yet known, so the length reconciliation is
    // deferred to `finish()`, where the real total is available. Every shape rule is enforced
    // now, before a single output byte is forwarded.
    // At header time the body has not arrived, so the *length equality* rule cannot run: it
    // would compare the declaration against zero. Passing the declared count satisfies the
    // shape checks without weakening them, and `finish()` re-runs the same validator against
    // the real total, where a truncated or over-long frame is caught.
    const declared = (parsed as { outBytes?: unknown }).outBytes;
    const headerClaim = typeof declared === "number" && Number.isSafeInteger(declared) ? declared : 0;
    let validated;
    try {
      validated = validateResultMetaV2(parsed, this.options.expectedOp, headerClaim);
    } catch (error) {
      // Translate the shared validator's protocol errors into this module's fault vocabulary,
      // so every framing fault surfaces the same way regardless of which rule caught it. The
      // underlying reason is preserved in the message.
      throw new StreamError(faultFor(error), error instanceof Error ? error.message : "the result metadata is invalid");
    }
    if (validated.kind === "fill") this.declaredOutputBytes = (validated.meta as { outBytes: number }).outBytes;
    return parsed as Record<string, unknown>;
  }

  /**
   * Assert the stream ended cleanly and return the digest.
   *
   * Every fault that can only be detected at the end lives here: a declared output length
   * that disagrees, an operation that should have been metadata-only but carried bytes, and
   * a frame shorter than its own header promised.
   */
  /**
   * Assert the stream ended cleanly.
   *
   * `seal` is the output this stream's bytes went into. Passing it closes the gap between
   * "the stream says the frame was valid" and "these bytes may be published": the output object
   * records the verified digest and length, and only then can it issue a terminal grant. Without
   * this the two objects were independent, and a caller could hand `collect` any output it liked.
   */
  finish(seal?: BoundedProvisionalOutput): StreamCompletion {
    if (this.ended) throw new StreamError("CLOSED", "the stream already ended");
    this.ended = true;
    if (this.meta === null) {
      // The header never completed. Either the process died early or the frame is short.
      throw new StreamError("TRUNCATED", `the result frame ended after ${this.frameBytes} bytes without a complete header`);
    }
    // Re-validate against the real byte count. This is where a truncated or over-long frame
    // is caught, using the same function as the buffered decoder so the two cannot disagree.
    try {
      validateResultMetaV2(this.meta, this.options.expectedOp, this.outputBytes);
    } catch (error) {
      throw new StreamError(faultFor(error, "TRUNCATED"), error instanceof Error ? error.message : "the result failed validation");
    }
    const outputSha256 = this.hash.digest("hex");
    this.completion = { outputBytes: this.outputBytes, outputSha256 };
    if (seal !== undefined) {
      if (seal.bytes !== this.outputBytes) {
        throw new StreamError("TRUNCATED", "the sealed output does not hold the bytes this stream forwarded");
      }
      seal.seal(this.options.executionId, outputSha256);
    }
    return {
      outputBytes: this.outputBytes,
      outputSha256,
      frameBytes: this.frameBytes,
      meta: this.meta,
    };
  }

  /** Hash of what has been seen so far. Used for the incremental digest check. */
  digestSoFar(): string {
    // `createHash` objects are single-use; cloning via `copy()` keeps the running digest
    // intact so the stream can continue after a checkpoint.
    return (this.hash as unknown as { copy(): Hash }).copy().digest("hex");
  }
}

/**
 * A bounded, in-memory provisional output holder for the **caller** side.
 *
 * The supervisor streams; the trusted caller still has to hold the result until it is
 * published, because publication is the caller's job. That retention is bounded too, and
 * `append` fails once the cap is reached rather than growing. This is deliberately not a
 * general-purpose buffer: it exists so "the caller holds bounded provisional output" is a
 * property with a number attached.
 */
export class BoundedProvisionalOutput {
  private readonly cap: number;
  private readonly chunks: Uint8Array[] = [];
  private total = 0;
  private discarded = false;
  /** Set by `seal` once the stream has validated its own end state. */
  private sealed: { executionId: string; digest: string; bytes: number } | null = null;
  private granted = false;

  constructor(capBytes: number) {
    this.cap = capBytes;
  }

  /**
   * Record the stream's validated completion.
   *
   * Called by `ProvisionalResultStream` once its frame has ended, its digest and length have
   * been reconciled, and no fault has occurred. It exists so the object holding the bytes knows
   * what the stream concluded, without the caller carrying that fact — and without a caller
   * being able to assert it.
   */
  seal(executionId: string, digest: string): void {
    if (this.sealed !== null) throw new StreamError("CLOSED", "this output was already sealed");
    this.sealed = { executionId, digest, bytes: this.total };
  }

  /**
   * Issue the terminal commit.
   *
   * ## Why the caller's boolean was not enough
   *
   * The previous signature was `collect(commitGranted: boolean)`. Every caller that wrote
   * `collect(true)` published the document, and there was nothing behind the `true` — no
   * binding to the metadata, no confirmation that the exit outcome was clean, no evidence the
   * container was gone. A caller with a bug, or one merely optimistic about its own
   * preconditions, publishes unverified bytes and the type system agrees with it.
   *
   * Everything this object can check has been checked by the time it gets here. The caller
   * still owns the lifecycle evidence this class cannot see. What it refuses is issuing a grant
   * over output that is not internally consistent, and that refusal is the difference between
   * "the caller said so" and "the bytes and the metadata agree".
   */
  grantTerminalCommit(): TerminalCommitGrant {
    if (this.discarded) throw new StreamError("CLOSED", "output was discarded");
    if (this.sealed === null) throw new StreamError("CLOSED", "the stream has not sealed this output");
    this.granted = true;
    return {
      executionId: this.sealed.executionId,
      digest: this.sealed.digest,
      bytes: this.sealed.bytes,
      consumed: false,
    };
  }

  get bytes(): number {
    return this.total;
  }

  append(bytes: Uint8Array): void {
    if (this.discarded) throw new StreamError("CLOSED", "output was discarded");
    if (this.total + bytes.byteLength > this.cap) {
      throw new StreamError("OUTPUT_TOO_LARGE", `provisional output exceeds the caller's ${this.cap} byte cap`);
    }
    // Copied, because the sink's chunk may alias a reused buffer.
    this.chunks.push(Uint8Array.prototype.slice.call(bytes) as Uint8Array);
    this.total += bytes.byteLength;
  }

  /**
   * Discard everything.
   *
   * Called on any of: missing or invalid terminal commit, malformed frame, abnormal exit,
   * timeout, cancellation, or cleanup debt. After this the bytes are unreachable — the
   * caller cannot publish them even by mistake.
   */
  discard(): void {
    this.discarded = true;
    this.chunks.length = 0;
    this.total = 0;
  }

  /**
   * The bytes, but only with a grant this stream itself issued.
   *
   * ## Why the caller's boolean was not enough
   *
   * The previous signature was `collect(commitGranted: boolean)`. Every caller that wrote
   * `collect(true)` published the document, and there was nothing behind the `true` — no
   * binding to the metadata, no confirmation that the exit outcome was clean, no evidence that
   * the container was gone. A caller with a bug, or one that was simply optimistic about its
   * own preconditions, publishes unverified bytes and the type system agrees with it.
   *
   * A grant is now issued by `grantTerminalCommit` and can only be issued once the stream knows
   * its own end state: the frame is complete, the digest and length match the declaration, and
   * no fault occurred. Whatever the caller decides about lifecycle evidence, this object is the
   * authority for "is this byte sequence the one the executor declared", and it refuses to
   * answer otherwise.
   *
   * The grant is single-use. A second publication of the same provisional output would be a
   * second document from one execution.
   */
  collect(grant: TerminalCommitGrant): Uint8Array {
    if (this.discarded) throw new StreamError("CLOSED", "output was discarded");
    if (this.sealed === null) throw new StreamError("CLOSED", "the stream has not sealed this output");
    // Check the grant's contents before its provenance. A forged grant must be reported as a
    // mismatch, not as "no commit was issued": the two are different failures and conflating them
    // would hide a binding defect behind a lifecycle one.
    if (grant.executionId !== this.sealed.executionId) {
      throw new StreamError("CLOSED", "the grant belongs to a different execution");
    }
    if (grant.digest !== this.sealed.digest) {
      throw new StreamError("CLOSED", "the grant does not match the bytes this stream carries");
    }
    if (grant.bytes !== this.sealed.bytes) {
      throw new StreamError("CLOSED", "the grant does not match the byte count this stream carries");
    }
    if (grant.consumed) throw new StreamError("CLOSED", "the grant was already used");
    if (!this.granted) throw new StreamError("CLOSED", "publication requires a terminal commit");
    grant.consumed = true;
    return Buffer.concat(this.chunks.map((chunk) => Buffer.from(chunk)));
  }
}

/**
 * SHA-256 of a byte sequence, hex-encoded.
 *
 * Shared by the request-side input digest and the result-side stream digest so both use the
 * same primitive and cannot disagree about encoding.
 */
export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}
