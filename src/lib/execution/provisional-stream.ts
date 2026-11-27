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
  finish(): StreamCompletion {
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
    return {
      outputBytes: this.outputBytes,
      outputSha256: this.hash.digest("hex"),
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

  constructor(capBytes: number) {
    this.cap = capBytes;
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

  /** Only valid after a terminal commit. Throws otherwise, because publication is gated. */
  collect(commitGranted: boolean): Uint8Array {
    if (!commitGranted) throw new StreamError("CLOSED", "publication requires a terminal commit");
    if (this.discarded) throw new StreamError("CLOSED", "output was discarded");
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
