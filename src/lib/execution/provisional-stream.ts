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
 * A terminal commit whose signatures have been verified by the holder.
 *
 * ## What the type can and cannot promise
 *
 * A TypeScript type proves nothing at run time: a caller can construct this shape by hand. That
 * is why it is not the security boundary — `src/lib/execution/terminal-commit.ts` is, and it
 * verifies an HMAC chain (caller ← supervisor ← watchdog) before producing this record. What the
 * type does is make the *dependency* explicit: `collect` will not accept anything that has not
 * passed through that verification, because there is no other way to obtain the value.
 *
 * Constructing one by hand gets a caller exactly one thing: a refusal from `collect` when the
 * fields do not match the bytes, which is the same refusal a replay gets.
 */
export type VerifiedTerminalCommit = {
  readonly executionId: string;
  readonly requestId: string;
  readonly operation: "inspect" | "fill" | "verify";
  /** Digest of the validated result frame. */
  readonly resultDigest: string;
  /** Body bytes, excluding the metadata block. */
  readonly resultBytes: number;
  /** Metadata block length, so the framing is bound too. */
  readonly metaBytes: number;
  readonly outcome: "committed" | "refused" | "timeout" | "cancelled" | "failed";
  readonly containerRemoved: boolean;
  /** The independent Watchdog instance whose grant was verified. */
  readonly watchdogInstance: string;
  readonly verifiedAtMonotonicMs: number;
};

/**
 * Incremental reader for one fd3 frame.
 *
 * Single-use. A second `push` after `finish` throws, because a frame has exactly one end.
 */
export class ProvisionalResultStream {
  private readonly options: ProvisionalStreamOptions;
  /** Which part of the frame the reader is in. Only two accumulate, and both are bounded. */
  private phase: "HEADER_PREFIX" | "HEADER_BODY" | "BODY" = "HEADER_PREFIX";
  private prefixBytes: Buffer = Buffer.alloc(0);
  private metaLength = 0;
  private metaFilled = 0;
  private metaBuffer: Buffer = Buffer.alloc(0);
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
  /** Set once the bytes were released. Publication happens at most once. */
  private collected = false;
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
   * ## The state machine, and why it is not "concatenate and slice"
   *
   * The previous version did `this.headerBuffer = Buffer.concat([this.headerBuffer, view])` on
   * every push. That is quadratic in the number of chunks, and it copies the whole buffer even
   * when only four bytes are needed to learn the header length. More importantly it had no
   * bound: a peer that sent an endless stream of bytes while declaring nothing would grow the
   * header buffer without limit.
   *
   * The phases are explicit. Only `HEADER_PREFIX` and `HEADER_BODY` accumulate, and both are
   * bounded by the control ceiling; `META` copies exactly the declared length and nothing more.
   * A frame that declares 4 MiB of metadata allocates 4 MiB — not 4 MiB plus whatever was
   * buffered before it was known.
   *
   * ## Faults are terminal
   *
   * Every throw sets `invalidated`. A stream that has produced a framing error has no valid
   * continuation: the bytes after it were never validated and must not be treated as a shorter
   * valid result. `push` refuses afterwards and `finish` refuses too, so no code path can
   * accidentally complete a frame that already failed.
   */
  push(input: Buffer | Uint8Array): void {
    if (this.ended) throw this.invalidate("CLOSED", "the stream already ended");
    if (this.invalidated) throw new StreamError("CLOSED", "the stream was invalidated by an earlier framing fault");
    const view = Buffer.isBuffer(input) ? input : Buffer.from(input.buffer, input.byteOffset, input.byteLength);
    this.frameBytes += view.byteLength;
    // A single coalesced chunk may contain a header *and* a body, so the views advance through
    // the input rather than being recursively fed back through `push`.
    this.consume(view);
  }

  /** Advance the state machine over one view, without recursion or re-copying. */
  private consume(view: Buffer): void {
    let offset = 0;

    // ---- phase 1: the four-byte length prefix -----------------------------------------
    if (this.phase === "HEADER_PREFIX") {
      const need = 4 - this.prefixBytes.byteLength;
      const take = Math.min(need, view.byteLength);
      this.prefixBytes = Buffer.concat([this.prefixBytes, view.subarray(0, take)]);
      offset = take;
      if (this.prefixBytes.byteLength < 4) return;
      const metaLength = this.prefixBytes.readUInt32BE(0);
      if (metaLength === 0) throw this.invalidate("META_INVALID_JSON", "the result declares an empty metadata block");
      if (metaLength > WORKER_LIMITS.metaBytes) {
        throw this.invalidate("META_TOO_LARGE", `the result metadata declares ${metaLength} bytes`);
      }
      // The declared length is validated *before* anything is allocated for it.
      this.metaLength = metaLength;
      this.metaBuffer = Buffer.allocUnsafe(metaLength);
      this.phase = "HEADER_BODY";
    }

    // ---- phase 2: exactly the declared metadata --------------------------------------
    if (this.phase === "HEADER_BODY") {
      const need = this.metaLength - this.metaFilled;
      const take = Math.min(need, view.byteLength - offset);
      view.copy(this.metaBuffer, this.metaFilled, offset, offset + take);
      this.metaFilled += take;
      offset += take;
      if (this.metaFilled < this.metaLength) return;

      let parsed: unknown;
      try {
        parsed = JSON.parse(this.metaBuffer.toString("utf8"));
      } catch {
        throw this.invalidate("META_INVALID_JSON", "the result metadata is not valid JSON");
      }
      this.meta = this.validateMeta(parsed);
      // The metadata buffer is dropped here; nothing needs it after validation.
      this.metaBuffer = Buffer.alloc(0);
      this.phase = "BODY";
    }

    // ---- phase 3: body -----------------------------------------------------------------
    if (offset >= view.byteLength) return;
    const body = offset === 0 ? view : view.subarray(offset);
    const maxOutput = this.options.maxOutputBytes ?? 512 * 1024 * 1024;
    if (this.outputBytes + body.byteLength > maxOutput) {
      throw this.invalidate("OUTPUT_TOO_LARGE", `output exceeds ${maxOutput} bytes`);
    }
    // The declared length is known once the metadata is parsed, so an over-long frame is
    // refused as soon as it exceeds the declaration rather than only at `finish`.
    if (this.declaredOutputBytes !== null && this.outputBytes + body.byteLength > this.declaredOutputBytes) {
      throw this.invalidate("TRUNCATED", `the frame carried more than the declared ${this.declaredOutputBytes} output bytes`);
    }
    if (this.pendingBytes + body.byteLength > this.maxBufferedBytes * 4) {
      // The caller is not consuming. Refusing here is better than growing without bound in a
      // process that is supposed to remain a thin pipe.
      throw this.invalidate("BUFFER_EXCEEDED", "the consumer is not keeping up with the result stream");
    }
    this.hash.update(body);
    this.outputBytes += body.byteLength;
    this.pendingBytes += body.byteLength;
    this.options.sink({ index: this.chunks, bytes: body });
    this.chunks += 1;
  }

  /**
   * Record a terminal fault and return the error to throw.
   *
   * Every fault path routes through here so invalidation cannot be forgotten at one of them.
   */
  private invalidate(fault: StreamFault, message: string): StreamError {
    this.invalidated = true;
    // Release what was buffered: keeping it would defeat the bound it just violated.
    this.metaBuffer = Buffer.alloc(0);
    this.prefixBytes = Buffer.alloc(0);
    return new StreamError(fault, message);
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
    // A frame that already produced a framing fault can never be completed. Without this, a
    // caller that caught the fault and carried on could publish a partial document.
    if (this.invalidated) throw new StreamError("CLOSED", "the stream was invalidated by an earlier framing fault");
    this.ended = true;
    if (this.meta === null) {
      // The header never completed. Either the process died early or the frame is short.
      throw new StreamError("TRUNCATED", `the result frame ended after ${this.frameBytes} bytes without a complete header`);
    }
    // Trailing data past the declaration is a framing fault, not extra output. The body regime
    // refuses it during `push` as soon as it exceeds the declaration; this catches the case
    // where the frame ended exactly at the ceiling and the declaration was the shorter of the
    // two numbers.
    if (this.declaredOutputBytes !== null && this.outputBytes !== this.declaredOutputBytes) {
      throw this.invalidate(
        "TRUNCATED",
        `the result declared ${this.declaredOutputBytes} output bytes and carried ${this.outputBytes}`,
      );
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
  /** Set once the bytes were released. Publication happens at most once. */
  private collected = false;

  constructor(capBytes: number) {
    this.cap = capBytes;
  }

  /** Bytes currently retained. */
  get bytes(): number {
    return this.total;
  }

  /**
   * Record the stream's validated completion.
   *
   * Called by `ProvisionalResultStream.finish` once the frame ended, the digest and length were
   * reconciled, and no fault occurred. It records facts; it does not authorize anything. The
   * distinction is the whole correction: sealing previously *was* the authorization, because the
   * same object could then issue a grant to itself.
   */
  seal(executionId: string, digest: string): void {
    if (this.sealed !== null) throw new StreamError("CLOSED", "this output was already sealed");
    this.sealed = { executionId, digest, bytes: this.total };
  }

  /** The identity and digest recorded at seal time, for the supervisor to compare against. */
  get sealedIdentity(): { executionId: string; digest: string; bytes: number } {
    if (this.sealed === null) throw new StreamError("CLOSED", "the stream has not sealed this output");
    return { ...this.sealed };
  }

  append(bytes: Uint8Array): void {
    if (this.discarded) throw new StreamError("CLOSED", "output was discarded");
    // Sealed output is frozen. Appending after the digest was verified would let the bytes
    // differ from what was authenticated while the grant still described the old content.
    if (this.sealed !== null) throw new StreamError("CLOSED", "output was sealed and cannot accept more bytes");
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
   * The bytes, but only after an independent authority authorized publication.
   *
   * ## What changed, and why twice
   *
   * It began as `collect(commitGranted: boolean)`: every caller that wrote `collect(true)`
   * published the document, with nothing behind the `true`.
   *
   * That was replaced by a grant this object issued to itself after sealing. Better, but still
   * self-attestation — repeated calls could mint new grants, `consumed` was caller-visible
   * mutable state, and the only thing between an incorrect lifecycle and a published document
   * was this class's own opinion of itself.
   *
   * It now takes a `VerifiedTerminalCommit`, which only `terminal-commit.ts` can produce after
   * verifying an HMAC chain ending at the independent Watchdog's grant. This object's
   * contribution is limited to what it can actually observe: that the commit describes the bytes
   * it is holding. It is not an authority on whether the execution succeeded, and it no longer
   * pretends to be one.
   */
  collect(commit: VerifiedTerminalCommit): Uint8Array {
    if (this.discarded) throw new StreamError("CLOSED", "output was discarded");
    if (this.sealed === null) throw new StreamError("CLOSED", "the stream has not sealed this output");
    // The commit must describe exactly these bytes. A valid commit for a different result is
    // what a replay looks like, and it must fail here rather than publish the wrong document.
    if (commit.executionId !== this.sealed.executionId) {
      throw new StreamError("CLOSED", "the commit belongs to a different execution");
    }
    if (commit.resultDigest !== this.sealed.digest) {
      throw new StreamError("CLOSED", "the commit does not match the bytes this stream carries");
    }
    if (commit.resultBytes !== this.sealed.bytes) {
      throw new StreamError("CLOSED", "the commit does not match the byte count this stream carries");
    }
    if (commit.outcome !== "committed") {
      throw new StreamError("CLOSED", "only a committed execution may release output");
    }
    if (!commit.containerRemoved) {
      throw new StreamError("CLOSED", "the container was not confirmed removed");
    }
    // Consumption is tracked here against a private flag, not by mutating the caller's object.
    // A caller cannot un-consume something it does not own.
    if (this.collected) throw new StreamError("CLOSED", "this output was already collected");
    this.collected = true;
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
