/**
 * Internal worker protocol v2 (R7D.1).
 *
 * ## Why a second version instead of editing the first
 *
 * v1 is the wire format the current `form-worker` and `form-worker-child` speak in
 * production. Its semantics — inspect and fill, one request, one process, one framed reply
 * on fd 3 — are unchanged by R7D.1 and must stay that way. Rather than widen the v1
 * discriminated union (which would change what every existing decoder accepts), v2 is a
 * separate set of schemas that *reuses* the v1 length constants and value semantics.
 *
 * The difference v2 introduces is one new operation, `verify`, and a stricter contract
 * around it: `verify` carries metadata only and never returns document bytes.
 *
 * ## What is shared, deliberately
 *
 *   - `controlBytes` (256 KiB), `metaBytes` (4 MiB) and the hard input ceiling come from
 *     v1. Separate limits would let the two protocols disagree about what "too large"
 *     means, and the tighter of the two would silently become the real limit.
 *   - Refusal semantics are v1's `FailureMeta` shape. A refusal that looked different
 *     depending on which protocol produced it would be a new class of bug.
 *
 * ## What v2 refuses to do
 *
 * The decoder rejects trailing bytes, unknown versions, unknown operations, wrong value
 * types, and lengths that disagree with actual payload sizes. Each of those is a separate
 * check with its own error code, because "the frame was bad" is not actionable and
 * "the frame declared 100 bytes and carried 99" is.
 */

import {
  WORKER_LIMITS,
  WorkerProtocolError,
  type FailureMeta,
  type InspectMeta,
  type FillMeta,
} from "./worker-protocol";
import type { FormInventory } from "./form-types";
import { validateResultMetaV2 } from "../execution/result-validation";

/** The version this module encodes and accepts. */
export const WORKER_PROTOCOL_V2 = 2;

/**
 * Operations v2 defines.
 *
 * `flatten` stays a boolean *option on fill* rather than becoming a fourth operation.
 * Flattening is a fill whose output form is removed; making it a separate operation would
 * duplicate every value-validation path and let the two diverge.
 */
export type WorkerOpV2 = "inspect" | "fill" | "verify";

/**
 * The v2 request body — what the caller asks for, independent of transport.
 *
 * Kept free of limits: `maxInputBytes` and friends are *negotiated per connection* by the
 * supervisor (R7D.1 §14), not asserted by the caller. A caller that could set its own
 * ceiling would defeat the ceiling.
 */
export type WorkerRequestV2 =
  | { v: typeof WORKER_PROTOCOL_V2; op: "inspect" }
  | { v: typeof WORKER_PROTOCOL_V2; op: "fill"; flatten: boolean; fields: Record<string, string | boolean | string[]> }
  | { v: typeof WORKER_PROTOCOL_V2; op: "verify"; baseline: VerifyBaseline };

/**
 * The transient expected-state for a fresh verification.
 *
 * ## Why this is not persisted
 *
 * `verify` compares a freshly re-parsed document against what the caller *intended*. The
 * original admission `inspect` does not persist a complete field inventory, and adding one
 * would put field names and values into durable storage — exactly the sensitive execution-
 * plane state R7D.1 §10 and §13 forbid. So the baseline travels with the request, lives in
 * worker memory for one operation, and is never journalled.
 *
 * ## What it contains
 *
 * Field *names* and their expected values must both be present for comparison, which means
 * this structure necessarily carries them. That is why it is transient, bounded by the
 * control ceiling (256 KiB), and never written to disk by the supervisor.
 */
export type VerifyBaseline = {
  /**
   * Which verification to run.
   *
   * `fill` compares values and appearances; `flatten` additionally requires that every
   * interactive field and widget annotation is gone.
   */
  kind: "fill" | "flatten";
  /**
   * The values the fill was asked to write. Compared with v1's `valuesEqual`, so checkbox
   * and radio state handling, multi-widget fields and array-valued choices behave exactly
   * as the existing engine does.
   */
  expected: Record<string, string | boolean | string[]>;
  /**
   * Fields that were present before the fill and must be unchanged after it.
   *
   * Captured from the admission inspection in the *worker's* memory, not from storage.
   */
  untouched?: Record<string, string | boolean | string[] | null>;
};

/** Metadata-only result for `verify`. Never carries document bytes. */
export type VerifyMeta = {
  ok: true;
  op: "verify";
  /** Pages in the verified document. */
  pages: number;
  /** Field widgets found after the operation. Must be 0 for `kind: "flatten"`. */
  widgets: number;
  /** Untouched fields confirmed unchanged. */
  preserved: number;
};

/** Every metadata shape v2 can produce. `FailureMeta` is v1's, reused deliberately. */
export type WorkerMetaV2 = InspectMeta | FillMeta | VerifyMeta | FailureMeta;

/**
 * Operation-specific bounds for `verify`.
 *
 * ## The compatibility question, answered rather than deferred
 *
 * Verify re-parses a document the engine just produced. It does not accept arbitrary
 * client input, and it is invoked by the worker immediately after a fill it already
 * admitted. So it does not need the 512 MiB hard input ceiling that a user upload does —
 * a fill output larger than that could not have been produced by this pipeline anyway.
 *
 * The bound is deliberately generous (the same `metaBytes` band as a result metadata
 * frame) because a wrongly small verify bound would reject legitimate fills. It is a
 * *transport* bound on the control frame's baseline, not a document bound: the document
 * itself arrives on the same input channel as fill and is subject to the same input
 * ceiling, so previously supported Fill outputs are not silently capped.
 *
 * No owner decision is required, and none is implied: verify cannot be asked to accept a
 * document larger than fill could produce.
 */
export const VERIFY_BOUNDS = {
  /** Largest transient baseline accepted in a verify request. */
  baselineBytes: WORKER_LIMITS.controlBytes,
} as const;

// ---------------------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------------------

/**
 * Encode a v2 control frame: `[u32 controlLen][control JSON][body bytes]`.
 *
 * The 4-byte big-endian length prefix is identical to v1's, so the same reader can find
 * the boundary; only the JSON that follows differs.
 */
export function encodeControlV2(request: WorkerRequestV2, body: Uint8Array, maxBodyBytes: number): Buffer {
  if (body.byteLength > maxBodyBytes) {
    throw new WorkerProtocolError("The input exceeds the transport limit.", "INPUT_TOO_LARGE");
  }
  const control = { ...request, bodyBytes: body.byteLength };
  const json = Buffer.from(JSON.stringify(control), "utf8");
  if (json.byteLength > WORKER_LIMITS.controlBytes) {
    throw new WorkerProtocolError("The control metadata exceeds the transport limit.", "CONTROL_TOO_LARGE");
  }
  const header = Buffer.alloc(4);
  header.writeUInt32BE(json.byteLength, 0);
  return Buffer.concat([header, json, Buffer.from(body.buffer, body.byteOffset, body.byteLength)]);
}

/**
 * Encode a v2 result frame: `[u32 metaLen][meta JSON][output bytes]`.
 *
 * Only `fill` ever has output. `inspect` and `verify` are metadata-only by construction —
 * a type-level guarantee above, and an assertion here.
 */
export function encodeResultV2(meta: WorkerMetaV2, output?: Uint8Array): Buffer {
  if (meta.op !== "fill" && output && output.byteLength > 0) {
    throw new WorkerProtocolError("Only fill carries output bytes.", "UNEXPECTED_OUTPUT");
  }
  const json = Buffer.from(JSON.stringify(meta), "utf8");
  if (json.byteLength > WORKER_LIMITS.metaBytes) {
    throw new WorkerProtocolError("The result metadata exceeds the transport limit.", "META_TOO_LARGE");
  }
  const header = Buffer.alloc(4);
  header.writeUInt32BE(json.byteLength, 0);
  const head = Buffer.concat([header, json]);
  return output && output.byteLength > 0
    ? Buffer.concat([head, Buffer.from(output.buffer, output.byteOffset, output.byteLength)])
    : head;
}

// ---------------------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------------------

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Parse the transient baseline, rejecting anything malformed.
 *
 * Bounded by `VERIFY_BOUNDS.baselineBytes` after serialisation, because the JSON reader
 * has already materialised it and a size check before parsing would only be advisory.
 */
function parseBaseline(value: unknown): VerifyBaseline {
  if (!isRecord(value)) throw new WorkerProtocolError("The verify baseline is not an object.", "INVALID_REQUEST");
  const { kind, expected, untouched } = value;
  if (kind !== "fill" && kind !== "flatten") {
    throw new WorkerProtocolError("The verify baseline kind is not supported.", "INVALID_REQUEST");
  }
  if (!isRecord(expected)) throw new WorkerProtocolError("The verify baseline expected values are not an object.", "INVALID_REQUEST");
  if (untouched !== undefined && !isRecord(untouched)) {
    throw new WorkerProtocolError("The verify baseline untouched values are not an object.", "INVALID_REQUEST");
  }
  if (Buffer.byteLength(JSON.stringify(value), "utf8") > VERIFY_BOUNDS.baselineBytes) {
    throw new WorkerProtocolError("The verify baseline exceeds the transport limit.", "CONTROL_TOO_LARGE");
  }
  return {
    kind,
    expected: expected as VerifyBaseline["expected"],
    ...(untouched === undefined ? {} : { untouched: untouched as VerifyBaseline["untouched"] }),
  };
}

/** v1's field-map parser, re-expressed here so v2 does not import a mutable internal. */
function parseFieldsV2(value: unknown): Record<string, string | boolean | string[]> {
  if (!isRecord(value)) throw new WorkerProtocolError("The fields payload is not an object.", "INVALID_REQUEST");
  const out: Record<string, string | boolean | string[]> = Object.create(null) as Record<string, string | boolean | string[]>;
  for (const [name, raw] of Object.entries(value)) {
    if (typeof raw === "string" || typeof raw === "boolean") {
      out[name] = raw;
      continue;
    }
    if (Array.isArray(raw) && raw.every((item) => typeof item === "string")) {
      out[name] = [...raw];
      continue;
    }
    throw new WorkerProtocolError("A field value has an unsupported type.", "INVALID_REQUEST");
  }
  return out;
}

/**
 * Decode a v2 request frame.
 *
 * Returns the parsed request *and* the body, and asserts the body length against the
 * declared `bodyBytes`. A frame whose declared length disagrees with what it carried is
 * rejected rather than truncated: silently accepting the shorter of the two would let a
 * caller smuggle an ambiguity past the digest check downstream.
 */
export function decodeControlV2(buffer: Buffer, maxBodyBytes: number): { request: WorkerRequestV2; body: Uint8Array } {
  if (buffer.byteLength < 4) throw new WorkerProtocolError("The frame is truncated.", "TRUNCATED");
  const controlLength = buffer.readUInt32BE(0);
  if (controlLength > WORKER_LIMITS.controlBytes) {
    throw new WorkerProtocolError("The control metadata exceeds the transport limit.", "CONTROL_TOO_LARGE");
  }
  if (4 + controlLength > buffer.byteLength) throw new WorkerProtocolError("The frame is truncated.", "TRUNCATED");
  let raw: unknown;
  try {
    raw = JSON.parse(buffer.subarray(4, 4 + controlLength).toString("utf8"));
  } catch {
    throw new WorkerProtocolError("The control metadata is not valid JSON.", "INVALID_REQUEST");
  }
  if (!isRecord(raw)) throw new WorkerProtocolError("The control metadata is not an object.", "INVALID_REQUEST");
  if (raw.v !== WORKER_PROTOCOL_V2) {
    throw new WorkerProtocolError("The protocol version is not supported.", "VERSION_MISMATCH");
  }
  const declared = raw.bodyBytes;
  if (typeof declared !== "number" || !Number.isInteger(declared) || declared < 0) {
    throw new WorkerProtocolError("The declared body length is invalid.", "INVALID_REQUEST");
  }
  const body = buffer.subarray(4 + controlLength);
  // Exact, not "at most": trailing bytes past the declaration are a framing fault.
  if (body.byteLength !== declared) {
    throw new WorkerProtocolError("The declared body length does not match the frame.", "LENGTH_MISMATCH");
  }
  if (declared > maxBodyBytes) {
    throw new WorkerProtocolError("The input exceeds the transport limit.", "INPUT_TOO_LARGE");
  }
  const request = parseRequestV2(raw);
  return { request, body };
}

function parseRequestV2(raw: Record<string, unknown>): WorkerRequestV2 {
  const op = raw.op;
  if (op === "inspect") return { v: WORKER_PROTOCOL_V2, op: "inspect" };
  if (op === "fill") {
    if (typeof raw.flatten !== "boolean") {
      throw new WorkerProtocolError("The flatten option must be a boolean.", "INVALID_REQUEST");
    }
    return { v: WORKER_PROTOCOL_V2, op: "fill", flatten: raw.flatten, fields: parseFieldsV2(raw.fields) };
  }
  if (op === "verify") return { v: WORKER_PROTOCOL_V2, op: "verify", baseline: parseBaseline(raw.baseline) };
  throw new WorkerProtocolError("The operation is not supported.", "INVALID_REQUEST");
}

/**
 * Decode a v2 result frame.
 *
 * `expectedOp` is asserted when supplied. The supervisor always supplies it, so a container
 * that answers a `verify` with a `fill` payload is rejected rather than parsed.
 */
export function decodeResultV2(buffer: Buffer, maxOutputBytes: number, expectedOp: WorkerOpV2 | null = null): { meta: WorkerMetaV2; output: Uint8Array } {
  if (buffer.byteLength < 4) throw new WorkerProtocolError("The frame is truncated.", "TRUNCATED");
  const metaLength = buffer.readUInt32BE(0);
  if (metaLength > WORKER_LIMITS.metaBytes) {
    throw new WorkerProtocolError("The result metadata exceeds the transport limit.", "META_TOO_LARGE");
  }
  if (4 + metaLength > buffer.byteLength) throw new WorkerProtocolError("The frame is truncated.", "TRUNCATED");
  let raw: unknown;
  try {
    raw = JSON.parse(buffer.subarray(4, 4 + metaLength).toString("utf8"));
  } catch {
    throw new WorkerProtocolError("The result metadata is not valid JSON.", "INVALID_REQUEST");
  }
  const output = buffer.subarray(4 + metaLength);
  if (output.byteLength > maxOutputBytes) {
    throw new WorkerProtocolError("The output exceeds the transport limit.", "OUTPUT_TOO_LARGE");
  }
  // F02: this previously ended with `return raw as WorkerMetaV2`, which asserts a shape to the
  // compiler having verified almost nothing. The same validator the streaming reader uses is
  // applied here, so the two decoders cannot disagree about what a valid result is.
  const validated = validateResultMetaV2(raw, expectedOp ?? guessOp(raw), output.byteLength);
  return { meta: validated.meta as WorkerMetaV2, output: validated.kind === "fill" ? output : new Uint8Array(0) };
}

/**
 * The operation to validate against when the caller did not supply one.
 *
 * Used only by callers that decode a result without a request context. The validator still
 * checks every operation-specific rule; the only thing missing is the cross-check that the
 * answer matches the question.
 */
function guessOp(raw: unknown): WorkerOpV2 {
  const op = (raw as { op?: unknown } | null)?.op;
  if (op === "inspect" || op === "fill" || op === "verify") return op;
  throw new WorkerProtocolError("The result names an unexpected operation.", "UNKNOWN_OP");
}

/** Narrow a v2 metadata record to `VerifyMeta`, rejecting a mismatched shape. */
export function asVerifyMeta(meta: WorkerMetaV2): VerifyMeta {
  if (meta.op !== "verify" || meta.ok !== true) {
    throw new WorkerProtocolError("The result is not a verify success.", "OP_MISMATCH");
  }
  const { pages, widgets, preserved } = meta as unknown as Record<string, unknown>;
  for (const [field, value] of Object.entries({ pages, widgets, preserved })) {
    if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
      throw new WorkerProtocolError(`The verify result field ${field} is invalid.`, "INVALID_REQUEST");
    }
  }
  return meta as VerifyMeta;
}

/** Re-export so callers do not need to import from two modules. */
export type { FormInventory };
export { WorkerProtocolError, WORKER_LIMITS };
