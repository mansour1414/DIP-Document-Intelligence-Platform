/**
 * Strict result metadata validation for protocol v2 (R7D.1, corrected per review F02).
 *
 * ## The defect this replaces
 *
 * The first version ended with `return { meta: raw as WorkerMetaV2, output }`. That is a
 * TypeScript cast, not validation: it asserts to the compiler that the object already has the
 * shape it needs, having checked almost nothing. A container could have returned
 * `{ ok: true, op: "fill" }` with no `outBytes`, no `checksum`, no `report`, or
 * `{ ok: "yes", op: "inspect" }`, and every one would have been accepted and forwarded.
 *
 * ## Why one function, used by both decoders
 *
 * The review also asked for identical semantics between the buffered decoder and the streaming
 * validator. The only way to guarantee that is to have one implementation. `validateResultMetaV2`
 * below is called by `decodeResultV2` and by `ProvisionalResultStream`, so they cannot drift —
 * there is nothing to drift.
 *
 * ## Where v1's rules are reused rather than restated
 *
 * For `inspect` and `fill`, the metadata is handed to v1's own `parseMeta`. That is deliberate:
 * re-implementing "is this checksum 64 hex characters" here would create a second opinion about
 * what a valid fill result is, and the two would eventually disagree. v1 is the production
 * contract; v2 inherits it. Only `verify` is new, and only `verify` is validated here from
 * scratch.
 */

import { isFormFillErrorCode } from "../pdf/form-types";
import {
  parseMeta,
  WorkerProtocolError,
  type FailureMeta,
  type FillMeta,
  type InspectMeta,
} from "../pdf/worker-protocol";
import type { WorkerMetaV2, WorkerOpV2 } from "./worker-protocol-v2-types";

/**
 * The result shapes v2 can produce, after validation.
 *
 * `outBytes` on a fill is mandatory and is checked against the bytes actually present. A
 * mismatch in either direction is a refusal, because a shorter-than-declared output is a
 * truncated document and a longer one means the frame carried bytes nobody accounted for.
 */
export type ValidatedResult =
  | { kind: "failure"; meta: FailureMeta; outputBytes: 0 }
  | { kind: "metadata-only"; meta: InspectMeta | VerifyMetaStrict; outputBytes: 0 }
  | { kind: "fill"; meta: FillMeta; outputBytes: number };

/** A verify success, strictly shaped. */
export type VerifyMetaStrict = {
  ok: true;
  op: "verify";
  pages: number;
  widgets: number;
  preserved: number;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function strictInteger(value: unknown, what: string, min = 0): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min) {
    throw new WorkerProtocolError(`The verify result field ${what} is invalid.`, "INVALID_META");
  }
  return value;
}

/**
 * Validate `verify` metadata.
 *
 * Rejects unknown properties rather than ignoring them. An extra field is either a protocol
 * misunderstanding or an attempt to smuggle something through a shape the caller does not
 * inspect, and neither should pass silently.
 */
export function parseVerifyMeta(value: unknown, expectedOp: WorkerOpV2 | null): VerifyMetaStrict {
  if (!isRecord(value)) throw new WorkerProtocolError("The result metadata is not an object.", "INVALID_META");
  const keys = Object.keys(value).sort();
  const allowed = ["ok", "op", "pages", "preserved", "widgets"];
  if (keys.length !== allowed.length || keys.some((key, index) => key !== allowed[index])) {
    throw new WorkerProtocolError("The verify result carries unexpected properties.", "INVALID_META");
  }
  if (value.ok !== true) throw new WorkerProtocolError("The verify result is not a success.", "INVALID_DISCRIMINATOR");
  if (value.op !== "verify") throw new WorkerProtocolError("The result names an unexpected operation.", "UNKNOWN_OP");
  if (expectedOp !== null && expectedOp !== "verify") {
    throw new WorkerProtocolError("The result does not match the operation that was requested.", "OP_MISMATCH");
  }
  return {
    ok: true,
    op: "verify",
    pages: strictInteger(value.pages, "pages", 1),
    widgets: strictInteger(value.widgets, "widgets"),
    preserved: strictInteger(value.preserved, "preserved"),
  };
}

/**
 * Validate result metadata and reconcile it with the output bytes actually present.
 *
 * `outputBytes` is what the transport observed, not what the sender claimed. Every branch
 * either confirms those agree or refuses.
 */
export function validateResultMetaV2(raw: unknown, expectedOp: WorkerOpV2, outputBytes: number): ValidatedResult {
  if (!isRecord(raw)) throw new WorkerProtocolError("The result metadata is not an object.", "INVALID_META");

  // The discriminator decides which contract applies, so it is checked before anything else
  // and must be a real boolean — `"false"` and `0` are both truthy-adjacent lies.
  if (typeof raw.ok !== "boolean") {
    throw new WorkerProtocolError("The result discriminator must be a boolean.", "INVALID_DISCRIMINATOR");
  }

  // ---- refusal -------------------------------------------------------------------------
  if (raw.ok === false) {
    // A refusal is metadata-only. If output arrived alongside it, the frame is either
    // corrupted or an attempt to have bytes accepted under a failure marker. Neither is
    // something to forward.
    if (outputBytes !== 0) {
      throw new WorkerProtocolError("A refusal carried output bytes.", "UNEXPECTED_OUTPUT");
    }
    if (raw.op !== expectedOp) {
      throw new WorkerProtocolError("The result does not match the operation that was requested.", "OP_MISMATCH");
    }
    if (!isFormFillErrorCode(raw.code)) {
      throw new WorkerProtocolError("The failure result names an unknown code.", "UNKNOWN_ERROR_CODE");
    }
    // v1's own parser sanitises details from an allowlist; using it here means a refusal is
    // interpreted identically by both protocols.
    const parsed = parseMeta(raw, expectedOp === "verify" ? null : expectedOp) as FailureMeta;
    return { kind: "failure", meta: parsed, outputBytes: 0 };
  }

  // ---- inspect -------------------------------------------------------------------------
  if (raw.op === "inspect") {
    if (expectedOp !== "inspect") throw new WorkerProtocolError("The result does not match the operation that was requested.", "OP_MISMATCH");
    if (outputBytes !== 0) throw new WorkerProtocolError("An inspect result carried output bytes.", "UNEXPECTED_OUTPUT");
    return { kind: "metadata-only", meta: parseMeta(raw, "inspect") as InspectMeta, outputBytes: 0 };
  }

  // ---- verify --------------------------------------------------------------------------
  if (raw.op === "verify") {
    if (outputBytes !== 0) throw new WorkerProtocolError("A verify result carried output bytes.", "UNEXPECTED_OUTPUT");
    return { kind: "metadata-only", meta: parseVerifyMeta(raw, expectedOp) satisfies VerifyMetaStrict, outputBytes: 0 };
  }

  // ---- fill ----------------------------------------------------------------------------
  if (raw.op === "fill") {
    if (expectedOp !== "fill") throw new WorkerProtocolError("The result does not match the operation that was requested.", "OP_MISMATCH");
    const meta = parseMeta(raw, "fill") as FillMeta;
    // v1 requires outBytes to be a positive integer; this adds the requirement that it equal
    // what the frame actually carried. Without that, a truncated stream would be forwarded to
    // the caller as a complete document whose declared length nobody compared to reality.
    if (meta.outBytes !== outputBytes) {
      throw new WorkerProtocolError(
        `The fill result declared ${meta.outBytes} output bytes and the frame carried ${outputBytes}.`,
        "OUTPUT_LENGTH_MISMATCH",
      );
    }
    return { kind: "fill", meta, outputBytes };
  }

  throw new WorkerProtocolError("The result names an unexpected operation.", "UNKNOWN_OP");
}

/** Re-export so callers do not need three imports. */
export type { WorkerMetaV2 };
