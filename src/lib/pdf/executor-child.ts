/**
 * Disposable PDF executor child (R7D.1).
 *
 * One container, one operation, one framed reply on **fd 3**. Identical in shape to the
 * in-process `form-worker-child`, because the lessons that shaped that file apply unchanged:
 * nothing but the frame goes to fd 3, stdout and stderr stay diagnostic, and a refusal is data
 * rather than a crash.
 *
 * ## What is different from the in-process child
 *
 *   - Protocol **v2**, which adds `verify`. v1's inspect and fill are not implemented here: this
 *     binary is only ever spoken to by the supervisor, which speaks v2.
 *   - The input ceiling comes from the frame's own declaration. This process is launched with a
 *     minimal environment and cannot see the supervisor's configuration, so the bound has to
 *     travel with the request — the same reasoning as the in-process child, and the same code
 *     shape.
 *
 * ## Verify, and why the baseline lives in memory
 *
 * `verify` re-parses a document the engine just produced and compares it against what the
 * caller intended. The baseline arrives in the request and is never written anywhere: the
 * admission `inspect` does not persist a field inventory, and adding one would put field names
 * and values into durable storage, which §10 and §13 forbid. So verification is bounded by the
 * control frame and lives for one process.
 *
 * ## fd 3 write loop
 *
 * `writeSync` may write fewer bytes than asked, and on a pipe it does so whenever the frame is
 * larger than the pipe buffer and the reader has not drained yet. Writing once and ignoring the
 * return value produces a truncated frame that the supervisor correctly rejects. The loop below
 * is the fix, and it is the same fix the in-process child needed.
 */

import { writeSync } from "node:fs";
import { WORKER_LIMITS, WorkerProtocolError } from "./worker-protocol";
import type { FormInventory } from "./form-types";
import { encodeResultV2, decodeControlV2, WORKER_PROTOCOL_V2, type WorkerRequestV2 } from "./worker-protocol-v2";

// ---------------------------------------------------------------------------------------
// fd 3 bridge
// ---------------------------------------------------------------------------------------

/** The result channel. Nothing else may ever be written here. */
const RESULT_FD = 3;

/**
 * Write the whole frame to fd 3, or fail.
 *
 * A short write is normal on a pipe, so the loop retries from the new offset. EPIPE (the
 * supervisor died or timed out) propagates as a non-zero exit: a partial frame in a closed pipe
 * is a failed run, never a half-success.
 */
function writeAll(frame: Buffer): void {
  let offset = 0;
  while (offset < frame.byteLength) {
    offset += writeSync(RESULT_FD, frame, offset, frame.byteLength - offset);
  }
}

// ---------------------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------------------

/**
 * Inspect: parse the document and return its field inventory.
 *
 * The heavy modules are required lazily. Loading `@napi-rs/canvas` costs tens of megabytes and
 * several hundred milliseconds, and an inspect of a document with no appearances never needs it.
 * In a container sized at 384 MiB, deferring that is the difference between one concurrent
 * inspect and none.
 */
async function inspect(bytes: Uint8Array) {
  const { inspectFormPdf } = await import("./form-inspection");
  const inventory: FormInventory = await inspectFormPdf(bytes, { budgetMs: 20_000 });
  return { ok: true as const, op: "inspect" as const, pages: inventory.pages, inventory };
}

/**
 * Fill: apply values and return the produced document.
 *
 * Delegates to the existing engine so the executor and the in-process worker cannot diverge in
 * what a fill *means*. The internal verification inside `fillForm` is preserved: the output is
 * re-opened and checked before it is returned, which is the existing `verifyFilledForm` path.
 */
async function fill(bytes: Uint8Array, request: Extract<WorkerRequestV2, { op: "fill" }>) {
  const { fillFormPdf } = await import("./form-fill");
  const { sha256Hex } = await import("../execution/provisional-stream");
  const result = await fillFormPdf(bytes, request.fields, { flatten: request.flatten });
  return {
    meta: {
      ok: true as const,
      op: "fill" as const,
      pages: result.report.pages,
      outBytes: result.bytes.byteLength,
      // The digest of the produced document, computed here so the supervisor can bind the
      // terminal commit to the exact bytes rather than to a claim about them.
      checksum: sha256Hex(result.bytes),
      report: result.report,
    },
    output: result.bytes,
  };
}

/**
 * Verify: re-parse a produced document and compare it against a transient baseline.
 *
 * ## What this establishes, and what it does not
 *
 * It establishes that the bytes the engine produced, re-opened from scratch in a fresh parser,
 * still carry the intended values and that untouched fields were not disturbed. It does **not**
 * establish visual fidelity (B31-08 remains independently mandatory) and, because it uses the
 * same engine that produced the document, it is not proof against a shared parser vulnerability.
 * Both limits are real and are stated rather than implied.
 *
 * ## For flatten
 *
 * The structural requirements are: the page count is unchanged, no interactive fields remain,
 * no Widget annotations remain, and no annotation reference dangles. A matching page count with
 * zero widgets does **not** establish that arbitrary page content survived, so it is reported as
 * a structural result, not a fidelity result.
 */
async function verify(bytes: Uint8Array, request: Extract<WorkerRequestV2, { op: "verify" }>) {
  const baseline = request.baseline;

  if (baseline.kind === "flatten") {
    const structural = await import("./form-verify").then((module) => module.verifyFlattened(bytes));
    return {
      ok: true as const,
      op: "verify" as const,
      pages: structural.pages,
      widgets: structural.widgets,
      preserved: structural.preserved,
    };
  }

  const semantic = await import("./form-verify").then((module) =>
    module.verifyFilled({
      bytes,
      expected: baseline.expected,
      untouched: baseline.untouched,
    }),
  );
  return {
    ok: true as const,
    op: "verify" as const,
    pages: semantic.pages,
    widgets: semantic.widgets,
    preserved: semantic.preserved,
  };
}

// ---------------------------------------------------------------------------------------
// Refusal translation
// ---------------------------------------------------------------------------------------

/**
 * Turn an error into an allowlisted refusal.
 *
 * The code is taken from a closed set and the details are rebuilt from an allowlist, because a
 * `details` field that echoed a message could quote document content into a log or an API
 * response. An unexpected throw is reported as `UNEXPECTED` with no borrowing of its text.
 */
function failureMeta(op: WorkerRequestV2["op"] | undefined, error: unknown) {
  const known = error instanceof WorkerProtocolError;
  return {
    ok: false as const,
    op: (op ?? "inspect") as "inspect" | "fill" | "verify",
    code: (known && (error.reason === "PDF_TOO_LARGE" ? "FORM_TOO_LARGE" : "FORM_UNSUPPORTED")) as never,
    details: { reason: known ? error.reason : "UNEXPECTED" },
  };
}

// ---------------------------------------------------------------------------------------
// Input accumulation
// ---------------------------------------------------------------------------------------

/**
 * The declared input ceiling, learned from the control header.
 *
 * Until the header is readable the bound is the header plus the transport maximum, which is
 * large enough for any legal frame and small enough that a peer which never finishes its header
 * cannot make this process buffer without limit.
 */
let effectiveLimit = 4 + WORKER_LIMITS.controlBytes;
let headerRead = false;
const chunks: Buffer[] = [];
let received = 0;
let overLimit = false;

function adoptDeclaredBound(): void {
  if (headerRead || received < 4) return;
  const head = chunks.length === 1 ? chunks[0] : Buffer.concat(chunks);
  const controlLen = head.readUInt32BE(0);
  if (controlLen === 0 || controlLen > WORKER_LIMITS.controlBytes) {
    overLimit = true;
    return;
  }
  if (received < 4 + controlLen) {
    effectiveLimit = 4 + controlLen + WORKER_LIMITS.maxInputBytesCeiling;
    return;
  }
  headerRead = true;
  let declared: number;
  try {
    const parsed = JSON.parse(head.subarray(4, 4 + controlLen).toString("utf8")) as { maxInputBytes?: unknown };
    if (typeof parsed.maxInputBytes !== "number" || !Number.isSafeInteger(parsed.maxInputBytes) || parsed.maxInputBytes <= 0) {
      overLimit = true;
      return;
    }
    declared = parsed.maxInputBytes;
  } catch {
    overLimit = true;
    return;
  }
  effectiveLimit = declared + 4 + controlLen;
}

process.stdin.on("data", (chunk: Buffer) => {
  if (overLimit) return;
  received += chunk.byteLength;
  chunks.push(chunk);
  if (!headerRead) adoptDeclaredBound();
  if (received > effectiveLimit) {
    // Discard what was buffered: keeping it would defeat the bound it just violated.
    overLimit = true;
    chunks.length = 0;
  }
});

process.stdin.on("end", () => {
  void (async () => {
    let op: WorkerRequestV2["op"] | undefined;
    try {
      if (overLimit) throw new WorkerProtocolError("The input exceeds the transport limit.", "PDF_TOO_LARGE");
      const { request, body } = decodeControlV2(Buffer.concat(chunks), WORKER_LIMITS.maxInputBytesCeiling);
      op = request.op;
      const result =
        request.op === "inspect"
          ? { meta: await inspect(body), output: undefined }
          : request.op === "fill"
            ? await fill(body, request)
            : { meta: await verify(body, request), output: undefined };
      writeAll(encodeResultV2(result.meta as never, result.output));
      process.exitCode = 0;
    } catch (error) {
      try {
        writeAll(encodeResultV2(failureMeta(op, error) as never));
      } catch {
        // The pipe is gone. A partial frame is not a result.
        process.exitCode = 1;
        return;
      }
      // A refused document is data, not a crash: exit 0 so the supervisor can tell
      // "the executor refused" from "the executor died".
      process.exitCode = 0;
    }
  })();
});

// Exported for the artifact verifier, which loads this module to prove it resolves.
export { WORKER_PROTOCOL_V2 };
