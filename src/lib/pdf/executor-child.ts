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
import { FORM_ERROR_MESSAGES, isFormFillErrorCode } from "./form-types";
import { FormFillError } from "./form-validation";
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
  const pages = result.report.pages;
  if (typeof pages !== "number" || !Number.isSafeInteger(pages) || pages <= 0) {
    throw new FormFillError("FORM_OUTPUT_UNVERIFIED", FORM_ERROR_MESSAGES.FORM_OUTPUT_UNVERIFIED);
  }
  return {
    meta: {
      ok: true as const,
      op: "fill" as const,
      pages,
      outBytes: result.bytes.byteLength,
      // The digest of the produced document, computed here so the supervisor can bind the
      // terminal commit to the exact bytes rather than to a claim about them.
      checksum: sha256Hex(result.bytes),
      // The wire report is counts, matching what `form-worker-child` emits. `FillReport.filled`
      // is the detail array and `rasterAppearances` is a list of field names; sending either
      // straight through would fail the decoder's "is this an integer" check — which is what it
      // is for. The projection is explicit so the two shapes cannot silently diverge.
      report: {
        filled: result.report.filled.length,
        untouched: result.report.untouched,
        rasterAppearances: result.report.rasterAppearances.length,
        flatten: result.report.flatten,
      },
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
/**
 * The refusal frame for a failed operation.
 *
 * The code must come from the closed `FormFillErrorCode` set — the supervisor's decoder rejects
 * anything else, which is the behaviour that caught `FORM_TOO_LARGE` here: it looked plausible
 * and is not a member. Mapping through `isFormFillErrorCode` means a wrong guess fails at the
 * boundary rather than producing a refusal the supervisor cannot parse.
 *
 * A document that exceeds the transport limit is not a form the engine could not read; it is
 * input this endpoint will not accept at all, so it reports the same content-free refusal as
 * any other unreadable input rather than inventing a code.
 */
function failureMeta(op: WorkerRequestV2["op"] | undefined, error: unknown) {
  const known = error instanceof WorkerProtocolError;
  const code = error instanceof FormFillError && isFormFillErrorCode(error.code) ? error.code : "FORM_UNSUPPORTED";
  return {
    ok: false as const,
    op: (op ?? "inspect") as "inspect" | "fill" | "verify",
    code,
    details: { reason: known ? error.reason : error instanceof FormFillError ? error.code : "UNEXPECTED" },
  };
}

// ---------------------------------------------------------------------------------------
// Input accumulation
// ---------------------------------------------------------------------------------------

/**
 * The input bound, learned from the frame as it arrives.
 *
 * ## Why this is not simply "buffer until stdin ends"
 *
 * The child runs inside the untrusted boundary and the supervisor may be compromised or simply
 * crash. Buffering without a bound means a peer that never finishes its frame can make this
 * process allocate until the container's memory limit kills it — which the supervisor would
 * then have to distinguish from a document that is genuinely too large.
 *
 * So the bound tightens in steps, and is *exact* at each step:
 *
 *   1. before the length prefix: `4 + controlBytes` — enough for any legal header, no more;
 *   2. once the prefix is readable: `4 + controlLen`, so the control frame can complete;
 *   3. once the control JSON is complete: `4 + controlLen + bodyBytes`, the exact frame.
 *
 * The declared body length is read from `bodyBytes` — the field the codec actually writes. An
 * earlier version looked for `maxInputBytes`, which no encoder produces, so every legal frame
 * was treated as a protocol violation and every real request was refused.
 */
let effectiveLimit = 4 + WORKER_LIMITS.controlBytes;
let controlLength: number | null = null;
let controlComplete = false;
const chunks: Buffer[] = [];
let received = 0;
let overLimit = false;

function tightenedBound(): void {
  if (overLimit) return;
  const head = chunks.length === 1 ? chunks[0] : Buffer.concat(chunks);

  if (controlLength === null) {
    if (head.byteLength < 4) return;
    const declared = head.readUInt32BE(0);
    // Zero or oversized control metadata cannot be a legal frame in any version, so the bound
    // does not need to grow to discover that.
    if (declared === 0 || declared > WORKER_LIMITS.controlBytes) {
      fail();
      return;
    }
    controlLength = declared;
    // The bound deliberately stays at the pre-auth ceiling until the control frame is
    // *complete*. The body length is not known yet, and the control ceiling already bounds how
    // much can arrive before it is. Tightening to `4 + controlLength` here was a real bug: a
    // frame delivered in a single write — the common case — was flagged as oversized because
    // the body arrived in the same chunk the bound was tightened for.
    effectiveLimit = 4 + WORKER_LIMITS.controlBytes;
  }

  if (!controlComplete) {
    if (head.byteLength < 4 + controlLength) return;
    controlComplete = true;
    try {
      const parsed = JSON.parse(head.subarray(4, 4 + controlLength).toString("utf8")) as { bodyBytes?: unknown };
      const declaredBody = parsed.bodyBytes;
      if (typeof declaredBody !== "number" || !Number.isSafeInteger(declaredBody) || declaredBody < 0) {
        fail();
        return;
      }
      if (declaredBody > WORKER_LIMITS.maxInputBytesCeiling) {
        fail();
        return;
      }
      // The exact frame length, now that both halves are declared.
      effectiveLimit = 4 + controlLength + declaredBody;
    } catch {
      // Not JSON. The decoder rejects it; a malformed frame must not widen the allocation bound.
      return;
    }
  }

  if (received > effectiveLimit) fail();
}

/** Record a bound violation and drop what was buffered, defeating the bound it just broke. */
function fail(): void {
  overLimit = true;
  chunks.length = 0;
}

/**
 * Self-check mode: load the module, prove the engine imports, exit.
 *
 * Declared before the stdin wiring because that wiring must not run in this mode. Registering
 * it anyway meant the self-check decoded an empty stdin frame, failed, and exited 1 while
 * printing a success line — a build gate that could never pass, and worse, one that would have
 * "failed" for a reason unrelated to the artifact it checks.
 */
const SELF_CHECK = process.argv.includes("--self-check");

if (!SELF_CHECK) process.stdin.on("data", (chunk: Buffer) => {
  if (overLimit) return;
  received += chunk.byteLength;
  chunks.push(chunk);
  if (!overLimit) tightenedBound();
  if (received > effectiveLimit) {
    // Discard what was buffered: keeping it would defeat the bound it just violated.
    overLimit = true;
    chunks.length = 0;
  }
});

if (!SELF_CHECK) process.stdin.on("end", () => {
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

// ---------------------------------------------------------------------------------------
// Build-time self-check
// ---------------------------------------------------------------------------------------
//
// The artifact verifier executes the built bundle rather than reading it, because a module that
// imports cleanly and crashes on first use is exactly the failure a file-existence check misses.
// `--self-check` proves the module loads, its protocol constant is the expected one, and the
// heavy native surface resolves — without opening fd 3 or waiting for stdin.
//
// This runs at image build time only. It is not an IPC path and accepts no input.
if (SELF_CHECK) {
  void (async () => {
    try {
      // Force the three lazy engine imports, which is what a real request would touch. A
      // missing font, a wrong-libc native binary or an ESM/CJS mismatch throws here.
      await import("./form-inspection");
      await import("./form-fill");
      await import("./form-verify");
      process.stdout.write(JSON.stringify({ selfCheck: true, protocolVersion: WORKER_PROTOCOL_V2 }) + "\n");
      process.exitCode = 0;
    } catch (error) {
      process.stderr.write(`self-check failed: ${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 1;
    }
  })();
}
