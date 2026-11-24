/**
 * Bounded child entry for untrusted PDF work (see `form-worker.ts`).
 *
 * One request, one process, one framed reply on **fd 3**. The framing, the bounds
 * and the strict metadata validation all live in `worker-protocol.ts`, so this
 * file only decides *what* to do — it never invents its own wire format.
 *
 * ## Operations
 *
 * - `inspect`: cheap parser-free shape checks, one `PDFDocument.load`, the
 *   structural restriction walk and the AcroForm inventory. Renderer-free — no
 *   native canvas, no fonts, so an inspection never pays for appearance
 *   generation it will not use.
 * - `fill`: reuses `fillFormPdf` unchanged. That function already performs the
 *   restriction probe, the load, the inventory gate, value validation, appearance
 *   generation (vector, with the Arabic raster fallback), flattening and its own
 *   reopen/verification pass. Running it here is the point of this round: the
 *   parser, the native canvas and the verification parse all execute inside the
 *   hard-bounded process instead of on the worker's main thread.
 *
 * ## Diagnostics
 *
 * Nothing but the framed reply goes to fd 3. stdout and stderr remain free for
 * incidental output and are never treated as authority by the parent. The
 * child's own error messages stay inside the allowlisted `FORM_*` codes; an
 * unexpected throw is reported as a generic code rather than forwarded.
 *
 * ## Why the reply is written with `writeSync`
 *
 * An async `process.stdout.write` can race `process.exit()`, truncating the frame.
 * `writeSync(3, …)` completes before the process exits, which is what makes "no
 * success frame followed by an abnormal exit" checkable at all.
 */
import { writeSync } from "node:fs";
import { PDFDocument } from "pdf-lib";
import { readFormInventory } from "@/lib/pdf/form-schema";
import { FormFillError } from "@/lib/pdf/form-validation";
import { fillFormPdf } from "@/lib/pdf/form-fill";
import { FORM_ERROR_MESSAGES, isFormFillErrorCode } from "@/lib/pdf/form-types";
import {
  assertCheapPdfShape,
  assertFillableRestrictions,
  scanStructureInDocument,
  scanEncryptionMarkers,
  type Restrictions,
} from "@/lib/pdf/form-inspection";
import {
  decodeControl,
  encodeResult,
  WorkerProtocolError,
  type FailureMeta,
  type WorkerControl,
  type WorkerMeta,
} from "@/lib/pdf/worker-protocol";
import { runtimeLimits } from "@/lib/runtime/config";
import { createHash } from "node:crypto";

/** The maximum document this child will read, from the shared runtime contract. */
const MAX_INPUT_BYTES = runtimeLimits.maxInputBytes;

function reasonOf(error: unknown): string {
  if (error && typeof error === "object" && "reason" in error) return String((error as { reason: unknown }).reason);
  return "STRUCTURE_UNREADABLE";
}

/** Inspect: renderer-free, one parse, no native appearance machinery. */
async function inspect(bytes: Uint8Array): Promise<WorkerMeta> {
  assertCheapPdfShape(bytes);
  if (scanEncryptionMarkers(bytes)) throw new FormFillError("FORM_RESTRICTED", FORM_ERROR_MESSAGES.FORM_RESTRICTED, { restriction: "ENCRYPTED" });

  let document: PDFDocument;
  try { document = await PDFDocument.load(bytes, { ignoreEncryption: false, updateMetadata: false }); }
  catch (error) {
    const encrypted = /encrypted/iu.test(error instanceof Error ? error.message : "");
    throw new FormFillError(
      encrypted ? "FORM_RESTRICTED" : "FORM_UNSUPPORTED",
      encrypted ? FORM_ERROR_MESSAGES.FORM_RESTRICTED : FORM_ERROR_MESSAGES.FORM_UNSUPPORTED,
      { parse: encrypted ? "ENCRYPTED" : "UNREADABLE" },
    );
  }

  // Same walk the route used to run, against the document that was already
  // loaded and is already in this process.
  let structural: { xfa: boolean; signed: boolean };
  try { structural = scanStructureInDocument(document); }
  catch (error) {
    const reason = reasonOf(error);
    throw new FormFillError("FORM_RESTRICTED", FORM_ERROR_MESSAGES.FORM_RESTRICTED, { structure: reason });
  }
  const restrictions: Restrictions = { encrypted: false, xfa: structural.xfa, signed: structural.signed };
  assertFillableRestrictions(restrictions);

  let inventory;
  try { inventory = readFormInventory(document); }
  catch (error) {
    if (error instanceof FormFillError) throw error;
    throw new FormFillError("FORM_UNSUPPORTED", FORM_ERROR_MESSAGES.FORM_UNSUPPORTED, {
      structure: error instanceof RangeError ? "FIELD_GRAPH_TOO_DEEP" : "INVENTORY_UNREADABLE",
    });
  }
  return { ok: true, op: "inspect", pages: document.getPageCount(), inventory };
}

/**
 * Fill: the real engine, in here.
 *
 * `fillFormPdf` does its own probe, load, inventory, validation, appearance and
 * flatten work, and reopens the result to verify it. All of that is bounded by
 * this process's deadline and heap cap — which is exactly what a `withTimeout`
 * Promise wrapper around it on the main thread could never provide.
 */
async function fill(bytes: Uint8Array, control: Extract<WorkerControl, { op: "fill" }>): Promise<{ meta: WorkerMeta; output: Uint8Array }> {
  const filled = await fillFormPdf(bytes, control.fields, { flatten: control.flatten });
  const pages = filled.report.pages;
  if (typeof pages !== "number" || !Number.isSafeInteger(pages) || pages <= 0) {
    throw new FormFillError("FORM_OUTPUT_UNVERIFIED", FORM_ERROR_MESSAGES.FORM_OUTPUT_UNVERIFIED, { carry: "PAGES_MISSING" });
  }
  const checksum = createHash("sha256").update(filled.bytes).digest("hex");
  const meta: WorkerMeta = {
    ok: true,
    op: "fill",
    pages,
    outBytes: filled.bytes.byteLength,
    checksum,
    report: {
      filled: filled.report.filled.length,
      untouched: filled.report.untouched,
      rasterAppearances: filled.report.rasterAppearances.length,
      flatten: filled.report.flatten,
    },
  };
  return { meta, output: filled.bytes };
}

/** Everything the parent is allowed to learn about a failure. */
function failureMeta(control: WorkerControl | undefined, error: unknown): FailureMeta {
  const op = control?.op ?? "inspect";
  if (error instanceof WorkerProtocolError) return { ok: false, op, code: "FORM_UNSUPPORTED", details: { boundary: error.reason } };
  if (error instanceof FormFillError && isFormFillErrorCode(error.code)) {
    return { ok: false, op, code: error.code, ...(error.details ? { details: error.details } : {}) };
  }
  // An unexpected throw is not forwarded: its message could quote document bytes.
  return { ok: false, op, code: "FORM_UNSUPPORTED", details: { boundary: "UNEXPECTED" } };
}

const chunks: Buffer[] = [];
process.stdin.on("data", (chunk: Buffer) => chunks.push(chunk));
process.stdin.on("end", () => {
  void (async () => {
    let control: WorkerControl | undefined;
    try {
      const { control: parsed, pdf } = decodeControl(Buffer.concat(chunks), MAX_INPUT_BYTES);
      control = parsed;
      const result = parsed.op === "inspect"
        ? { meta: await inspect(pdf), output: undefined }
        : await fill(pdf, parsed);
      writeSync(3, encodeResult(result.meta, result.output));
      process.exitCode = 0;
    } catch (error) {
      const meta = failureMeta(control, error);
      try { writeSync(3, encodeResult(meta)); }
      catch { process.exitCode = 1; return; }
      // A refused document is data, not a crash: exit 0 so the parent distinguishes
      // "child refused" from "child died".
      process.exitCode = 0;
    }
  })();
});
