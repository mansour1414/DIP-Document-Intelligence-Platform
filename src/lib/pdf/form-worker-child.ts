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
import { FORM_ERROR_MESSAGES, FORM_VALUE_ISSUES, isFormFillErrorCode } from "@/lib/pdf/form-types";
import {
  assertCheapPdfShape,
  assertFillableRestrictions,
  scanStructureInDocument,
  scanEncryptionMarkers,
  type Restrictions,
} from "@/lib/pdf/form-inspection";
import {
  WORKER_LIMITS,
  decodeControl,
  encodeResult,
  WorkerProtocolError,
  type FailureMeta,
  type WorkerControl,
  type WorkerMeta,
} from "@/lib/pdf/worker-protocol";
import { createHash } from "node:crypto";

/** The maximum document this child will read, from the shared runtime contract. */

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

/**
 * Everything the parent is allowed to learn about a failure.
 *
 * The keys here are the parent's allowlist, deliberately: the parent rebuilds
 * `details` field by field, so emitting a key it does not know (`boundary`, in the
 * previous version) meant the diagnostic silently vanished in transit. Writing the
 * sanitized shape on both sides — rather than "child says anything, parent filters"
 * — keeps the contract visible in one place instead of only at the receiver.
 */
function failureMeta(control: WorkerControl | undefined, error: unknown): FailureMeta {
  const op = control?.op ?? "inspect";
  if (error instanceof WorkerProtocolError) return { ok: false, op, code: "FORM_UNSUPPORTED", details: { reason: error.reason } };
  if (error instanceof FormFillError && isFormFillErrorCode(error.code)) {
    const issues = allowlistedIssues(error.details);
    return { ok: false, op, code: error.code, ...(issues.length ? { details: { issues } } : {}) };
  }
  // An unexpected throw is not forwarded: its message could quote document bytes.
  return { ok: false, op, code: "FORM_UNSUPPORTED", details: { reason: "UNEXPECTED" } };
}

/** Project `FormFillError.details` onto the allowlisted `issues` codes. */
function allowlistedIssues(details: unknown): string[] {
  if (!details || typeof details !== "object") return [];
  const candidates = (details as { issues?: unknown; issue?: unknown }).issues ?? (details as { issue?: unknown }).issue;
  const list = Array.isArray(candidates) ? candidates : [candidates];
  return list.filter((entry): entry is string => typeof entry === "string" && (FORM_VALUE_ISSUES as readonly string[]).includes(entry));
}

/**
 * Write the whole frame to fd 3, or fail.
 *
 * `writeSync` returns the number of bytes written and is explicitly permitted to
 * write fewer than the whole buffer — on a pipe that happens when the frame is
 * larger than the pipe buffer and the reader has not drained it yet. The previous
 * version called it once and ignored the return value, so a large filled PDF (or a
 * large inventory) produced a *truncated* frame that the parent correctly rejected
 * as `TRUNCATED`. The bug and the parent's rejection were both real; only the child
 * needed fixing.
 *
 * EPIPE (the parent died or timed out) propagates: a partial frame written into a
 * closed pipe is a failed run, and the caller turns that into a non-zero exit rather
 * than a half-success.
 */
function writeAll(frame: Buffer): void {
  let offset = 0;
  while (offset < frame.byteLength) {
    offset += writeSync(3, frame, offset, frame.byteLength - offset);
  }
}

/**
 * Accumulate stdin, but stop at the declared ceiling.
 *
 * The child previously pushed every chunk it received, so the *parent's* limit was
 * the only thing standing between a hostile or buggy writer and an unbounded heap in
 * the child. The pipe is the channel the parent controls least, so the bound belongs
 * on both ends. Exceeding it is a protocol error, reported as data like any other.
 */
/**
 * How many bytes may still arrive.
 *
 * The bound cannot be a constant: this process is launched with a minimal environment
 * and so cannot see the parent's `MAX_INPUT_BYTES`. It is learned from the control
 * header as soon as the first bytes arrive, which is why the ceiling below is only a
 * provisional bound — large enough for any frame the transport permits, tight enough
 * that a peer which never finishes its header cannot make us buffer indefinitely.
 *
 * Enforcing it here (rather than only after the frame is complete) matters because the
 * parent is the party that decides the limit: if the child used its own compiled
 * default, raising the limit on the parent would leave the child refusing documents the
 * parent had already accepted, and lowering it would let the child buffer more than the
 * parent ever intended to send.
 */
let effectiveLimit = 4 + WORKER_LIMITS.controlBytes; // header alone, until we can read it
let headerRead = false;
const chunks: Buffer[] = [];
let received = 0;
let overLimit = false;
/** Peek at the control header; once parseable, adopt the bound it declares. */
function adoptDeclaredBound(): void {
  if (headerRead || received < 4) return;
  const head = chunks.length === 1 ? chunks[0] : Buffer.concat(chunks);
  const controlLen = head.readUInt32BE(0);
  if (controlLen === 0 || controlLen > WORKER_LIMITS.controlBytes) { overLimit = true; return; }
  if (received < 4 + controlLen) { effectiveLimit = 4 + controlLen + WORKER_LIMITS.maxInputBytesCeiling; return; }
  headerRead = true;
  let declared: number;
  try {
    const parsed = JSON.parse(head.subarray(4, 4 + controlLen).toString("utf8")) as { maxInputBytes?: unknown };
    if (typeof parsed.maxInputBytes !== "number" || !Number.isSafeInteger(parsed.maxInputBytes) || parsed.maxInputBytes <= 0) {
      overLimit = true;
      return;
    }
    declared = parsed.maxInputBytes;
  } catch { overLimit = true; return; }
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
    let control: WorkerControl | undefined;
    try {
      if (overLimit) throw new WorkerProtocolError("The input exceeds the transport limit.", "PDF_TOO_LARGE");
      // Decode against the transport ceiling, then re-check against the bound the
      // parent actually declared in the frame. Decoding first avoids parsing the
      // header twice; the second check is what makes the *declared* number
      // authoritative, so parent and child cannot enforce different limits.
      const { control: parsed, pdf } = decodeControl(Buffer.concat(chunks), WORKER_LIMITS.maxInputBytesCeiling);
      if (pdf.byteLength > parsed.maxInputBytes) {
        throw new WorkerProtocolError("The document exceeds the declared input limit.", "PDF_TOO_LARGE");
      }
      control = parsed;
      const result = parsed.op === "inspect"
        ? { meta: await inspect(pdf), output: undefined }
        : await fill(pdf, parsed);
      writeAll(encodeResult(result.meta, result.output));
      process.exitCode = 0;
    } catch (error) {
      const meta = failureMeta(control, error);
      try { writeAll(encodeResult(meta)); }
      catch { process.exitCode = 1; return; }
      // A refused document is data, not a crash: exit 0 so the parent distinguishes
      // "child refused" from "child died".
      process.exitCode = 0;
    }
  })();
});
