/**
 * B31-01 — Fill Forms must not parse untrusted PDFs in the API process.
 *
 * ## What was wrong
 *
 * `validateUpload` called `PDFDocument.load()` inside the request handler. For Fill
 * Forms that ran *before* the bounded inspection child, so the document was parsed
 * twice: once with web-server privileges and once in the child whose isolation the
 * tool is supposed to rely on. The isolation was therefore decorative.
 *
 * ## What these tests assert
 *
 * Behaviour, not source text. The decisive trick below is that the authoritative
 * page count supplied to `validateUpload` deliberately *disagrees* with the real
 * page count of the fixture: if any in-process parse still happens, the function
 * returns the fixture's own count and the assertion fails.
 *
 * The corollary matters as much: removing the parse must not remove the limit. The
 * isolated report is what plan enforcement and the file row receive, so it is
 * validated (integer, non-negative) and still compared against the tool limit.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { PDFDocument } from "pdf-lib";
import { controlledPreflightToolIds, isolatedInspectionToolIds } from "@/lib/tools/registry";
import { validateInspectedPdf, validateUploadBytes, validateUploadWithParse } from "@/lib/uploads/validation";

/** A real, parseable two-page PDF: the ground truth an accidental parse would report. */
async function twoPagePdf(): Promise<Uint8Array> {
  const document = await PDFDocument.create();
  document.addPage();
  document.addPage();
  return document.save();
}

/** The orchestrator's exact Fill Forms path: parser-free stage, then stage 2. */
function validateFillForms(bytes: Uint8Array, inspectedPages: number) {
  const stage1 = validateUploadBytes({ toolId: "fill-forms", declaredMime: "application/pdf", bytes });
  return { result: validateInspectedPdf({ toolId: "fill-forms", bytes, bytes_: stage1, inspectedPages }), stage1 };
}

test("the isolated-inspection set is Fill Forms, and disjoint from controlled preflight", () => {
  assert.deepEqual([...isolatedInspectionToolIds], ["fill-forms"]);
  const overlap = [...isolatedInspectionToolIds].filter((tool) => controlledPreflightToolIds.has(tool));
  assert.deepEqual(overlap, [], "a tool cannot be both parse-exempt for damage and parse-isolated");
});

test("Fill Forms does not parse the document in-process", async () => {
  const bytes = await twoPagePdf();
  // The fixture has two pages. The authoritative isolated result says nine.
  const { result, stage1 } = validateFillForms(bytes, 9);
  assert.equal(result.pageCount, 9, "the page count must come from isolated inspection, not from an in-process parse (which would report 2)");
  assert.equal(stage1.pageCount, undefined, "the parser-free stage must never produce a page count");
});

test("the authoritative page count is still bounded and still enforced", async () => {
  const bytes = await twoPagePdf();
  // A page limit must not be bypassed by the isolation change.
  assert.throws(
    () => validateFillForms(bytes, 10_000),
    (error: unknown) => (error as { code?: string }).code === "PAGE_LIMIT_EXCEEDED",
    "an oversized isolated page count must still be refused",
  );
  // A count that could not have come from a real child reply is refused rather than
  // coerced, so a malformed boundary result cannot become a silent pass.
  for (const bogus of [-1, 0, 2.5, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 2]) {
    assert.throws(
      () => validateFillForms(bytes, bogus),
      (error: unknown) => (error as { code?: string }).code === "PAGE_LIMIT_EXCEEDED",
      `inspectedPages=${bogus} must be rejected`,
    );
  }
});

test("a missing isolated page count is unknown, never guessed", async () => {
  const bytes = await twoPagePdf();
  const stage1 = validateUploadBytes({ toolId: "fill-forms", declaredMime: "application/pdf", bytes });
  // Not 2: that would mean the API parsed it. Not a fabricated number either.
  assert.equal(stage1.pageCount, undefined, "without an isolated result the count is unknown");
  // And stage 2 refuses rather than defaulting: a missing count is a refusal, not a
  // quota pass (`pageCount ?? 0` would make the page limit disappear).
  assert.throws(
    () => validateInspectedPdf({ toolId: "fill-forms", bytes, bytes_: stage1, inspectedPages: undefined as unknown as number }),
    (error: unknown) => (error as { code?: string }).code === "PAGE_LIMIT_EXCEEDED",
    "a missing isolated page count must fail closed",
  );
});

test("ordinary PDF tools still parse in the API, unchanged", async () => {
  const bytes = await twoPagePdf();
  const result = await validateUploadWithParse({ toolId: "compress-pdf", declaredMime: "application/pdf", bytes });
  assert.equal(result.pageCount, 2, "the shared path for ordinary tools must be untouched by this correction");
});

test("controlled-preflight tools keep their damage-tolerant contract", async () => {
  const damaged = new TextEncoder().encode("%PDF-1.7\ntruncated");
  for (const toolId of ["repair-pdf", "unlock-pdf"]) {
    const result = validateUploadBytes({ toolId, declaredMime: "application/pdf", bytes: damaged });
    assert.equal((result as { controlledWorkerPreflight?: boolean }).controlledWorkerPreflight, true);
    assert.equal(result.pageCount, undefined, "the worker, not the API, decides what these documents are");
  }
});

test("generic validation still rejects bytes that are not a PDF, for every tool", async () => {
  const notPdf = new Uint8Array([0x50, 0x4b, 0x03, 0x04, ...new Array(200).fill(0)]);
  for (const toolId of ["fill-forms", "repair-pdf", "unlock-pdf", "compress-pdf"]) {
    assert.throws(
      () => validateUploadBytes({ toolId, declaredMime: "application/pdf", bytes: notPdf }),
      (error: unknown) => (error as { code?: string }).code === "MAGIC_BYTES_INVALID",
      `${toolId} must reject non-PDF bytes before anything else`,
    );
  }
});

test("the orchestrator screens before isolating, and isolates before generic validation", async () => {
  // Ordering *is* the guarantee here: the child must run before the generic parse, and
  // malware screening must run before both. Asserted by position in the real source,
  // because the three steps live in one function and no side effect distinguishes
  // their order from outside.
  const source = readFileSync(new URL("../src/lib/jobs/orchestrator.ts", import.meta.url), "utf8");
  const screen = source.indexOf("requireCleanUpload(");
  const isolate = source.indexOf("assertFillableInput(screened[0].upload.bytes)");
  // The *parse* stage is what must follow isolation; the parser-free stage is
  // intentionally the first thing that runs.
  const parseStage = source.indexOf("validateUploadWithParse({ toolId: tool.toolId");
  const stageOne = source.indexOf("validateUploadBytes({ toolId: tool.toolId");
  assert.ok(screen > 0, "screening must exist");
  assert.ok(isolate > 0, "isolated inspection must be invoked from the submission path");
  assert.ok(stageOne > 0 && parseStage > 0, "both validation stages must exist");
  assert.ok(screen < isolate, "screening must precede isolation");
  assert.ok(isolate < parseStage, "isolation must precede the parse stage, or the API parses first");
  assert.ok(stageOne < screen, "the parser-free stage must precede screening");
  // Exactly one invocation: the child must not be run twice per submission.
  const calls = source.split("assertFillableInput(").length - 1;
  assert.equal(calls, 2, "one definition plus exactly one call site");
});
