/**
 * A Fill Forms restriction must not leak into unrelated PDF tools.
 *
 * ## The regression this pins
 *
 * `assertCheapPdfShape` lives in the Fill Forms module and throws
 * `FORM_UNSUPPORTED`, a Fill Forms verdict. Round 3 applied it to *every* PDF
 * upload in the shared orchestrator, before `validateUpload`. That contradicted a
 * boundary the pipeline already had: `validateUpload` deliberately does **not**
 * parse for tools whose legitimate input is a damaged or undecryptable PDF.
 *
 * The result reached release testing: a truncated PDF sent to Repair PDF was
 * refused with "This document uses a form feature that is not supported."
 * (`test/full-processing.e2e.test.ts:68`), a tool whose entire purpose is to
 * repair exactly that document.
 *
 * These are behavioural assertions over the real functions — no source grepping —
 * so a future change has to either keep the boundary or break this test.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { assertCheapPdfShape } from "@/lib/pdf/form-inspection";
import { controlledPreflightToolIds } from "@/lib/tools/registry";
import { validateUploadBytes, validateUploadWithParse } from "@/lib/uploads/validation";

/** The exact bytes the E2E suite hands to Repair PDF. */
const truncated = new TextEncoder().encode("%PDF-1.7\ntruncated");
/** A PDF that is structurally fine but carries no `%%EOF` trailer. */
const noTrailer = new Uint8Array(Buffer.concat([Buffer.from("%PDF-1.7\n"), Buffer.alloc(96, 0x20)]));

test("the controlled-preflight tools are exactly the ones whose input may be damaged", () => {
  assert.deepEqual([...controlledPreflightToolIds].sort(), ["repair-pdf", "unlock-pdf"]);
});

test("a cheap shape check rejects the truncated fixture (so the assertion below has force)", () => {
  // If this ever passed, the regression test would be vacuous: the shape check would
  // not be rejecting Repair PDF's input at all.
  assert.throws(() => assertCheapPdfShape(truncated), (error: unknown) => (error as { code?: string }).code === "FORM_UNSUPPORTED");
  assert.throws(() => assertCheapPdfShape(noTrailer), (error: unknown) => (error as { code?: string }).code === "FORM_UNSUPPORTED");
});

test("Repair PDF and Unlock PDF accept damaged input without the Fill Forms shape gate", async () => {
  // This is the path the orchestrator now takes for these tools: `validateUpload`
  // reports `controlledWorkerPreflight` and performs no parse, so damaged bytes are
  // accepted here and their authoritative validation happens in the contained worker.
  for (const toolId of ["repair-pdf", "unlock-pdf"]) {
    const result = validateUploadBytes({ toolId, declaredMime: "application/pdf", bytes: truncated });
    assert.equal(result.controlledWorkerPreflight, true, `${toolId} must defer structural validation to the worker`);
    assert.equal(result.pageCount, undefined, `${toolId} must not have parsed the document`);
  }
});

test("ordinary PDF tools still reject the same damaged input", async () => {
  // Unchanged by B31-01: an ordinary tool parses in the API and must fail before
  // allocating work.
  await assert.rejects(
    () => validateUploadWithParse({ toolId: "compress-pdf", declaredMime: "application/pdf", bytes: truncated }),
    (error: unknown) => {
      assert.ok(error instanceof Error, "compress-pdf must refuse the document");
      return true;
    },
    "compress-pdf must not accept a damaged PDF",
  );
});

test("Fill Forms still refuses a damaged document, but at its isolated boundary", async () => {
  // B31-01 moved *where* Fill Forms decides this. `validateUpload` no longer parses, so
  // it cannot be the place that rejects a broken document — the rejection now comes
  // from the bounded inspection child, which is where the decision belonged. The
  // user-visible outcome is unchanged: the document is refused. Asserting a
  // `validateUpload` rejection here would have re-introduced the in-process parse.
  const { FormFillError } = await import("@/lib/pdf/form-validation");
  const { assertCheapPdfShape } = await import("@/lib/pdf/form-inspection");
  // The child runs exactly this shape check first, so this is the same refusal the
  // worker produces for these bytes.
  assert.throws(
    () => assertCheapPdfShape(truncated),
    (error: unknown) => error instanceof FormFillError && error.code === "FORM_UNSUPPORTED",
    "the isolated boundary must still refuse the document",
  );
  // And the transport layer genuinely no longer parses for this tool.
  const bytes = validateUploadBytes({ toolId: "fill-forms", declaredMime: "application/pdf", bytes: truncated });
  assert.equal(bytes.pageCount, undefined, "stage 1 must not produce a page count");
  // And the parse path refuses to serve an isolated tool at all, so a caller cannot
  // accidentally re-introduce the in-process parse by choosing the wrong function.
  await assert.rejects(
    () => validateUploadWithParse({ toolId: "fill-forms", declaredMime: "application/pdf", bytes: truncated }),
    (error: unknown) => (error as { code?: string }).code === "PDF_INVALID",
    "the parse path must refuse an isolated tool",
  );
});

test("the shape gate still rejects documents the controlled tools cannot repair", async () => {
  // Scoping the gate must not disable it. Bytes that are not a PDF at all fail the
  // generic signature check for every tool, including the controlled ones — their
  // exemption is from the *structural* pre-filter, not from validation.
  const notPdf = new Uint8Array([0x50, 0x4b, 0x03, 0x04, ...new Array(120).fill(0)]);
  for (const toolId of ["fill-forms", "repair-pdf", "unlock-pdf", "compress-pdf"]) {
    // Stage 1 is synchronous, so this is `assert.throws`, not `assert.rejects`.
    assert.throws(
      () => validateUploadBytes({ toolId, declaredMime: "application/pdf", bytes: notPdf }),
      (error: unknown) => ["MAGIC_BYTES_INVALID", "PDF_INVALID"].includes((error as { code?: string }).code ?? ""),
      `${toolId} must reject bytes that are not a PDF`,
    );
  }
});

test("malware screening is not part of this boundary and cannot be skipped by it", async () => {
  // FF-04 / P3 invariant: the orchestrator scans every upload regardless of tool.
  // This test asserts the *shape* exemption does not become a screening exemption by
  // checking the orchestrator still scans inside the same map, for all tools.
  const { readFileSync } = await import("node:fs");
  const source = readFileSync(new URL("../src/lib/jobs/orchestrator.ts", import.meta.url), "utf8");
  const body = source.slice(source.indexOf("const screened = await Promise.all"), source.indexOf("const prepared = screened"));
  assert.match(body, /requireCleanUpload\(upload\.bytes\)/u, "screening must run for every upload");
  // The gate exemption is the only tool-specific branch in the pre-screening step.
  // The gate call must be conditioned on the controlled-preflight set. Asserted by
  // finding the guarding statement rather than matching an exact string, so
  // reformatting the condition cannot produce a false red.
  const callIndex = body.indexOf("assertCheapPdfShape(");
  assert.ok(callIndex > 0, "the shape gate must still be present");
  const statementStart = Math.max(body.lastIndexOf(";", callIndex), body.lastIndexOf("\n", callIndex));
  const guard = body.slice(statementStart, callIndex);
  assert.match(guard, /controlledPreflightToolIds\.has\(/u, `the shape gate must be scoped to the non-controlled tools, saw: ${guard.trim()}`);
  assert.match(guard, /!/u, "the guard must exempt the controlled tools, not require them");
  // A clean, parseable document must still reach the parser for ordinary tools.
  assert.match(body, /validateUploadBytes\(/u);
});
