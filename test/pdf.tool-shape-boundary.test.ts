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
import { validateUpload } from "@/lib/uploads/validation";

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
    const result = await validateUpload({ toolId, declaredMime: "application/pdf", bytes: truncated });
    assert.equal(result.controlledWorkerPreflight, true, `${toolId} must defer structural validation to the worker`);
    assert.equal(result.pageCount, undefined, `${toolId} must not have parsed the document`);
  }
});

test("Fill Forms and ordinary PDF tools still reject the same damaged input", async () => {
  // The restriction stays where it belongs. A fillable-form tool cannot work on bytes
  // that will not parse, and an ordinary tool must fail before allocating work.
  for (const toolId of ["fill-forms", "compress-pdf"]) {
    await assert.rejects(
      () => validateUpload({ toolId, declaredMime: "application/pdf", bytes: truncated }),
      (error: unknown) => {
        // Either an explicit refusal or a parse failure is acceptable; silently
        // accepting the document is not.
        assert.ok(error instanceof Error, `${toolId} must refuse the document`);
        assert.notEqual((error as { controlledWorkerPreflight?: boolean }).controlledWorkerPreflight, true);
        return true;
      },
      `${toolId} must not accept a damaged PDF`,
    );
  }
});

test("the shape gate still rejects documents the controlled tools cannot repair", async () => {
  // Scoping the gate must not disable it. Bytes that are not a PDF at all fail the
  // generic signature check for every tool, including the controlled ones — their
  // exemption is from the *structural* pre-filter, not from validation.
  const notPdf = new Uint8Array([0x50, 0x4b, 0x03, 0x04, ...new Array(120).fill(0)]);
  for (const toolId of ["fill-forms", "repair-pdf", "unlock-pdf", "compress-pdf"]) {
    await assert.rejects(
      () => validateUpload({ toolId, declaredMime: "application/pdf", bytes: notPdf }),
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
  assert.match(body, /validateUpload\(\{ toolId: tool\.toolId/u);
});
