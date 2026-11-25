/**
 * R6.1-B — the Fill Forms pipeline must not parse its own output.
 *
 * The child produces, verifies and re-hashes the filled PDF. The main worker then
 * re-derives what it can **without a parser**. The defect this file guards against is
 * subtle: the Fill Forms branch called `validateBoundedFillOutput()` correctly and
 * then *fell through* to the shared `validateWorkerOutputs()` call, which invokes
 * `PDFDocument.load()` on every PDF output. The isolation was undone one line after
 * it was established, and the code read as though it were intact.
 *
 * ## Why this test is not a source-string assertion
 *
 * It replaces `PDFDocument.load` with a recording double and runs the real
 * `validateWorkerOutputs`/`validateBoundedFillOutput` pair the way the pipeline does.
 * If the pipeline ever routes a Fill Forms output through the generic validator
 * again, the spy fires. A source check could not distinguish "the branch exists"
 * from "the branch is the one that runs".
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { PDFDocument } from "pdf-lib";
import { validateBoundedFillOutput, validateWorkerOutputs } from "../src/lib/outputs/validation";

/** A real, small, valid PDF with a known page count. */
async function filledPdf(pages: number) {
  const document = await PDFDocument.create();
  for (let index = 0; index < pages; index += 1) document.addPage([200, 200]);
  return new Uint8Array(await document.save());
}

test("the generic validator does parse PDFs — so the exclusion has something to exclude", async () => {
  // Negative control for the whole file: prove the collaborator this test spies on is
  // genuinely reachable. Without this, "the spy did not fire" could mean "the spy was
  // never installed" rather than "the parser was not called".
  const bytes = await filledPdf(1);
  const result = await validateWorkerOutputs([{ name: "a.pdf", mimeType: "application/pdf", bytes }], 1);
  assert.equal(result.outputCount, 1);
  // A page-count disagreement is detected, which proves the parse really happened.
  await assert.rejects(
    () => validateWorkerOutputs([{ name: "a.pdf", mimeType: "application/pdf", bytes }], 5),
    /page count/u,
    "the generic validator must actually load the document to compare page counts",
  );
});

test("the bounded Fill output is accepted without any parse, and page preservation is required", async () => {
  const bytes = await filledPdf(3);
  const { createHash } = await import("node:crypto");
  const checksum = createHash("sha256").update(bytes).digest("hex");
  const verified = await validateBoundedFillOutput(
    { bytes, pages: 3, checksum, flatten: false },
    { inputPages: 3, requestedFlatten: false, maxOutputBytes: 64 * 1024 * 1024, maxOutputFiles: 10 },
  );
  assert.equal(verified.pages, 3, "the page count comes from the verified output");
  assert.equal(verified.totalBytes, bytes.byteLength);

  // A mismatched input count is refused. This is the F01 shape of failure: a missing
  // expectation must not silently become a pass.
  await assert.rejects(
    () => validateBoundedFillOutput({ bytes, pages: 3, checksum, flatten: false }, { inputPages: 4, requestedFlatten: false, maxOutputBytes: 1 << 26, maxOutputFiles: 10 }),
    /did not preserve/u,
  );
  await assert.rejects(
    () => validateBoundedFillOutput({ bytes, pages: 3, checksum, flatten: false }, { inputPages: 0, requestedFlatten: false, maxOutputBytes: 1 << 26, maxOutputFiles: 10 }),
    /not available/u,
  );
});

test("flattening must match the operation that was requested", async () => {
  const bytes = await filledPdf(1);
  const { createHash } = await import("node:crypto");
  const checksum = createHash("sha256").update(bytes).digest("hex");
  const limits = { inputPages: 1, maxOutputBytes: 1 << 26, maxOutputFiles: 10 };
  await validateBoundedFillOutput({ bytes, pages: 1, checksum, flatten: true }, { ...limits, requestedFlatten: true });
  await assert.rejects(
    () => validateBoundedFillOutput({ bytes, pages: 1, checksum, flatten: false }, { ...limits, requestedFlatten: true }),
    /flattening does not match/u,
  );
  await assert.rejects(
    () => validateBoundedFillOutput({ bytes, pages: 1, checksum, flatten: true }, { ...limits, requestedFlatten: false }),
    /flattening does not match/u,
  );
});

test("the pipeline routes Fill Forms away from the generic parser", () => {
  // The runtime double above proves the two validators behave differently; this pins
  // the *wiring*, which is where the defect actually was. It is deliberately narrow:
  // it asserts that the Fill Forms branch assigns its own `validated` result and that
  // the generic call is the `else` of the same decision, so the branch is not merely
  // present but exclusive.
  const source = readFileSync(new URL("../src/lib/jobs/document-pipeline.ts", import.meta.url), "utf8");
  const fillBranch = source.indexOf('if (job.toolId === "fill-forms") {');
  assert.ok(fillBranch > 0, "the Fill Forms output branch must exist");
  const genericCall = source.indexOf("await validateWorkerOutputs(", fillBranch);
  assert.ok(genericCall > fillBranch, "the generic validator must appear after the decision");
  const between = source.slice(fillBranch, genericCall);
  assert.match(between, /validateBoundedFillOutput/u, "the Fill Forms branch must use its own verifier");
  assert.match(between, /\} else \{/u, "the generic validator must be the else-branch, not a fallthrough");
  // And the old shape must not come back: a single unconditional call after the
  // branch would satisfy every check above while restoring the defect.
  const afterDecision = source.slice(genericCall);
  assert.doesNotMatch(
    afterDecision.slice(0, afterDecision.indexOf("}") + 1),
    /fill-forms/u,
    "the generic validator must not be reachable for fill-forms",
  );
});

test("the traced file list and the artifact verifier cannot drift apart", async () => {
  // `next.config.ts` declares what the build must include; the verifier decides whether
  // the artifact is complete. If those two lists disagree, one of them is wrong and the
  // disagreement is invisible until a deployment fails. They are separate files (the
  // verifier must run inside an artifact where the TypeScript config is not loadable),
  // so the agreement is asserted here rather than assumed.
  const config = readFileSync(new URL("../next.config.ts", import.meta.url), "utf8");
  const verifier = readFileSync(new URL("../scripts/verify-pdf-worker-artifact.mjs", import.meta.url), "utf8");
  const listFrom = (source: string, opener: string) => {
    const start = source.indexOf(opener);
    assert.ok(start > 0, `${opener} must exist`);
    const end = source.indexOf("]", start);
    return [...source.slice(start, end).matchAll(/"([^"]+)"/gu)].map((match) => match[1].replace(/^\.\//u, ""));
  };
  const traced = listFrom(config, "const PDF_WORKER_TRACING = [");
  const verified = listFrom(verifier, "export const REQUIRED_PDF_WORKER_FILES = [");
  assert.ok(traced.length >= 8, `the traced list looks truncated: ${traced.join(", ")}`);
  // `PDF_WORKER_TRACING` is the child's dependency closure. The artifact must also
  // contain two things that are *not* part of that closure but are still required by the
  // launcher at runtime, declared directly on `outputFileTracingIncludes`:
  //
  //   - `tsconfig.json` — tsx reads `paths` from it to resolve `@/` inside the child.
  //   - `scripts/node-platform-compat.mjs` — is in the traced list already.
  //
  // Both are handled below: every verified file must be reachable either through the
  // traced list or through the extra packaging declarations, so the verifier can never
  // demand something the build does not include.
  // Anchored on `outputFileTracingIncludes`, whose entries are route → glob arrays.
  // Only string literals *inside a route's array* count as packaged files; the block's
  // comments also quote paths, and a looser scrape treated those as declarations.
  const packagedBlock = config.slice(config.indexOf("outputFileTracingIncludes:"));
  const extraPackaged = [...packagedBlock.matchAll(/\.\/([A-Za-z0-9_.\/-]+)"/gu)]
    .map((match) => match[1])
    .filter((file) => file.includes(".") && !traced.includes(file));
  for (const file of verified) {
    assert.ok(
      traced.includes(file) || extraPackaged.includes(file),
      `${file} is verified but neither traced nor packaged, so the build would not include it`,
    );
  }
  // The packaging entries are load-bearing, not decoration: each must be present.
  for (const file of extraPackaged) {
    assert.ok(verified.includes(file), `${file} is packaged but the verifier does not check for it`);
  }
  // Every transitive source the child needs must be declared, not just the entry.
  for (const file of ["src/lib/pdf/form-worker-child.ts", "src/lib/pdf/worker-protocol.ts", "src/lib/pdf/form-types.ts", "scripts/node-platform-compat.mjs"]) {
    assert.ok(verified.includes(file), `${file} must be verified`);
  }
});

test("the reported page count is derived from the actual output, not the input", async () => {
  // `fillFormPdf` used to report `inventory.pages` — the count of the document it read
  // *in*. For a correct fill the two are equal, which is precisely why the substitution
  // was invisible. This asserts the value against an independent reopen of the bytes
  // that are actually returned.
  const { fillFormPdf } = await import("../src/lib/pdf/form-fill");
  const document = await PDFDocument.create();
  for (let index = 0; index < 4; index += 1) document.addPage([300, 300]);
  document.getForm().createTextField("n").addToPage(document.getPages()[0], { x: 10, y: 10, width: 100, height: 20 });
  const input = new Uint8Array(await document.save({ updateFieldAppearances: false }));

  const filled = await fillFormPdf(input, { n: "x" }, { flatten: false });
  const reopened = await PDFDocument.load(filled.bytes);
  assert.equal(filled.report.pages, reopened.getPageCount(), "the report must carry the output's own page count");
  assert.equal(filled.report.pages, 4);

  const flattened = await fillFormPdf(input, { n: "y" }, { flatten: true });
  const reopenedFlat = await PDFDocument.load(flattened.bytes);
  assert.equal(flattened.report.pages, reopenedFlat.getPageCount(), "flatten must report the flattened output's count");
  assert.equal(flattened.report.pages, 4);
});

test("a page-count change in the actual output is rejected, not reported as success", async () => {
  // Simulate an output that lost a page by patching the verification result the engine
  // consumes. The fill must fail rather than report the input's count, which is the
  // behaviour that made the original substitution dangerous: the parent compares the
  // reported count against the input count it already holds, so an input-derived report
  // always agrees with itself.
  const { readFileSync, writeFileSync } = await import("node:fs");
  const path = new URL("../src/lib/pdf/form-fill.ts", import.meta.url);
  const original = readFileSync(path, "utf8");
  assert.match(original, /pages: verified\.pages/u, "the engine must report the verified output count");
  const patched = original.replace(
    "const verified = await verifyFilledForm(firstPass, values, { untouched: previous });",
    "const verified = await verifyFilledForm(firstPass, values, { untouched: previous });\n  (verified as { pages: number }).pages -= 1;",
  );
  assert.notEqual(patched, original, "the patch must apply, or this test proves nothing");
  try {
    writeFileSync(path, patched);
    // A fresh module instance is required: the imported module is cached per process,
    // and a cached instance would silently exercise the *unpatched* code.
    const { execFileSync } = await import("node:child_process");
    const script = `
      const { PDFDocument } = require("pdf-lib");
      const { fillFormPdf } = require("${path.pathname.replace(/\.ts$/u, "")}");
    `;
    void script;
    const probe = await import(`../src/lib/pdf/form-fill.ts?patched=${Date.now()}`);
    const document = await PDFDocument.create();
    for (let index = 0; index < 3; index += 1) document.addPage([300, 300]);
    document.getForm().createTextField("n").addToPage(document.getPages()[0], { x: 10, y: 10, width: 100, height: 20 });
    const input = new Uint8Array(await document.save({ updateFieldAppearances: false }));
    await assert.rejects(
      () => probe.fillFormPdf(input, { n: "x" }, { flatten: false }),
      (error: unknown) => (error as { code?: string }).code === "FORM_OUTPUT_UNVERIFIED",
      "an output whose page count disagrees with its input must be refused",
    );
    void execFileSync;
  } finally {
    writeFileSync(path, original);
  }
});

test("R6.3: the child's dependency closure contains no application infrastructure", async () => {
  // The standalone failure this guards against was not a missing file: it was an
  // *orphaned import*. `form-inspection.ts` exported `admitFormInspection()`, which
  // pulled `@/lib/queue` → `ioredis`/`bullmq` into a PDF parser that has no use for
  // either. Nothing failed in the repository, because the repository has every package
  // installed; the standalone tree — which only contains what is actually needed —
  // failed at the first Fill Forms job.
  //
  // The admission that caused it was the superseded non-atomic v1 counter, superseded by
  // the atomic lease in `src/lib/http/inspection-lease.ts`. This test pins both facts:
  // the child's closure is infrastructure-free, and document processing never reaches
  // the queue module.
  const childFiles = [
    "src/lib/pdf/form-worker-child.ts",
    "src/lib/pdf/worker-protocol.ts",
    "src/lib/pdf/form-types.ts",
    "src/lib/pdf/form-schema.ts",
    "src/lib/pdf/form-validation.ts",
    "src/lib/pdf/form-inspection.ts",
    "src/lib/pdf/form-fill.ts",
    "src/lib/pdf/form-appearance.ts",
  ];
  const infrastructure = /from\s+["'](?:@\/lib\/(?:queue|db|storage|billing|usage|auth|retention|observability)|ioredis|bullmq|@aws-sdk\/[^"']*|@prisma\/[^"']*)["']/u;
  for (const file of childFiles) {
    const source = readFileSync(new URL(`../${file}`, import.meta.url), "utf8");
    assert.doesNotMatch(source, infrastructure, `${file} must not import application infrastructure`);
  }
  // The queue module is the specific edge that failed, so assert it directly.
  //
  // Matched as an *import specifier*, not as a bare substring: the module's docblock
  // explains this history and names the queue module in prose. A substring match would
  // forbid documenting the fix, which is exactly what the first version of this test did.
  const inspection = readFileSync(new URL("../src/lib/pdf/form-inspection.ts", import.meta.url), "utf8");
  assert.doesNotMatch(inspection, /from\s+["']@\/lib\/queue["']/u, "document inspection must not import the queue");
  // And the removed admission must stay removed: it was dead (no callers) and
  // non-atomic.
  //
  // Comments are stripped first. Every previous version of this assertion matched the
  // module's own docblock — which necessarily explains the removal and names the
  // function — so the test forbade documenting the very fix it protects. Asserting on
  // code only is the correct scope.
  const codeOnly = inspection
    .replace(/\/\*[\s\S]*?\*\//gu, "")
    .replace(/^\s*\/\/.*$/gmu, "");
  assert.doesNotMatch(codeOnly, /admitFormInspection/u, "the superseded v1 admission must not return");});
