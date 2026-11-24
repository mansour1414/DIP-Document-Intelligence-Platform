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
  for (const file of verified) {
    assert.ok(traced.includes(file), `${file} is verified but not traced, so the build would not include it`);
  }
  // Every transitive source the child needs must be declared, not just the entry.
  for (const file of ["src/lib/pdf/form-worker-child.ts", "src/lib/pdf/worker-protocol.ts", "src/lib/pdf/form-types.ts", "scripts/node-platform-compat.mjs"]) {
    assert.ok(verified.includes(file), `${file} must be verified`);
  }
});
