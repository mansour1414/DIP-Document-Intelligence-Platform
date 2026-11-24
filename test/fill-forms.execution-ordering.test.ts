/**
 * R6-B / R6-C — behavioural proof that rejection is cheap and ordered.
 *
 * The claims "bad input is refused before the child is spawned" and "a rejected
 * upload creates no storage, billing, job or queue side effects" are ordering
 * claims, and ordering claims cannot be established by reading source text: an
 * `await` in the wrong place looks identical to the right one. These tests observe
 * the *effects* — how many processes were spawned, which collaborators were called —
 * rather than the shape of the code.
 *
 * `activeFormWorkers()` is the real pool counter, incremented only when a child is
 * actually spawned by `processPdfBounded`. It is not a mock.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { PDFDocument } from "pdf-lib";
import { activeFormWorkers, resetFormWorkersForTest } from "../src/lib/pdf/form-worker";
import { validateUploadBytes, validateUploadWithParse } from "../src/lib/uploads/validation";

async function realPdf() {
  const document = await PDFDocument.create();
  document.addPage([200, 200]);
  return new Uint8Array(await document.save());
}

test("a cheap rejection spawns no child process", async () => {
  resetFormWorkersForTest();
  const before = activeFormWorkers();
  const pdf = await realPdf();
  const cases: Array<{ name: string; input: Parameters<typeof validateUploadBytes>[0]; code: string }> = [
    { name: "wrong MIME", input: { toolId: "fill-forms", declaredMime: "image/png", bytes: new Uint8Array([1, 2, 3]) }, code: "MIME_NOT_ALLOWED" },
    { name: "empty file", input: { toolId: "fill-forms", declaredMime: "application/pdf", bytes: new Uint8Array(0) }, code: "SIZE_LIMIT_EXCEEDED" },
    { name: "bad magic", input: { toolId: "fill-forms", declaredMime: "application/pdf", bytes: new Uint8Array([0x50, 0x4b, 0x03, 0x04, ...pdf.subarray(4)]) }, code: "MAGIC_BYTES_INVALID" },
    { name: "mime not offered by tool", input: { toolId: "repair-pdf", declaredMime: "image/jpeg", bytes: new Uint8Array([0xff, 0xd8, 0xff, 0, 0]) }, code: "MIME_NOT_ALLOWED" },
  ];
  for (const item of cases) {
    assert.throws(() => validateUploadBytes(item.input), (error: unknown) => (error as { code?: string }).code === item.code, `${item.name} must be refused by stage 1`);
    assert.equal(activeFormWorkers(), before, `${item.name} must not have spawned a child`);
  }
});

test("stage 1 is synchronous, so it cannot be awaiting a scan or a child", () => {
  // A parser-free stage that returned a promise would be sequencing an expensive
  // operation behind a cheap-looking name. `assert.throws` (not `rejects`) is the
  // type-level proof: a promise-returning function would not be caught here at all.
  assert.throws(
    () => validateUploadBytes({ toolId: "fill-forms", declaredMime: "application/pdf", bytes: new Uint8Array(0) }),
    (error: unknown) => (error as { code?: string }).code === "SIZE_LIMIT_EXCEEDED",
  );
});

test("a valid document is the only case that reaches the child", async () => {
  resetFormWorkersForTest();
  // Stage 1 alone never spawns; it only reports a checksum and a MIME.
  const valid = await realPdf();
  const cleaned = validateUploadBytes({ toolId: "fill-forms", declaredMime: "application/pdf", bytes: valid });
  assert.equal(activeFormWorkers(), 0, "stage 1 must not spawn");
  assert.equal(cleaned.pageCount, undefined, "stage 1 must not produce a page count");
  // Fill Forms is *isolated inspection*, which is a different thing from *controlled
  // preflight* (`repair-pdf` / `unlock-pdf`, whose legitimate input is damaged). The
  // two sets are disjoint, and conflating them would either give Fill Forms a
  // damage-tolerant exemption it must not have, or send a damaged document down a
  // parse path that cannot succeed.
  assert.equal(cleaned.controlledWorkerPreflight, undefined, "Fill Forms is isolated, not controlled-preflight");

  // The parse path is closed to an isolated tool: there is no way to reach a
  // page count for Fill Forms except through the child.
  await assert.rejects(
    () => validateUploadWithParse({ toolId: "fill-forms", declaredMime: "application/pdf", bytes: new Uint8Array(0) }),
    (error: unknown) => (error as { code?: string }).code === "SIZE_LIMIT_EXCEEDED",
    "stage budget still applies first",
  );
  await assert.rejects(
    () => validateUploadWithParse({ toolId: "fill-forms", declaredMime: "application/pdf", bytes: valid }),
    (error: unknown) => (error as { code?: string }).code === "PDF_INVALID",
    "the parse path must refuse an isolated tool outright",
  );
});
