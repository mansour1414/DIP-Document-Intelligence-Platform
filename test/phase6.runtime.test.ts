import test from "node:test";
import assert from "node:assert/strict";
import { PDFDocument } from "pdf-lib";
import { validateWorkerOutputs } from "../src/lib/outputs/validation";
import { withTimeout } from "../src/lib/runtime/timeout";
import { redactLogContext } from "../src/lib/logging";
import { selectExpiredCandidates, selectOrphans } from "../src/lib/retention/policy";
import { runtimeLimits } from "../src/lib/runtime/config";

async function pdfFixture(pages = 1) { const pdf = await PDFDocument.create(); for (let index = 0; index < pages; index += 1) pdf.addPage().drawText(`generated page ${index + 1}`); return pdf.save(); }

test("timeout rejects with a classified terminal failure", async () => {
  await assert.rejects(() => withTimeout("fixture", 5, new Promise((resolve) => setTimeout(resolve, 50))), { code: "PROCESSING_TIMEOUT" });
});

test("output validation rejects corrupt PDF and JPEG outputs", async () => {
  await assert.rejects(() => validateWorkerOutputs([{ name: "bad.pdf", mimeType: "application/pdf", bytes: new Uint8Array([1, 2, 3]) }]), { code: "OUTPUT_VALIDATION_FAILED" });
  await assert.rejects(() => validateWorkerOutputs([{ name: "bad.jpg", mimeType: "image/jpeg", bytes: new Uint8Array([1, 2, 3]) }]), { code: "OUTPUT_VALIDATION_FAILED" });
});

test("golden generated PDF is parseable and page preservation is enforced", async () => {
  const bytes = await pdfFixture(2);
  assert.deepEqual(await validateWorkerOutputs([{ name: "golden.pdf", mimeType: "application/pdf", bytes }], 2), { outputCount: 1, totalBytes: bytes.byteLength });
  await assert.rejects(() => validateWorkerOutputs([{ name: "golden.pdf", mimeType: "application/pdf", bytes }], 1), { code: "OUTPUT_VALIDATION_FAILED" });
});

test("max output count is enforced before registration", async () => {
  const output = { name: "x.jpg", mimeType: "image/jpeg", bytes: new Uint8Array([0xff, 0xd8, 0xff, 0xd9]) };
  await assert.rejects(() => validateWorkerOutputs(Array.from({ length: runtimeLimits.maxOutputFiles + 1 }, () => output)), { code: "OUTPUT_VALIDATION_FAILED" });
});

test("retention preserves active data and orphan selection is idempotent", () => {
  const now = new Date("2026-09-10T00:00:00Z"); const old = new Date("2026-08-01T00:00:00Z");
  const expired = selectExpiredCandidates([{ id: "active", createdAt: old, hasActiveJob: true, alreadyDeleted: false }, { id: "expired", createdAt: old, hasActiveJob: false, alreadyDeleted: false }, { id: "done", createdAt: old, hasActiveJob: false, alreadyDeleted: true }], now, 7);
  assert.deepEqual(expired.map((item) => item.id), ["expired"]);
  assert.equal(selectOrphans([{ fileReferenceCount: 0, alreadyDeleted: false }, { fileReferenceCount: 0, alreadyDeleted: true }, { fileReferenceCount: 1, alreadyDeleted: false }]).length, 1);
});

test("structured logs redact sensitive fields", () => {
  assert.deepEqual(redactLogContext({ prompt: "secret document", api_key: "key", job_id: "safe", input_tokens: 4 }), { prompt: "[REDACTED]", api_key: "[REDACTED]", job_id: "safe", input_tokens: 4 });
});

