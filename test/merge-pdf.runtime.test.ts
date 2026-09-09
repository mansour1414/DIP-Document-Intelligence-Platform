import test from "node:test";
import assert from "node:assert/strict";
import { PDFDocument } from "pdf-lib";
import { mergePdfBytes } from "../src/lib/pdf/server";
import { validateUpload } from "../src/lib/uploads/validation";

async function fixture(text: string) { const pdf = await PDFDocument.create(); pdf.addPage().drawText(text); return pdf.save(); }

test("Merge PDF runtime validates content and produces one combined output", async () => {
  const first = await fixture("first"); const second = await fixture("second");
  const validation = await validateUpload({ toolId: "merge-pdf", declaredMime: "application/pdf", bytes: first });
  assert.equal(validation.mimeType, "application/pdf"); assert.equal(validation.pageCount, 1);
  const output = await mergePdfBytes([first, second]);
  assert.equal((await PDFDocument.load(output)).getPageCount(), 2);
});

test("Merge PDF rejects invalid magic bytes before storage", async () => {
  await assert.rejects(() => validateUpload({ toolId: "merge-pdf", declaredMime: "application/pdf", bytes: new Uint8Array([1, 2, 3]) }), { code: "MAGIC_BYTES_INVALID" });
});
