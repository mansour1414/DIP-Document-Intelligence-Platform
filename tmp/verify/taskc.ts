// Task C: does an unrelated tool still get a Fill Forms verdict, and does a
// .pdf-named non-PDF upload get refused by the shape gate?
import { PDFDocument } from "pdf-lib";
import { validateUploadBytes } from "../../src/lib/uploads/validation";
import { assertCheapPdfShape } from "../../src/lib/pdf/form-inspection";

async function main() {
  const doc = await PDFDocument.create(); doc.addPage();
  const real = new Uint8Array(await doc.save());

  // A valid PDF is fine for ordinary tools and passes the Fill Forms gate.
  console.log("stage1 compress-pdf:", JSON.stringify(validateUploadBytes({ toolId: "compress-pdf", declaredMime: "application/pdf", bytes: real }).pageCount));
  assertCheapPdfShape(real);
  console.log("fill-forms shape gate on a valid PDF: passes");

  // A *damaged* PDF: the shape gate rejects it with a FORM_* code. For an ordinary
  // tool that code must never be produced, because ordinary tools no longer run it.
  const damaged = real.subarray(0, Math.floor(real.length / 2));
  try { assertCheapPdfShape(damaged); } catch (e: any) { console.log("shape gate rejects damaged ->", e.code); }

  // And the generic stage 1 does NOT reject a damaged-but-PDF-signed file.
  try { validateUploadBytes({ toolId: "compress-pdf", declaredMime: "application/pdf", bytes: damaged }); console.log("stage1 accepts damaged PDF for compress-pdf (correct: generic safeguards only)"); }
  catch (e: any) { console.log("stage1 rejected ->", e.code); }
}
main().catch((e) => { console.error(e); process.exit(1); });
