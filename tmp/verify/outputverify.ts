import { PDFDocument } from "pdf-lib";
import { fillPdfBounded } from "../../src/lib/pdf/form-worker";
import { validateBoundedFillOutput } from "../../src/lib/outputs/validation";

async function main() {
  const doc = await PDFDocument.create();
  const p = doc.addPage([300,300]);
  doc.getForm().createTextField("n").addToPage(p, { x:10,y:10,width:100,height:20 });
  const pdf = new Uint8Array(await doc.save({ updateFieldAppearances: false }));
  const filled = await fillPdfBounded(pdf, { n: "x" }, { flatten: false });

  const limits = { maxOutputBytes: 250*1024*1024, maxOutputFiles: 500 };
  const r = await validateBoundedFillOutput(filled, { inputPages: 1, requestedFlatten: false, ...limits });
  console.log("valid output accepted:", JSON.stringify(r));

  // checksum mismatch
  try { await validateBoundedFillOutput({ ...filled, checksum: "0".repeat(64) }, { inputPages: 1, requestedFlatten: false, ...limits }); console.log("FAIL accepted bad checksum"); }
  catch (e: any) { console.log("checksum mismatch ->", e.code); }

  // page preservation mismatch (input claimed 2)
  try { await validateBoundedFillOutput(filled, { inputPages: 2, requestedFlatten: false, ...limits }); console.log("FAIL accepted page mismatch"); }
  catch (e: any) { console.log("page mismatch ->", e.code); }

  // size ceiling
  try { await validateBoundedFillOutput(filled, { inputPages: 1, requestedFlatten: false, maxOutputBytes: 100, maxOutputFiles: 500 }); console.log("FAIL accepted oversized"); }
  catch (e: any) { console.log("oversized ->", e.code); }

  // truncated / non-pdf
  try { await validateBoundedFillOutput({ ...filled, bytes: filled.bytes.subarray(0, 40) }, { inputPages: 1, requestedFlatten: false, ...limits }); console.log("FAIL accepted truncated"); }
  catch (e: any) { console.log("truncated ->", e.code); }
  // zero pages reported
  try { await validateBoundedFillOutput({ ...filled, pages: 0 }, { inputPages: 0, requestedFlatten: false, ...limits }); console.log("FAIL accepted 0 pages"); }
  catch (e: any) { console.log("zero pages ->", e.code); }
}
main().catch((e) => { console.error("FAILED", e); process.exit(1); });
