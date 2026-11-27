// Evidence B: does a cheap/malware rejection avoid spawning the child at all?
import { PDFDocument } from "pdf-lib";
import { activeFormWorkers, resetFormWorkersForTest } from "../../src/lib/pdf/form-worker";
import { validateUploadBytes } from "../../src/lib/uploads/validation";

async function main() {
  resetFormWorkersForTest();
  const childRuns = () => activeFormWorkers();

  // 1. Wrong MIME: rejected in stage 1, no child.
  try { validateUploadBytes({ toolId: "fill-forms", declaredMime: "image/png", bytes: new Uint8Array([1,2,3]) }); }
  catch (e: any) { console.log("wrong MIME ->", e.code, "| children spawned:", childRuns()); }

  // 2. Bad magic bytes on a real PDF body: stage 1, no child.
  const doc = await PDFDocument.create(); doc.addPage(); const real = new Uint8Array(await doc.save());
  const notPdf = new Uint8Array([0x50,0x4b,0x03,0x04, ...real.subarray(4)]);
  try { validateUploadBytes({ toolId: "fill-forms", declaredMime: "application/pdf", bytes: notPdf }); }
  catch (e: any) { console.log("bad magic  ->", e.code, "| children spawned:", childRuns()); }

  // 3. Oversize: stage 1, no child.
  try { validateUploadBytes({ toolId: "fill-forms", declaredMime: "application/pdf", bytes: new Uint8Array(100 * 1024 * 1024) }); }
  catch (e: any) { console.log("oversize   ->", e.code, "| children spawned:", childRuns()); }
}
main().catch((e) => { console.error("FAILED", e); process.exit(1); });
