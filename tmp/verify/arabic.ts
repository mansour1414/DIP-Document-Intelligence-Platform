import { PDFDocument } from "pdf-lib";
import { fillPdfBounded } from "../../src/lib/pdf/form-worker";
async function main() {
  const doc = await PDFDocument.create();
  const page = doc.addPage([300, 300]);
  doc.getForm().createTextField("name").addToPage(page, { x: 10, y: 10, width: 200, height: 24 });
  const pdf = new Uint8Array(await doc.save({ updateFieldAppearances: false }));
  const filled = await fillPdfBounded(pdf, { name: "محمد عبد الله" }, { flatten: false });
  console.log("arabic fill ok | pages:", filled.pages, "| bytes:", filled.bytes.byteLength);
  console.log("rasterAppearances:", filled.report.rasterAppearances, filled.report.rasterAppearances > 0 ? "(native canvas used inside the child)" : "(vector path)");
  const out = await PDFDocument.load(filled.bytes);
  console.log("value round-trip:", out.getForm().getTextField("name").getText());
}
main().catch((e) => { console.error("FAILED:", e.code ?? "", e.message); process.exit(1); });
