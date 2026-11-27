import { PDFDocument } from "pdf-lib";
import { fillPdfBounded, processPdfBounded } from "../../src/lib/pdf/form-worker";
async function main() {
  const doc = await PDFDocument.create();
  for (let i = 0; i < 4; i++) doc.addPage([300, 300]);
  doc.getForm().createTextField("n").addToPage(doc.getPages()[0], { x: 10, y: 10, width: 100, height: 20 });
  const pdf = new Uint8Array(await doc.save({ updateFieldAppearances: false }));
  const ins = await processPdfBounded(pdf);
  console.log("input pages (inspection):", ins.ok ? ins.pages : "?");

  // Non-flattened: the reported count must come from the reopened output.
  const f = await fillPdfBounded(pdf, { n: "x" }, { flatten: false });
  const reopened = await PDFDocument.load(f.bytes);
  console.log("reported pages:", f.pages, "| actual output pages:", reopened.getPageCount(), "| match:", f.pages === reopened.getPageCount());

  // Flatten.
  const fl = await fillPdfBounded(pdf, { n: "y" }, { flatten: true });
  const reopenedFlat = await PDFDocument.load(fl.bytes);
  console.log("flatten reported pages:", fl.pages, "| actual:", reopenedFlat.getPageCount(), "| match:", fl.pages === reopenedFlat.getPageCount(), "| flatten flag:", fl.flatten);
}
main().catch((e) => { console.error("FAILED:", e.code ?? "", e.message); process.exit(1); });
