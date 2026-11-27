import { PDFDocument } from "pdf-lib";
import { fillPdfBounded, processPdfBounded } from "../../src/lib/pdf/form-worker";

async function main() {
  const doc = await PDFDocument.create();
  const page = doc.addPage([300, 300]);
  doc.getForm().createTextField("name").addToPage(page, { x: 10, y: 10, width: 120, height: 20 });
  const pdf = new Uint8Array(await doc.save({ updateFieldAppearances: false }));

  const inspected = await processPdfBounded(pdf);
  console.log("inspect:", inspected.ok ? `pages=${inspected.pages} fields=${(inspected.inventory as any).fields.length}` : "failed");

  const filled = await fillPdfBounded(pdf, { name: "Hello" }, { flatten: false });
  console.log("fill:", "pages=" + filled.pages, "bytes=" + filled.bytes.byteLength, "checksum=" + filled.checksum.slice(0, 12));
  console.log("report:", JSON.stringify(filled.report));
  // The output must be a real PDF with the value applied.
  const out = await PDFDocument.load(filled.bytes, { ignoreEncryption: false });
  console.log("output pages:", out.getPageCount(), "| field value:", out.getForm().getTextField("name").getText());

  const flat = await fillPdfBounded(pdf, { name: "Flat" }, { flatten: true });
  const flatDoc = await PDFDocument.load(flat.bytes);
  console.log("flatten:", flat.report.flatten, "| field still present:", flatDoc.getForm().getFields().length > 0);
  console.log("flatten pages:", flat.pages);
}
main().catch((e) => { console.error("FAILED:", e.code ?? "", e.message); process.exit(1); });
