import { PDFDocument } from "pdf-lib";
import { fillFormPdf } from "../../src/lib/pdf/form-fill";
async function main() {
  const doc = await PDFDocument.create();
  for (let i = 0; i < 3; i++) doc.addPage([300, 300]);
  doc.getForm().createTextField("n").addToPage(doc.getPages()[0], { x: 10, y: 10, width: 100, height: 20 });
  const pdf = new Uint8Array(await doc.save({ updateFieldAppearances: false }));
  try {
    const r = await fillFormPdf(pdf, { n: "x" }, { flatten: false });
    console.log("NOT REJECTED — reported pages:", r.report.pages);
  } catch (e: any) {
    console.log("REJECTED with", e.code, "| details:", JSON.stringify(e.details));
  }
}
main();
