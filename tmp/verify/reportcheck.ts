// The defect is in the *reported* value, so measure that directly.
import { PDFDocument } from "pdf-lib";
import { fillFormPdf } from "../../src/lib/pdf/form-fill";
async function main() {
  const doc = await PDFDocument.create();
  for (let i = 0; i < 3; i++) doc.addPage([300, 300]);
  doc.getForm().createTextField("n").addToPage(doc.getPages()[0], { x: 10, y: 10, width: 100, height: 20 });
  const pdf = new Uint8Array(await doc.save({ updateFieldAppearances: false }));
  const r = await fillFormPdf(pdf, { n: "x" }, { flatten: false });
  const actual = (await PDFDocument.load(r.bytes)).getPageCount();
  console.log("report.pages =", r.report.pages, "| actual output pages =", actual, "| derived from output:", r.report.pages === actual);
}
main();
