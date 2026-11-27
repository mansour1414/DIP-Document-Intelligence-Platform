// Prove the *actual* output page count is used: make verifyFilledForm see a document
// with a different page count than the input, and confirm the fill is rejected rather
// than reporting the input's count.
import { PDFDocument } from "pdf-lib";
import { fillFormPdf } from "../../src/lib/pdf/form-fill";
import { readFileSync, writeFileSync } from "node:fs";

async function main() {
const src = readFileSync("src/lib/pdf/form-fill.ts", "utf8");
// Temporarily patch verifyFilledForm's page count to simulate an output that lost a page.
const patched = src.replace(
  "const verified = await verifyFilledForm(firstPass, values, { untouched: previous });",
  "const verified = await verifyFilledForm(firstPass, values, { untouched: previous });\n  (verified as { pages: number }).pages = verified.pages - 1; // SIMULATED page loss",
);
writeFileSync("src/lib/pdf/form-fill.ts", patched);
try {
  const { fillFormPdf: patchedFill } = await import("../../src/lib/pdf/form-fill");
  const doc = await PDFDocument.create();
  for (let i = 0; i < 3; i++) doc.addPage([300, 300]);
  doc.getForm().createTextField("n").addToPage(doc.getPages()[0], { x: 10, y: 10, width: 100, height: 20 });
  const pdf = new Uint8Array(await doc.save({ updateFieldAppearances: false }));
  try {
    const r = await patchedFill(pdf, { n: "x" }, { flatten: false });
    console.log("NOT REJECTED - reported pages:", r.report.pages, "(this is the input count leaking)");
  } catch (e: any) {
    console.log("REJECTED with", e.code, "| details:", JSON.stringify(e.details));
  }
} finally {
  writeFileSync("src/lib/pdf/form-fill.ts", src);
}
void fillFormPdf;

}
main();
