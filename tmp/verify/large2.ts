import { PDFDocument } from "pdf-lib";
import { fillPdfBounded } from "../../src/lib/pdf/form-worker";
import { createHash } from "node:crypto";
async function main() {
  // Embed incompressible data as an attachment-like stream so the output cannot be
  // deflated away: this is what actually fills the pipe buffer.
  const doc = await PDFDocument.create();
  for (let i = 0; i < 12; i++) doc.addPage([300, 300]);
  doc.getForm().createTextField("n").addToPage(doc.getPages()[0], { x: 10, y: 10, width: 150, height: 20 });
  const noise = Buffer.alloc(900_000);
  for (let i = 0; i < noise.length; i++) noise[i] = (i * 7919 + 104729) % 256;
  doc.attach(noise, "blob.bin", { mimeType: "application/octet-stream" });
  const pdf = new Uint8Array(await doc.save({ updateFieldAppearances: false }));
  const filled = await fillPdfBounded(pdf, { n: "big" }, { flatten: false });
  const actual = createHash("sha256").update(filled.bytes).digest("hex");
  console.log("output bytes:", filled.bytes.byteLength);
  console.log("exceeds 64KiB pipe buffer:", filled.bytes.byteLength > 65536);
  console.log("exceeds 1MiB:", filled.bytes.byteLength > 1024 * 1024);
  console.log("checksum matches received bytes:", actual === filled.checksum);
  const back = await PDFDocument.load(filled.bytes);
  console.log("reopened pages:", back.getPageCount(), "value:", back.getForm().getTextField("n").getText());
}
main().catch((e) => { console.error("FAILED:", e.code ?? "", e.message); process.exit(1); });
