import { PDFDocument, StandardFonts, rgb } from "pdf-lib";
import { fillPdfBounded, processPdfBounded } from "../../src/lib/pdf/form-worker";
async function main() {
  // A large but legal document: many pages so the returned PDF far exceeds the
  // 64 KiB pipe buffer, which is where a single writeSync would truncate.
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  for (let i = 0; i < 60; i++) {
    const p = doc.addPage([400, 400]);
    p.drawText(`page ${i} ${"x".repeat(1200)}`, { x: 10, y: 380, size: 6, font, color: rgb(0,0,0) });
  }
  doc.getForm().createTextField("note").addToPage(doc.getPages()[0], { x: 10, y: 10, width: 200, height: 20 });
  const pdf = new Uint8Array(await doc.save({ updateFieldAppearances: false }));
  console.log("input bytes:", pdf.byteLength, "pages:", doc.getPageCount());

  const ins = await processPdfBounded(pdf);
  console.log("inspect ok:", ins.ok, "pages:", ins.ok ? ins.pages : "-", "fields:", ins.ok ? ins.inventory?.fields.length : "-");

  const filled = await fillPdfBounded(pdf, { note: "large output test" }, { flatten: false });
  console.log("output bytes:", filled.bytes.byteLength, "| checksum:", filled.checksum.slice(0, 12), "| pages:", filled.pages);
  // Prove the frame arrived intact: the checksum the child computed over its own
  // bytes must match the checksum of what the parent actually received.
  const { createHash } = await import("node:crypto");
  const actual = createHash("sha256").update(filled.bytes).digest("hex");
  console.log("checksum matches received bytes:", actual === filled.checksum);
  const back = await PDFDocument.load(filled.bytes);
  console.log("reopened pages:", back.getPageCount(), "| value:", back.getForm().getTextField("note").getText());
  console.log("LARGE OUTPUT > 64KiB pipe buffer:", filled.bytes.byteLength > 65536);
}
main().catch((e) => { console.error("FAILED:", e.code ?? "", e.message); process.exit(1); });
