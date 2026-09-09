import { PDFDocument } from "pdf-lib";
import { PdfToolError } from "@/lib/pdf/client";

export async function mergePdfBytes(inputs: Uint8Array[]) {
  if (inputs.length < 2) throw new PdfToolError("VALIDATION_ERROR", "Merge requires at least two PDFs.");
  const output = await PDFDocument.create();
  for (const bytes of inputs) { const source = await PDFDocument.load(bytes, { ignoreEncryption: false }); const pages = await output.copyPages(source, source.getPageIndices()); pages.forEach((page) => output.addPage(page)); }
  return output.save({ useObjectStreams: true });
}
