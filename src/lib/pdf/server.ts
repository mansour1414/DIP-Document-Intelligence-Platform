import { degrees, PDFDocument } from "pdf-lib";
import { PdfToolError } from "@/lib/pdf/client";
import { createServerWatermarkPng, renderPdfToJpegs } from "@/lib/pdf/server-canvas";

export async function mergePdfBytes(inputs: Uint8Array[]) {
  if (inputs.length < 2) throw new PdfToolError("VALIDATION_ERROR", "Merge requires at least two PDFs.");
  const output = await PDFDocument.create();
  for (const bytes of inputs) { const source = await PDFDocument.load(bytes, { ignoreEncryption: false }); const pages = await output.copyPages(source, source.getPageIndices()); pages.forEach((page) => output.addPage(page)); }
  return output.save({ useObjectStreams: true });
}

export type PdfWorkerTool = "merge-pdf" | "split-pdf" | "organize-pdf" | "rotate-pdf" | "delete-pages" | "extract-pages" | "jpg-to-pdf" | "compress-pdf" | "pdf-to-jpg" | "watermark-pdf";
type WorkerOutput = { name: string; mimeType: string; bytes: Uint8Array };
export function pdfWorkerEngine(tool: PdfWorkerTool) { if (["compress-pdf", "pdf-to-jpg"].includes(tool)) return { engine: "pdfjs-dist+@napi-rs/canvas", engineVersion: "6.3.289+1.0.9" }; if (tool === "watermark-pdf") return { engine: "pdf-lib+@napi-rs/canvas", engineVersion: "1.17.1+1.0.9" }; return { engine: "pdf-lib", engineVersion: "1.17.1" }; }
function pageIndexes(value: string | undefined, count: number, ordered = false) {
  if (!value) throw new PdfToolError("VALIDATION_ERROR", "Pages are required."); const result: number[] = [];
  for (const token of value.split(",").map((item) => item.trim()).filter(Boolean)) { const match = token.match(/^(\d+)(?:-(\d+))?$/); if (!match) throw new PdfToolError("VALIDATION_ERROR", `Invalid page range: ${token}`); const start = Number(match[1]); const end = Number(match[2] ?? start); if (start < 1 || end < start || end > count) throw new PdfToolError("VALIDATION_ERROR", `Page range is outside the document: ${token}`); for (let page = start; page <= end; page += 1) result.push(page - 1); }
  if (!ordered && new Set(result).size !== result.length) throw new PdfToolError("VALIDATION_ERROR", "A page can only be selected once."); return result;
}
async function onePdf(bytes: Uint8Array) { return PDFDocument.load(bytes, { ignoreEncryption: false }); }
async function selectedPdf(source: PDFDocument, indexes: number[], name: string): Promise<WorkerOutput> { const output = await PDFDocument.create(); const pages = await output.copyPages(source, indexes); pages.forEach((page) => output.addPage(page)); return { name, mimeType: "application/pdf", bytes: await output.save({ useObjectStreams: true }) }; }
function qualityOption(value: unknown, fallback: number) { const quality = value === undefined ? fallback : Number(value); if (!Number.isFinite(quality) || quality < 0.45 || quality > 0.95) throw new PdfToolError("VALIDATION_ERROR", "Quality must be between 0.45 and 0.95."); return quality; }

export async function runPdfWorkerTool(tool: PdfWorkerTool, inputs: Uint8Array[], options: Record<string, unknown>): Promise<WorkerOutput[]> {
  if (tool === "merge-pdf") return [{ name: "merged.pdf", mimeType: "application/pdf", bytes: await mergePdfBytes(inputs) }];
  if (tool === "jpg-to-pdf") { const output = await PDFDocument.create(); for (let index = 0; index < inputs.length; index += 1) { const mime = String((options.inputMimeTypes as string[] | undefined)?.[index] ?? "image/jpeg"); const image = mime === "image/png" ? await output.embedPng(inputs[index]) : await output.embedJpg(inputs[index]); const page = output.addPage([image.width, image.height]); page.drawImage(image, { x: 0, y: 0, width: image.width, height: image.height }); } return [{ name: "images.pdf", mimeType: "application/pdf", bytes: await output.save({ useObjectStreams: true }) }]; }
  if (inputs.length !== 1) throw new PdfToolError("VALIDATION_ERROR", "This tool accepts one PDF."); const source = await onePdf(inputs[0]);
  if (tool === "pdf-to-jpg") { const images = await renderPdfToJpegs(inputs[0], qualityOption(options.quality, 0.9)); return images.map((image, index) => ({ name: `page-${index + 1}.jpg`, mimeType: "image/jpeg", bytes: image.bytes })); }
  if (tool === "compress-pdf") { const images = await renderPdfToJpegs(inputs[0], qualityOption(options.quality, 0.72)); const compressed = await PDFDocument.create(); for (const rendered of images) { const image = await compressed.embedJpg(rendered.bytes); const page = compressed.addPage([rendered.pageWidth, rendered.pageHeight]); page.drawImage(image, { x: 0, y: 0, width: rendered.pageWidth, height: rendered.pageHeight }); } return [{ name: "compressed.pdf", mimeType: "application/pdf", bytes: await compressed.save({ useObjectStreams: true }) }]; }
  if (tool === "watermark-pdf") { const text = String(options.watermark ?? "").trim(); if (!text) throw new PdfToolError("VALIDATION_ERROR", "Watermark text is required."); if (text.length > 80) throw new PdfToolError("VALIDATION_ERROR", "Watermark text exceeds 80 characters."); const output = await PDFDocument.load(inputs[0]); const watermark = await output.embedPng(createServerWatermarkPng(text)); output.getPages().forEach((page) => { const width = page.getWidth() * 0.72; const height = width * (watermark.height / watermark.width); page.drawImage(watermark, { x: page.getWidth() * 0.12, y: page.getHeight() * 0.42, width, height, rotate: degrees(35), opacity: 0.28 }); }); return [{ name: "watermarked.pdf", mimeType: "application/pdf", bytes: await output.save({ useObjectStreams: true }) }]; }
  if (tool === "split-pdf") { const indexes = typeof options.pages === "string" && options.pages ? pageIndexes(options.pages, source.getPageCount()) : source.getPageIndices(); return Promise.all(indexes.map((index) => selectedPdf(source, [index], `page-${index + 1}.pdf`))); }
  let indexes = source.getPageIndices();
  if (tool === "organize-pdf") indexes = pageIndexes(String(options.pages ?? ""), source.getPageCount(), true);
  if (tool === "extract-pages") indexes = pageIndexes(String(options.pages ?? ""), source.getPageCount());
  if (tool === "delete-pages") { const removed = new Set(pageIndexes(String(options.pages ?? ""), source.getPageCount())); indexes = indexes.filter((index) => !removed.has(index)); if (!indexes.length) throw new PdfToolError("VALIDATION_ERROR", "At least one page must remain."); }
  const result = await selectedPdf(source, indexes, `${tool}.pdf`);
  if (tool === "rotate-pdf") { const output = await PDFDocument.load(result.bytes); output.getPages().forEach((page) => page.setRotation(degrees((page.getRotation().angle + Number(options.rotation ?? 90)) % 360))); result.bytes = await output.save({ useObjectStreams: true }); }
  return [result];
}
