import { degrees, PDFDocument } from "pdf-lib";
import { PdfToolError } from "@/lib/pdf/client";
import { createServerTextPng, createServerWatermarkPng, renderPdfToJpegs } from "@/lib/pdf/server-canvas";
import { nUpPdf, removePdfAnnotations, splitPdfByBookmarks, splitPdfBySize, splitPdfByText } from "@/lib/pdf/phase1";
import { extractEmbeddedImages } from "@/lib/pdf/extract-images";

export async function mergePdfBytes(inputs: Uint8Array[]) {
  if (inputs.length < 2) throw new PdfToolError("VALIDATION_ERROR", "Merge requires at least two PDFs.");
  const output = await PDFDocument.create();
  for (const bytes of inputs) { const source = await PDFDocument.load(bytes, { ignoreEncryption: false }); const pages = await output.copyPages(source, source.getPageIndices()); pages.forEach((page) => output.addPage(page)); }
  return output.save({ useObjectStreams: true });
}

export type PdfWorkerTool = "merge-pdf" | "split-pdf" | "organize-pdf" | "rotate-pdf" | "delete-pages" | "extract-pages" | "jpg-to-pdf" | "compress-pdf" | "pdf-to-jpg" | "watermark-pdf" | "crop-pdf" | "page-numbers" | "header-footer" | "resize-pages" | "alternate-mix" | "flip-pages" | "split-pdf-by-size" | "split-pdf-by-bookmarks" | "split-pdf-by-text" | "n-up-pdf" | "remove-annotations" | "extract-images";
type WorkerOutput = { name: string; mimeType: string; bytes: Uint8Array };
export function pdfWorkerEngine(tool: PdfWorkerTool) { if (["compress-pdf", "pdf-to-jpg", "extract-images"].includes(tool)) return { engine: "pdfjs-dist+@napi-rs/canvas", engineVersion: "6.3.289+1.0.9" }; if (["watermark-pdf", "page-numbers", "header-footer"].includes(tool)) return { engine: "pdf-lib+@napi-rs/canvas", engineVersion: "1.17.1+1.0.9" }; return { engine: "pdf-lib", engineVersion: "1.17.1" }; }
function pageIndexes(value: string | undefined, count: number, ordered = false) {
  if (!value) throw new PdfToolError("VALIDATION_ERROR", "Pages are required."); const result: number[] = [];
  for (const token of value.split(",").map((item) => item.trim()).filter(Boolean)) { const match = token.match(/^(\d+)(?:-(\d+))?$/); if (!match) throw new PdfToolError("VALIDATION_ERROR", `Invalid page range: ${token}`); const start = Number(match[1]); const end = Number(match[2] ?? start); if (start < 1 || end < start || end > count) throw new PdfToolError("VALIDATION_ERROR", `Page range is outside the document: ${token}`); for (let page = start; page <= end; page += 1) result.push(page - 1); }
  if (!ordered && new Set(result).size !== result.length) throw new PdfToolError("VALIDATION_ERROR", "A page can only be selected once."); return result;
}
async function onePdf(bytes: Uint8Array) { return PDFDocument.load(bytes, { ignoreEncryption: false }); }
async function selectedPdf(source: PDFDocument, indexes: number[], name: string): Promise<WorkerOutput> { const output = await PDFDocument.create(); const pages = await output.copyPages(source, indexes); pages.forEach((page) => output.addPage(page)); return { name, mimeType: "application/pdf", bytes: await output.save({ useObjectStreams: true }) }; }
function qualityOption(value: unknown, fallback: number) { const quality = value === undefined ? fallback : Number(value); if (!Number.isFinite(quality) || quality < 0.45 || quality > 0.95) throw new PdfToolError("VALIDATION_ERROR", "Quality must be between 0.45 and 0.95."); return quality; }

type TextPosition = "top-left" | "top-center" | "top-right" | "bottom-left" | "bottom-center" | "bottom-right";
function visualPageSize(page: ReturnType<PDFDocument["getPage"]>) { const rotation = ((page.getRotation().angle % 360) + 360) % 360; return { rotation, width: rotation === 90 || rotation === 270 ? page.getHeight() : page.getWidth(), height: rotation === 90 || rotation === 270 ? page.getWidth() : page.getHeight() }; }
function visualRectToPage(page: ReturnType<PDFDocument["getPage"]>, x: number, y: number, width: number, height: number) {
  const { rotation } = visualPageSize(page);
  if (rotation === 90) return { x: page.getWidth() - y - height, y: x, width: height, height: width };
  if (rotation === 180) return { x: page.getWidth() - x - width, y: page.getHeight() - y - height, width, height };
  if (rotation === 270) return { x: y, y: page.getHeight() - x - width, width: height, height: width };
  return { x, y, width, height };
}
async function drawTextStrip(document: PDFDocument, page: ReturnType<PDFDocument["getPage"]>, text: string, options: { position: TextPosition; fontSize: number; margin: number }) {
  const { rotation, width: visualWidth, height: visualHeight } = visualPageSize(page); const drawWidth = Math.max(36, visualWidth - options.margin * 2); const drawHeight = options.fontSize * 2;
  if (drawHeight + options.margin > visualHeight) throw new PdfToolError("VALIDATION_ERROR", "Text and margin exceed the page height.");
  const alignment = options.position.endsWith("left") ? "left" as const : options.position.endsWith("right") ? "right" as const : "center" as const;
  const counterRotation = ((360 - rotation) % 360) as 0 | 90 | 180 | 270; const image = await document.embedPng(createServerTextPng(text, { width: drawWidth, fontSize: options.fontSize, alignment, rotation: counterRotation })); const visualX = options.margin; const visualY = options.position.startsWith("top") ? visualHeight - options.margin - drawHeight : options.margin; const rectangle = visualRectToPage(page, visualX, visualY, drawWidth, drawHeight);
  page.drawImage(image, rectangle);
}

const standardPageSizes = {
  a3: [841.89, 1190.55],
  a4: [595.28, 841.89],
  letter: [612, 792],
  legal: [612, 1008],
} as const;

async function alternateAndMix(inputs: Uint8Array[], options: Record<string, unknown>): Promise<WorkerOutput> {
  if (inputs.length !== 2) throw new PdfToolError("VALIDATION_ERROR", "Alternate & Mix requires exactly two PDFs.");
  const [first, second] = await Promise.all(inputs.map(onePdf)); const output = await PDFDocument.create();
  const firstPages = await output.copyPages(first, first.getPageIndices()); const secondIndexes = second.getPageIndices();
  if (options.reverseSecond === true) secondIndexes.reverse();
  const secondPages = await output.copyPages(second, secondIndexes); const order = options.startWith === "second" ? [secondPages, firstPages] : [firstPages, secondPages];
  for (let index = 0; index < Math.max(firstPages.length, secondPages.length); index += 1) for (const pages of order) if (pages[index]) output.addPage(pages[index]);
  return { name: "alternate-mixed.pdf", mimeType: "application/pdf", bytes: await output.save({ useObjectStreams: true }) };
}

function resizePages(output: PDFDocument, options: Record<string, unknown>) {
  const [portraitWidth, portraitHeight] = standardPageSizes[String(options.pageSize ?? "a4") as keyof typeof standardPageSizes] ?? standardPageSizes.a4;
  const requestedOrientation = String(options.orientation ?? "preserve"); const fit = String(options.fit ?? "contain");
  for (const page of output.getPages()) {
    const visual = visualPageSize(page); const landscape = requestedOrientation === "landscape" || (requestedOrientation === "preserve" && visual.width > visual.height);
    const visualTargetWidth = landscape ? portraitHeight : portraitWidth; const visualTargetHeight = landscape ? portraitWidth : portraitHeight;
    const quarterTurn = visual.rotation === 90 || visual.rotation === 270; const targetWidth = quarterTurn ? visualTargetHeight : visualTargetWidth; const targetHeight = quarterTurn ? visualTargetWidth : visualTargetHeight;
    const scaleX = targetWidth / page.getWidth(); const scaleY = targetHeight / page.getHeight();
    if (fit === "stretch") { page.scaleContent(scaleX, scaleY); page.scaleAnnotations(scaleX, scaleY); }
    else { const scale = Math.min(scaleX, scaleY); const offsetX = (targetWidth - page.getWidth() * scale) / 2; const offsetY = (targetHeight - page.getHeight() * scale) / 2; page.scaleContent(scale, scale); page.scaleAnnotations(scale, scale); page.translateContent(offsetX, offsetY); }
    page.setMediaBox(0, 0, targetWidth, targetHeight); page.setCropBox(0, 0, targetWidth, targetHeight);
  }
}

function flipPages(output: PDFDocument, options: Record<string, unknown>) {
  const selected = typeof options.pages === "string" ? new Set(pageIndexes(options.pages, output.getPageCount())) : new Set(output.getPageIndices()); const visualAxis = String(options.axis ?? "horizontal");
  output.getPages().forEach((page, index) => {
    if (!selected.has(index)) return;
    const quarterTurn = [90, 270].includes(visualPageSize(page).rotation); const rawAxis = quarterTurn ? (visualAxis === "horizontal" ? "vertical" : "horizontal") : visualAxis;
    if (rawAxis === "horizontal") { page.scaleContent(-1, 1); page.translateContent(page.getWidth(), 0); }
    else { page.scaleContent(1, -1); page.translateContent(0, page.getHeight()); }
  });
}

export async function runPdfWorkerTool(tool: PdfWorkerTool, inputs: Uint8Array[], options: Record<string, unknown>): Promise<WorkerOutput[]> {
  if (tool === "merge-pdf") return [{ name: "merged.pdf", mimeType: "application/pdf", bytes: await mergePdfBytes(inputs) }];
  if (tool === "alternate-mix") return [await alternateAndMix(inputs, options)];
  if (tool === "jpg-to-pdf") { const output = await PDFDocument.create(); for (let index = 0; index < inputs.length; index += 1) { const mime = String((options.inputMimeTypes as string[] | undefined)?.[index] ?? "image/jpeg"); const image = mime === "image/png" ? await output.embedPng(inputs[index]) : await output.embedJpg(inputs[index]); const page = output.addPage([image.width, image.height]); page.drawImage(image, { x: 0, y: 0, width: image.width, height: image.height }); } return [{ name: "images.pdf", mimeType: "application/pdf", bytes: await output.save({ useObjectStreams: true }) }]; }
  if (inputs.length !== 1) throw new PdfToolError("VALIDATION_ERROR", "This tool accepts one PDF.");
  if (tool === "split-pdf-by-size") return splitPdfBySize(inputs[0], Number(options.targetSizeMb ?? 10));
  if (tool === "split-pdf-by-bookmarks") return splitPdfByBookmarks(inputs[0]);
  if (tool === "split-pdf-by-text") return splitPdfByText(inputs[0], String(options.matchText ?? ""), options.caseSensitive === true);
  if (tool === "n-up-pdf") return nUpPdf(inputs[0], { layout: Number(options.layout ?? 2), orientation: String(options.orientation ?? "portrait"), pageSize: String(options.pageSize ?? "a4"), margin: Number(options.margin ?? 18), order: String(options.order ?? "row") });
  if (tool === "remove-annotations") return removePdfAnnotations(inputs[0], options.policy === "comments-and-links");
  if (tool === "extract-images") return extractEmbeddedImages(inputs[0]);
  const source = await onePdf(inputs[0]);
  if (tool === "pdf-to-jpg") { const images = await renderPdfToJpegs(inputs[0], qualityOption(options.quality, 0.9)); return images.map((image, index) => ({ name: `page-${index + 1}.jpg`, mimeType: "image/jpeg", bytes: image.bytes })); }
  if (tool === "compress-pdf") { const images = await renderPdfToJpegs(inputs[0], qualityOption(options.quality, 0.72)); const compressed = await PDFDocument.create(); for (const rendered of images) { const image = await compressed.embedJpg(rendered.bytes); const page = compressed.addPage([rendered.pageWidth, rendered.pageHeight]); page.drawImage(image, { x: 0, y: 0, width: rendered.pageWidth, height: rendered.pageHeight }); } return [{ name: "compressed.pdf", mimeType: "application/pdf", bytes: await compressed.save({ useObjectStreams: true }) }]; }
  if (tool === "watermark-pdf") { const text = String(options.watermark ?? "").trim(); if (!text) throw new PdfToolError("VALIDATION_ERROR", "Watermark text is required."); if (text.length > 80) throw new PdfToolError("VALIDATION_ERROR", "Watermark text exceeds 80 characters."); const output = await PDFDocument.load(inputs[0]); const watermark = await output.embedPng(createServerWatermarkPng(text)); output.getPages().forEach((page) => { const width = page.getWidth() * 0.72; const height = width * (watermark.height / watermark.width); page.drawImage(watermark, { x: page.getWidth() * 0.12, y: page.getHeight() * 0.42, width, height, rotate: degrees(35), opacity: 0.28 }); }); return [{ name: "watermarked.pdf", mimeType: "application/pdf", bytes: await output.save({ useObjectStreams: true }) }]; }
  if (tool === "crop-pdf") {
    const output = await PDFDocument.load(inputs[0]); const top = Number(options.topPercent ?? 0) / 100; const right = Number(options.rightPercent ?? 0) / 100; const bottom = Number(options.bottomPercent ?? 0) / 100; const left = Number(options.leftPercent ?? 0) / 100;
    output.getPages().forEach((page) => { const box = page.getCropBox(); page.setCropBox(box.x + box.width * left, box.y + box.height * bottom, box.width * (1 - left - right), box.height * (1 - top - bottom)); });
    return [{ name: "cropped.pdf", mimeType: "application/pdf", bytes: await output.save({ useObjectStreams: true }) }];
  }
  if (tool === "page-numbers") {
    const output = await PDFDocument.load(inputs[0]); const pages = output.getPages(); const start = Number(options.startNumber ?? 1); const format = String(options.format ?? "{page}"); const position = String(options.position ?? "bottom-center") as TextPosition; const fontSize = Number(options.fontSize ?? 12); const margin = Number(options.margin ?? 24);
    for (let index = 0; index < pages.length; index += 1) { const text = format.replaceAll("{page}", String(start + index)).replaceAll("{total}", String(pages.length)); await drawTextStrip(output, pages[index], text, { position, fontSize, margin }); }
    return [{ name: "numbered.pdf", mimeType: "application/pdf", bytes: await output.save({ useObjectStreams: true }) }];
  }
  if (tool === "header-footer") {
    const output = await PDFDocument.load(inputs[0]); const header = String(options.headerText ?? "").trim(); const footer = String(options.footerText ?? "").trim(); const alignment = String(options.alignment ?? "center"); const suffix = alignment === "left" || alignment === "right" ? alignment : "center"; const fontSize = Number(options.fontSize ?? 12); const margin = Number(options.margin ?? 24);
    for (const page of output.getPages()) { if (header) await drawTextStrip(output, page, header, { position: `top-${suffix}` as TextPosition, fontSize, margin }); if (footer) await drawTextStrip(output, page, footer, { position: `bottom-${suffix}` as TextPosition, fontSize, margin }); }
    return [{ name: "header-footer.pdf", mimeType: "application/pdf", bytes: await output.save({ useObjectStreams: true }) }];
  }
  if (tool === "resize-pages") { const output = await PDFDocument.load(inputs[0]); resizePages(output, options); return [{ name: "resized.pdf", mimeType: "application/pdf", bytes: await output.save({ useObjectStreams: true }) }]; }
  if (tool === "flip-pages") { const output = await PDFDocument.load(inputs[0]); flipPages(output, options); return [{ name: "flipped.pdf", mimeType: "application/pdf", bytes: await output.save({ useObjectStreams: true }) }]; }
  if (tool === "split-pdf") { const indexes = typeof options.pages === "string" && options.pages ? pageIndexes(options.pages, source.getPageCount()) : source.getPageIndices(); return Promise.all(indexes.map((index) => selectedPdf(source, [index], `page-${index + 1}.pdf`))); }
  let indexes = source.getPageIndices();
  if (tool === "organize-pdf") indexes = pageIndexes(String(options.pages ?? ""), source.getPageCount(), true);
  if (tool === "extract-pages") indexes = pageIndexes(String(options.pages ?? ""), source.getPageCount());
  if (tool === "delete-pages") { const removed = new Set(pageIndexes(String(options.pages ?? ""), source.getPageCount())); indexes = indexes.filter((index) => !removed.has(index)); if (!indexes.length) throw new PdfToolError("VALIDATION_ERROR", "At least one page must remain."); }
  const result = await selectedPdf(source, indexes, `${tool}.pdf`);
  if (tool === "rotate-pdf") { const output = await PDFDocument.load(result.bytes); output.getPages().forEach((page) => page.setRotation(degrees((page.getRotation().angle + Number(options.rotation ?? 90)) % 360))); result.bytes = await output.save({ useObjectStreams: true }); }
  return [result];
}
