import { degrees, PDFDocument } from "pdf-lib";

export type PdfOperation =
  | "merge-pdf"
  | "split-pdf"
  | "compress-pdf"
  | "organize-pdf"
  | "rotate-pdf"
  | "delete-pages"
  | "extract-pages"
  | "jpg-to-pdf"
  | "pdf-to-jpg"
  | "watermark-pdf";

export type PdfOptions = {
  pages?: string;
  rotation?: 90 | 180 | 270;
  watermark?: string;
  quality?: number;
  onProgress?: (completed: number, total: number) => void;
};

export type OutputFile = { name: string; bytes: Uint8Array; mimeType: string };

export class PdfToolError extends Error {
  constructor(public code: "VALIDATION_ERROR" | "UNSUPPORTED_FORMAT" | "SIZE_LIMIT_EXCEEDED" | "PAGE_LIMIT_EXCEEDED" | "INTERNAL_ERROR", message: string) {
    super(message);
  }
}

const MB100 = 100 * 1024 * 1024;

function validateFiles(files: File[]) {
  if (!files.length) throw new PdfToolError("VALIDATION_ERROR", "Choose at least one file.");
  if (files.reduce((total, file) => total + file.size, 0) > MB100) {
    throw new PdfToolError("SIZE_LIMIT_EXCEEDED", "The selected files exceed the 100 MB browser limit.");
  }
}

function parsePages(value: string | undefined, pageCount: number, allowOrder = false) {
  if (!value?.trim()) throw new PdfToolError("VALIDATION_ERROR", "Enter page numbers, for example 1-3, 5.");
  const pages: number[] = [];
  for (const part of value.split(",").map((item) => item.trim()).filter(Boolean)) {
    const match = part.match(/^(\d+)(?:-(\d+))?$/);
    if (!match) throw new PdfToolError("VALIDATION_ERROR", `Invalid page range: ${part}`);
    const start = Number(match[1]);
    const end = Number(match[2] ?? start);
    if (start < 1 || end < start || end > pageCount) throw new PdfToolError("VALIDATION_ERROR", `Page range ${part} is outside this document.`);
    for (let page = start; page <= end; page += 1) pages.push(page - 1);
  }
  if (!allowOrder && new Set(pages).size !== pages.length) throw new PdfToolError("VALIDATION_ERROR", "A page can only be selected once.");
  return pages;
}

async function loadPdf(file: File) {
  if (file.type !== "application/pdf" && !file.name.toLowerCase().endsWith(".pdf")) {
    throw new PdfToolError("UNSUPPORTED_FORMAT", `${file.name} is not a PDF file.`);
  }
  const document = await PDFDocument.load(await file.arrayBuffer(), { ignoreEncryption: false });
  if (document.getPageCount() > 500) throw new PdfToolError("PAGE_LIMIT_EXCEEDED", "This PDF exceeds the 500-page browser limit.");
  return document;
}

async function savePdf(document: PDFDocument, name: string): Promise<OutputFile> {
  return { name, bytes: await document.save({ useObjectStreams: true }), mimeType: "application/pdf" };
}

async function renderPdfPages(file: File, quality: number, onProgress?: PdfOptions["onProgress"]) {
  const pdfjs = await import("pdfjs-dist");
  pdfjs.GlobalWorkerOptions.workerSrc = new URL(
    "pdfjs-dist/build/pdf.worker.min.mjs",
    import.meta.url,
  ).toString();
  const task = pdfjs.getDocument({ data: new Uint8Array(await file.arrayBuffer()) });
  const document = await task.promise;
  if (document.numPages > 500) {
    await task.destroy();
    throw new PdfToolError("PAGE_LIMIT_EXCEEDED", "This PDF exceeds the 500-page browser limit.");
  }
  const images: Array<{ bytes: Uint8Array; pageWidth: number; pageHeight: number }> = [];

  try {
    for (let pageNumber = 1; pageNumber <= document.numPages; pageNumber += 1) {
      const page = await document.getPage(pageNumber);
      const pageSize = page.getViewport({ scale: 1 });
      const viewport = page.getViewport({ scale: 1.5 });
      const canvas = window.document.createElement("canvas");
      canvas.width = Math.ceil(viewport.width);
      canvas.height = Math.ceil(viewport.height);
      const context = canvas.getContext("2d", { alpha: false });
      if (!context) throw new PdfToolError("INTERNAL_ERROR", "Canvas rendering is unavailable in this browser.");
      await page.render({ canvas, canvasContext: context, viewport }).promise;
      const blob = await new Promise<Blob>((resolve, reject) =>
        canvas.toBlob((value) => value ? resolve(value) : reject(new Error("Image encoding failed")), "image/jpeg", quality),
      );
      images.push({ bytes: new Uint8Array(await blob.arrayBuffer()), pageWidth: pageSize.width, pageHeight: pageSize.height });
      page.cleanup();
      onProgress?.(pageNumber, document.numPages);
    }
  } finally {
    await task.destroy();
  }
  return images;
}

async function createWatermarkPng(text: string) {
  const canvas = window.document.createElement("canvas");
  canvas.width = 1400;
  canvas.height = 220;
  const context = canvas.getContext("2d");
  if (!context) throw new PdfToolError("INTERNAL_ERROR", "Canvas rendering is unavailable in this browser.");
  context.clearRect(0, 0, canvas.width, canvas.height);
  context.fillStyle = "#475569";
  context.font = "700 86px Arial, sans-serif";
  context.textAlign = "center";
  context.textBaseline = "middle";
  context.direction = /[\u0600-\u06ff]/.test(text) ? "rtl" : "ltr";
  context.fillText(text, canvas.width / 2, canvas.height / 2, canvas.width - 80);
  const blob = await new Promise<Blob>((resolve, reject) =>
    canvas.toBlob((value) => value ? resolve(value) : reject(new Error("Watermark encoding failed")), "image/png"),
  );
  return blob.arrayBuffer();
}

export async function runPdfOperation(operation: PdfOperation, files: File[], options: PdfOptions = {}): Promise<OutputFile[]> {
  validateFiles(files);

  if (operation === "merge-pdf") {
    if (files.length < 2) throw new PdfToolError("VALIDATION_ERROR", "Choose at least two PDF files.");
    const output = await PDFDocument.create();
    for (const file of files) {
      const source = await loadPdf(file);
      const pages = await output.copyPages(source, source.getPageIndices());
      pages.forEach((page) => output.addPage(page));
    }
    return [await savePdf(output, "merged.pdf")];
  }

  if (operation === "jpg-to-pdf") {
    const output = await PDFDocument.create();
    for (const file of files) {
      const bytes = await file.arrayBuffer();
      const image = file.type === "image/png" ? await output.embedPng(bytes) : await output.embedJpg(bytes);
      const page = output.addPage([image.width, image.height]);
      page.drawImage(image, { x: 0, y: 0, width: image.width, height: image.height });
    }
    return [await savePdf(output, "images.pdf")];
  }

  if (files.length !== 1) throw new PdfToolError("VALIDATION_ERROR", "Choose exactly one PDF file for this tool.");
  const source = await loadPdf(files[0]);

  if (operation === "split-pdf") {
    const indexes = options.pages?.trim() ? parsePages(options.pages, source.getPageCount()) : source.getPageIndices();
    const outputs: OutputFile[] = [];
    for (const index of indexes) {
      const output = await PDFDocument.create();
      const [page] = await output.copyPages(source, [index]);
      output.addPage(page);
      outputs.push(await savePdf(output, `page-${index + 1}.pdf`));
    }
    return outputs;
  }

  if (operation === "pdf-to-jpg") {
    const images = await renderPdfPages(files[0], options.quality ?? 0.9, options.onProgress);
    if (images.length === 1) return [{ name: "page-1.jpg", bytes: images[0].bytes, mimeType: "image/jpeg" }];
    const { default: JSZip } = await import("jszip");
    const archive = new JSZip();
    images.forEach((image, index) => archive.file(`page-${index + 1}.jpg`, image.bytes));
    return [{ name: "pdf-pages.zip", bytes: await archive.generateAsync({ type: "uint8array", compression: "DEFLATE" }), mimeType: "application/zip" }];
  }

  if (operation === "compress-pdf") {
    const images = await renderPdfPages(files[0], options.quality ?? 0.72, options.onProgress);
    const compressed = await PDFDocument.create();
    for (const imageBytes of images) {
      const image = await compressed.embedJpg(imageBytes.bytes);
      const page = compressed.addPage([imageBytes.pageWidth, imageBytes.pageHeight]);
      page.drawImage(image, { x: 0, y: 0, width: imageBytes.pageWidth, height: imageBytes.pageHeight });
    }
    return [await savePdf(compressed, "compressed.pdf")];
  }

  const output = await PDFDocument.create();
  let indexes = source.getPageIndices();
  if (operation === "extract-pages") indexes = parsePages(options.pages, source.getPageCount());
  if (operation === "delete-pages") {
    const removed = new Set(parsePages(options.pages, source.getPageCount()));
    indexes = indexes.filter((index) => !removed.has(index));
    if (!indexes.length) throw new PdfToolError("VALIDATION_ERROR", "At least one page must remain.");
  }
  if (operation === "organize-pdf") indexes = parsePages(options.pages, source.getPageCount(), true);
  const pages = await output.copyPages(source, indexes);
  pages.forEach((page) => output.addPage(page));

  if (operation === "rotate-pdf") output.getPages().forEach((page) => page.setRotation(degrees((page.getRotation().angle + (options.rotation ?? 90)) % 360)));
  if (operation === "watermark-pdf") {
    const text = options.watermark?.trim();
    if (!text) throw new PdfToolError("VALIDATION_ERROR", "Enter watermark text.");
    const watermarkImage = await output.embedPng(await createWatermarkPng(text));
    output.getPages().forEach((page) => {
      const width = page.getWidth() * 0.72;
      const height = width * (watermarkImage.height / watermarkImage.width);
      page.drawImage(watermarkImage, { x: page.getWidth() * 0.12, y: page.getHeight() * 0.42, width, height, rotate: degrees(35), opacity: 0.28 });
    });
  }

  const names: Partial<Record<PdfOperation, string>> = {
    "organize-pdf": "organized.pdf", "rotate-pdf": "rotated.pdf",
    "delete-pages": "pages-removed.pdf", "extract-pages": "extracted-pages.pdf", "watermark-pdf": "watermarked.pdf",
  };
  return [await savePdf(output, names[operation] ?? "result.pdf")];
}

export function downloadOutput(output: OutputFile) {
  const blob = new Blob([output.bytes as BlobPart], { type: output.mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = output.name;
  link.click();
  URL.revokeObjectURL(url);
}
