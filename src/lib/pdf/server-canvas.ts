import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { createCanvas, GlobalFonts } from "@napi-rs/canvas";
import { runtimeLimits } from "@/lib/runtime/config";
import { recordMetric } from "@/lib/observability/metrics";
import { normalizePdfJsData } from "@/lib/pdf/pdfjs-data";

const require = createRequire(import.meta.url);
const pdfJsRoot = dirname(require.resolve("pdfjs-dist/package.json"));
const standardFontDataUrl = `${join(pdfJsRoot, "standard_fonts").replaceAll("\\", "/")}/`;
let fontsReady = false;
function registerWatermarkFonts() {
  if (fontsReady) return;
  const arabic = require.resolve("@fontsource/noto-sans-arabic/files/noto-sans-arabic-arabic-700-normal.woff");
  const latin = require.resolve("@fontsource/noto-sans-arabic/files/noto-sans-arabic-latin-700-normal.woff");
  if (!GlobalFonts.registerFromPath(arabic, "DIP Noto Arabic") || !GlobalFonts.registerFromPath(latin, "DIP Noto Latin")) throw Object.assign(new Error("Unable to register watermark fonts"), { code: "FONT_UNAVAILABLE" });
  fontsReady = true;
}

export async function renderPdfToJpegs(bytes: Uint8Array, quality = 0.9) {
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs");
  // PDF.js transfers the backing buffer to its worker; copy it so retries/callers retain input bytes.
  const loadingOptions = { data: normalizePdfJsData(bytes), isEvalSupported: false, useSystemFonts: false, standardFontDataUrl } as unknown as Parameters<typeof pdfjs.getDocument>[0];
  const task = pdfjs.getDocument(loadingOptions);
  try {
    const document = await task.promise;
    if (document.numPages > runtimeLimits.maxPages) throw Object.assign(new Error("PDF exceeds the page limit"), { code: "PAGE_LIMIT_EXCEEDED" });
    const outputs: Array<{ bytes: Uint8Array; pageWidth: number; pageHeight: number }> = [];
    for (let pageNumber = 1; pageNumber <= document.numPages; pageNumber += 1) {
      const page = await document.getPage(pageNumber); const pageSize = page.getViewport({ scale: 1 }); const viewport = page.getViewport({ scale: 1.5 });
      const pixels = viewport.width * viewport.height;
      if (pixels > runtimeLimits.maxRenderedPixelsPerPage) throw Object.assign(new Error("Rendered page exceeds the pixel limit"), { code: "PAGE_DIMENSION_LIMIT_EXCEEDED" });
      const canvas = createCanvas(Math.ceil(viewport.width), Math.ceil(viewport.height)); const context = canvas.getContext("2d"); context.fillStyle = "#ffffff"; context.fillRect(0, 0, canvas.width, canvas.height);
      const started = performance.now();
      await page.render({ canvas: canvas as never, canvasContext: context as never, viewport }).promise;
      outputs.push({ bytes: canvas.toBuffer("image/jpeg", Math.max(0, Math.min(100, Math.round(quality * 100)))), pageWidth: pageSize.width, pageHeight: pageSize.height });
      recordMetric("pdf_page_render_time", performance.now() - started, "ms", { page: pageNumber, pixels });
      page.cleanup();
    }
    return outputs;
  } catch (error) { if (typeof error === "object" && error && "code" in error) throw error; throw Object.assign(new Error(error instanceof Error ? error.message : "PDF rendering failed"), { code: "PDF_RENDER_FAILED" }); }
  finally { await task.destroy(); }
}

export function createServerWatermarkPng(text: string) {
  registerWatermarkFonts(); const hasArabic = /[\u0600-\u06ff]/.test(text); const canvas = createCanvas(1400, 240); const context = canvas.getContext("2d");
  context.clearRect(0, 0, canvas.width, canvas.height); context.fillStyle = "#475569"; context.textAlign = "center"; context.textBaseline = "middle"; context.direction = hasArabic ? "rtl" : "ltr";
  let size = 86; const family = hasArabic ? '"DIP Noto Arabic", "DIP Noto Latin"' : '"DIP Noto Latin", "DIP Noto Arabic"';
  do { context.font = `700 ${size}px ${family}`; size -= 2; } while (size > 30 && context.measureText(text).width > canvas.width - 80);
  context.fillText(text, canvas.width / 2, canvas.height / 2, canvas.width - 80); return canvas.toBuffer("image/png");
}
