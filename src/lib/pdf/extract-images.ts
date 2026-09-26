import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { createCanvas } from "@napi-rs/canvas";
import { runtimeLimits } from "@/lib/runtime/config";
import { normalizePdfJsData } from "@/lib/pdf/pdfjs-data";

const require = createRequire(import.meta.url); const pdfJsRoot = dirname(require.resolve("pdfjs-dist/package.json")); const standardFontDataUrl = `${join(pdfJsRoot, "standard_fonts").replaceAll("\\", "/")}/`;
const MAX_IMAGE_DIMENSION = 16_384; const MAX_IMAGE_PIXELS = 40_000_000;
const MAX_EXTRACT_OUTPUTS = 100;
type PdfImage = { width: number; height: number; kind: number; data: Uint8Array | Uint8ClampedArray };
type Output = { name: string; mimeType: string; bytes: Uint8Array };
type PdfObjects = { get(id: string): PdfImage };
async function resolvedImage(stores: PdfObjects[], id: string) { for (let attempt = 0; attempt < 100; attempt += 1) { for (const objects of stores) try { return objects.get(id); } catch { /* resolution is asynchronous; try the alternate store and bounded poll */ } await new Promise((resolve) => setTimeout(resolve, 10)); } throw new Error("Embedded image object did not resolve within the bounded wait."); }

function imageToPng(image: PdfImage, imageKind: { GRAYSCALE_1BPP: number; RGB_24BPP: number; RGBA_32BPP: number }) {
  if (!image || !(image.data instanceof Uint8Array || image.data instanceof Uint8ClampedArray)) throw Object.assign(new Error("The embedded image object is not available as a bounded pixel buffer."), { code: "EMBEDDED_IMAGE_FORMAT_UNSUPPORTED" });
  if (!Number.isSafeInteger(image.width) || !Number.isSafeInteger(image.height) || image.width < 1 || image.height < 1 || image.width > MAX_IMAGE_DIMENSION || image.height > MAX_IMAGE_DIMENSION || image.width * image.height > MAX_IMAGE_PIXELS) throw Object.assign(new Error("An embedded image exceeds the safe dimension limit."), { code: "IMAGE_DIMENSION_LIMIT_EXCEEDED" });
  const rgba = new Uint8ClampedArray(image.width * image.height * 4);
  if (image.kind === imageKind.RGBA_32BPP && image.data.length === rgba.length) rgba.set(image.data);
  else if (image.kind === imageKind.RGB_24BPP && image.data.length === image.width * image.height * 3) for (let source = 0, target = 0; source < image.data.length; source += 3, target += 4) { rgba[target] = image.data[source]; rgba[target + 1] = image.data[source + 1]; rgba[target + 2] = image.data[source + 2]; rgba[target + 3] = 255; }
  else if (image.kind === imageKind.GRAYSCALE_1BPP) for (let pixel = 0; pixel < image.width * image.height; pixel += 1) { const value = ((image.data[pixel >> 3] >> (7 - (pixel & 7))) & 1) ? 255 : 0; const target = pixel * 4; rgba[target] = rgba[target + 1] = rgba[target + 2] = value; rgba[target + 3] = 255; }
  else throw Object.assign(new Error("The embedded image decoding format is unsupported."), { code: "EMBEDDED_IMAGE_FORMAT_UNSUPPORTED" });
  const canvas = createCanvas(image.width, image.height); const context = canvas.getContext("2d"); const target = context.createImageData(image.width, image.height); target.data.set(rgba); context.putImageData(target, 0, 0); return new Uint8Array(canvas.toBuffer("image/png"));
}

export async function extractEmbeddedImages(bytes: Uint8Array): Promise<Output[]> {
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs"); const task = pdfjs.getDocument({ data: normalizePdfJsData(bytes), isEvalSupported: false, useSystemFonts: false, standardFontDataUrl } as never);
  try {
    const document = await task.promise; if (document.numPages > runtimeLimits.maxPages) throw Object.assign(new Error("PDF exceeds the page limit."), { code: "PAGE_LIMIT_EXCEEDED" });
    const outputs: Output[] = []; const hashes = new Set<string>(); let unsupported = 0; let duplicates = 0; let totalBytes = 0;
    for (let pageNumber = 1; pageNumber <= document.numPages; pageNumber += 1) {
      const page = await document.getPage(pageNumber); const operators = await page.getOperatorList(); const pageAny = page as unknown as { objs: PdfObjects; commonObjs: PdfObjects };
      for (let index = 0; index < operators.fnArray.length; index += 1) {
        if ([pdfjs.OPS.paintInlineImageXObject, pdfjs.OPS.paintInlineImageXObjectGroup].includes(operators.fnArray[index])) { unsupported += 1; continue; }
        if (operators.fnArray[index] !== pdfjs.OPS.paintImageXObject && operators.fnArray[index] !== pdfjs.OPS.paintImageXObjectRepeat) continue;
        if (operators.fnArray[index] === pdfjs.OPS.paintImageXObject) { const declaredWidth = Number(operators.argsArray[index]?.[1]); const declaredHeight = Number(operators.argsArray[index]?.[2]); if (!Number.isSafeInteger(declaredWidth) || !Number.isSafeInteger(declaredHeight) || declaredWidth < 1 || declaredHeight < 1 || declaredWidth > MAX_IMAGE_DIMENSION || declaredHeight > MAX_IMAGE_DIMENSION || declaredWidth * declaredHeight > MAX_IMAGE_PIXELS) throw Object.assign(new Error("An embedded image exceeds the safe pre-decode dimension limit."), { code: "IMAGE_DIMENSION_LIMIT_EXCEEDED" }); }
        const objectId = String(operators.argsArray[index]?.[0] ?? ""); let image: PdfImage; try { image = await resolvedImage([pageAny.objs, pageAny.commonObjs], objectId); } catch { unsupported += 1; continue; }
        let png: Uint8Array; try { png = imageToPng(image, pdfjs.ImageKind); } catch (error) { if (typeof error === "object" && error && "code" in error && error.code === "EMBEDDED_IMAGE_FORMAT_UNSUPPORTED") { unsupported += 1; continue; } throw error; }
        const hash = createHash("sha256").update(png).digest("hex"); if (hashes.has(hash)) { duplicates += 1; continue; } hashes.add(hash);
        totalBytes += png.byteLength; if (outputs.length + 1 >= Math.min(runtimeLimits.maxOutputFiles, MAX_EXTRACT_OUTPUTS) || totalBytes > runtimeLimits.maxOutputBytes) throw Object.assign(new Error("Extracted images exceed the configured output limits."), { code: "OUTPUT_LIMIT_EXCEEDED" });
        outputs.push({ name: `page-${pageNumber}-image-${outputs.length + 1}.png`, mimeType: "image/png", bytes: png });
      }
    }
    if (!outputs.length) throw Object.assign(new Error(`No supported embedded image XObjects were found (${unsupported} unsupported object(s)).`), { code: "NO_SUPPORTED_EMBEDDED_IMAGES" });
    const manifest = { schemaVersion: 1, mode: "decoded-embedded-images", originalStreamsPreserved: false, extracted: outputs.length, duplicatesSkipped: duplicates, unsupportedObjectsSkipped: unsupported, masks: "accepted only when PDF.js supplies a decoded bounded pixel buffer", note: "These are decoded embedded image XObjects, not rendered page screenshots and not guaranteed byte-identical original streams." }; const report = new TextEncoder().encode(JSON.stringify(manifest, null, 2));
    if (totalBytes + report.byteLength > runtimeLimits.maxOutputBytes) throw Object.assign(new Error("Extracted images exceed the configured total-output limit."), { code: "OUTPUT_LIMIT_EXCEEDED" }); outputs.push({ name: "extract-images-report.json", mimeType: "application/json", bytes: report }); return outputs;
  } finally { await task.destroy(); }
}
