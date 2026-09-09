import test from "node:test";
import assert from "node:assert/strict";
import { PDFDocument } from "pdf-lib";
import { mergePdfBytes, pdfWorkerEngine, runPdfWorkerTool } from "../src/lib/pdf/server";
import { validateUpload } from "../src/lib/uploads/validation";
import { toolRegistry, workerToolIds } from "../src/lib/tools/registry";
import { createCanvas, loadImage } from "@napi-rs/canvas";
import { createServerWatermarkPng } from "../src/lib/pdf/server-canvas";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

async function fixture(text: string) { const pdf = await PDFDocument.create(); pdf.addPage().drawText(text); return pdf.save(); }

test("Merge PDF runtime validates content and produces one combined output", async () => {
  const first = await fixture("first"); const second = await fixture("second");
  const validation = await validateUpload({ toolId: "merge-pdf", declaredMime: "application/pdf", bytes: first });
  assert.equal(validation.mimeType, "application/pdf"); assert.equal(validation.pageCount, 1);
  const output = await mergePdfBytes([first, second]);
  assert.equal((await PDFDocument.load(output)).getPageCount(), 2);
});

test("Merge PDF rejects invalid magic bytes before storage", async () => {
  await assert.rejects(() => validateUpload({ toolId: "merge-pdf", declaredMime: "application/pdf", bytes: new Uint8Array([1, 2, 3]) }), { code: "MAGIC_BYTES_INVALID" });
});

test("registry covers the complete 18-tool catalog and first worker batch", () => {
  assert.equal(Object.keys(toolRegistry).length, 18);
  assert.equal(workerToolIds.size, 18);
  for (const tool of Object.values(toolRegistry)) assert.ok(tool.inputSchema && tool.outputSchema && tool.mime.input.length && tool.locales.includes("ar"));
});

test("Batch 2 renders PDF pages as independent JPEG outputs", async () => {
  const pdf = await PDFDocument.create(); pdf.addPage().drawText("page one"); pdf.addPage().drawText("page two");
  const outputs = await runPdfWorkerTool("pdf-to-jpg", [await pdf.save()], { quality: 0.8 });
  assert.deepEqual(outputs.map((output) => output.name), ["page-1.jpg", "page-2.jpg"]);
  for (const output of outputs) { assert.equal(output.mimeType, "image/jpeg"); assert.deepEqual(Array.from(output.bytes.slice(0, 3)), [0xff, 0xd8, 0xff]); }
  assert.deepEqual(pdfWorkerEngine("pdf-to-jpg"), { engine: "pdfjs-dist+@napi-rs/canvas", engineVersion: "6.3.289+1.0.9" });
});

test("Batch 2 compresses server-side into a valid two-page PDF", async () => {
  const pdf = await PDFDocument.create(); pdf.addPage().drawText("first"); pdf.addPage().drawText("second");
  const [output] = await runPdfWorkerTool("compress-pdf", [await pdf.save()], { quality: 0.65 });
  assert.equal(output.name, "compressed.pdf"); assert.equal((await PDFDocument.load(output.bytes)).getPageCount(), 2);
});

test("Batch 2 produces valid English and Arabic server watermarks", async () => {
  const source = await fixture("watermark target");
  const [english] = await runPdfWorkerTool("watermark-pdf", [source], { watermark: "Confidential" });
  const [arabic] = await runPdfWorkerTool("watermark-pdf", [source], { watermark: "سري للغاية" });
  assert.equal((await PDFDocument.load(english.bytes)).getPageCount(), 1); assert.equal((await PDFDocument.load(arabic.bytes)).getPageCount(), 1);
  assert.notDeepEqual(english.bytes, arabic.bytes); assert.ok(english.bytes.byteLength > source.byteLength); assert.ok(arabic.bytes.byteLength > source.byteLength);
  for (const text of ["Confidential", "سري للغاية"]) { const image = await loadImage(createServerWatermarkPng(text)); const canvas = createCanvas(image.width, image.height); const context = canvas.getContext("2d"); context.drawImage(image, 0, 0); const pixels = context.getImageData(0, 0, image.width, image.height).data; let visible = 0; for (let index = 3; index < pixels.length; index += 4) if (pixels[index] > 0) visible += 1; assert.ok(visible > 500, `${text} must render visible glyphs`); }
});

test("worker PDF batch reuses existing engines for page operations", async () => {
  const source = await fixture("one");
  const rotated = await runPdfWorkerTool("rotate-pdf", [source], { rotation: 90 });
  assert.equal(rotated.length, 1);
  assert.equal((await PDFDocument.load(rotated[0].bytes)).getPage(0).getRotation().angle, 90);
});

test("write Batch 2 visual QA artifacts", { skip: process.env.WRITE_BATCH2_QA !== "1" }, async () => {
  const directory = join(process.cwd(), "tmp", "pdfs", "worker-batch2"); await mkdir(directory, { recursive: true }); const source = await fixture("DIP visual QA");
  for (const [name, tool, options] of [["compressed.pdf", "compress-pdf", { quality: 0.65 }], ["watermark-en.pdf", "watermark-pdf", { watermark: "Confidential" }], ["watermark-ar.pdf", "watermark-pdf", { watermark: "سري للغاية" }]] as const) { const [output] = await runPdfWorkerTool(tool, [source], options); await writeFile(join(directory, name), output.bytes); }
  for (const image of await runPdfWorkerTool("pdf-to-jpg", [source], { quality: 0.8 })) await writeFile(join(directory, image.name), image.bytes);
});
