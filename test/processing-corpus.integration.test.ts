import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { PDFDocument } from "pdf-lib";
import { processServerDocument, type ServerToolId } from "../src/lib/document-processing/server";
import { validateWorkerOutputs } from "../src/lib/outputs/validation";
import { extractPdfTextServer } from "../src/lib/pdf/text-server";

const integration = process.env.RUN_PROCESSING_CORPUS === "1" ? test : test.skip;
const root = join(process.cwd(), "test", "fixtures", "processing");
const mime: Record<string, string> = { docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation", pdf: "application/pdf" };
async function run(tool: ServerToolId, filename: string, language?: string) { const bytes = await readFile(join(root, filename)); const ext = filename.split(".").pop()!; const started = performance.now(); const result = await processServerDocument(tool, new File([bytes], basename(filename), { type: mime[ext] }), language); const durationMs = performance.now() - started; await validateWorkerOutputs([{ name: result.filename, mimeType: result.contentType, bytes: result.bytes }]); return { result, durationMs }; }

integration("real LibreOffice corpus converts Word, Excel and PowerPoint", { timeout: 180_000 }, async () => {
  for (const [tool, name] of [["word-to-pdf", "word-en.docx"], ["word-to-pdf", "word-ar.docx"], ["word-to-pdf", "word-mixed.docx"], ["excel-to-pdf", "excel-corpus.xlsx"], ["powerpoint-to-pdf", "powerpoint-corpus.pptx"]] as const) {
    const { result, durationMs } = await run(tool, name); const pdf = await PDFDocument.load(result.bytes); assert.ok(pdf.getPageCount() > 0); const text = (await extractPdfTextServer(result.bytes)).map((page) => page.text).join(" "); assert.ok(text.trim().length > 3); const arabicReadable = /[\u0600-\u06ff]{3,}/u.test(text); if (name.includes("-ar") || name.includes("mixed")) assert.equal(arabicReadable, true); console.log(JSON.stringify({ corpus: "office", input: name, output: result.filename, success: true, duration_ms: durationMs, pages: pdf.getPageCount(), output_valid: true, gross_corruption: false, arabic_readable: arabicReadable, warning: "layout smoke validation only", fidelity: "not-pixel-perfect" }));
  }
});

integration("real Arabic, English, mixed, low-quality and multi-page OCR corpus", { timeout: 600_000 }, async () => {
  for (const [name, language] of [["ocr-en.pdf", "eng"], ["ocr-ar.pdf", "ara"], ["ocr-mixed.pdf", "ara+eng"], ["ocr-low-quality.pdf", "ara+eng"], ["ocr-multipage.pdf", "ara+eng"]] as const) {
    const input = await PDFDocument.load(await readFile(join(root, name))); const { result, durationMs } = await run("ocr-pdf", name, language); const output = await PDFDocument.load(result.bytes); assert.equal(output.getPageCount(), input.getPageCount()); const text = (await extractPdfTextServer(result.bytes)).map((page) => page.text).join(" "); assert.ok(text.trim().length > 3); const arabicReadable = /[\u0600-\u06ff]{3,}/u.test(text); if (language.includes("ara") && name !== "ocr-low-quality.pdf") assert.equal(arabicReadable, true); console.log(JSON.stringify({ corpus: "ocr", input: name, language, success: true, duration_ms: durationMs, ms_per_page: durationMs / output.getPageCount(), pages: output.getPageCount(), searchable: true, text_present: true, arabic_readable: arabicReadable, warning: name.includes("low-quality") ? "degraded fixture; no accuracy percentage claimed" : null }));
  }
});
