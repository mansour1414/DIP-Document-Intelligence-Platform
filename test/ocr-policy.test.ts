import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { APPROVED_OCR_EXECUTABLE, approvedOcrArguments } from "../src/lib/document-processing/ocr-policy";

test("approved OCR command is explicit, standard-PDF, unoptimized and Ghostscript-free", () => {
  const args = [...approvedOcrArguments("ara+eng", "/tmp/input.pdf", "/tmp/output.pdf")];
  const valueAfter = (option: string) => args[args.indexOf(option) + 1];

  assert.equal(APPROVED_OCR_EXECUTABLE, "ocrmypdf");
  assert.equal(valueAfter("--output-type"), "pdf");
  assert.equal(valueAfter("--optimize"), "0");
  assert.equal(valueAfter("--rasterizer"), "pypdfium");
  assert.equal(valueAfter("--ocr-engine"), "tesseract");
  assert.equal(valueAfter("--language"), "ara+eng");
  assert.equal(args.includes("gs"), false);
  assert.deepEqual(args.slice(-2), ["/tmp/input.pdf", "/tmp/output.pdf"]);
});

test("heavy CI keeps bilingual OCR corpus enabled and verifies the approved runtime", async () => {
  const workflow = await readFile(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
  const verifier = await readFile(new URL("../scripts/verify-ocr-runtime.py", import.meta.url), "utf8");

  assert.match(workflow, /tesseract-ocr-eng tesseract-ocr-ara/);
  assert.match(workflow, /python scripts\/verify-ocr-runtime\.py/);
  assert.match(workflow, /RUN_PROCESSING_CORPUS: "1"/);
  assert.match(workflow, /FULL_PROCESSING_E2E: "1"/);
  assert.doesNotMatch(verifier, /\["ocrmypdf", "--help"\]/);
  assert.match(verifier, /\["ocrmypdf", "--version"\]/);
  assert.match(verifier, /TemporaryDirectory/);
  assert.match(verifier, /"--output-type",\s+"pdf"/);
  assert.match(verifier, /"--optimize",\s+"0"/);
  assert.match(verifier, /"--rasterizer",\s+"pypdfium"/);
  assert.match(verifier, /"--ocr-engine",\s+"tesseract"/);
  assert.match(verifier, /startswith\(b"%PDF-"\)/);
});
