import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createCanvas, loadImage } from "@napi-rs/canvas";
import { degrees, PDFDocument, rgb } from "pdf-lib";
import { PLAN_POLICIES } from "../src/lib/entitlements/policy";
import { validateAgentPlan } from "../src/lib/agent/validator";
import type { AgentPlanDraft, ResolvedAgentScope, TrustedAgentContext } from "../src/lib/agent/types";
import { createServerTextPng, renderPdfToJpegs } from "../src/lib/pdf/server-canvas";
import { runPdfWorkerTool } from "../src/lib/pdf/server";
import { extractPdfTextServer } from "../src/lib/pdf/text-server";
import { validateWorkerOutputs } from "../src/lib/outputs/validation";
import { ToolOptionsValidationError, validateToolOptions } from "../src/lib/tools/options";
import { toolRegistry } from "../src/lib/tools/registry";
import { validateWorkflowDefinition } from "../src/lib/workflows/validator";

async function mixedFixture(prefix = "PAGE") {
  const document = await PDFDocument.create(); const arabic = await document.embedPng(createServerTextPng("وثيقة عربية Arabic document", { width: 280, fontSize: 18, alignment: "center" }));
  const specs = [[600, 800, 0], [500, 800, 90], [500, 700, 180], [480, 720, 270]] as const;
  specs.forEach(([width, height, rotation], index) => { const page = document.addPage([width, height]); page.setRotation(degrees(rotation)); page.drawRectangle({ x: 36, y: 80, width: width * 0.18, height: height * 0.42, color: rgb(0.08, 0.15, 0.3) }); page.drawText(`${prefix}-${index + 1}`, { x: width * 0.43, y: height * 0.52, size: 22 }); page.drawImage(arabic, { x: width * 0.3, y: 24, width: width * 0.5, height: 42 }); });
  return document.save({ useObjectStreams: true });
}

async function imageData(bytes: Uint8Array) { const image = await loadImage(bytes); const canvas = createCanvas(image.width, image.height); const context = canvas.getContext("2d"); context.drawImage(image, 0, 0); return { width: image.width, height: image.height, pixels: context.getImageData(0, 0, image.width, image.height).data }; }
async function visualMirrorError(source: Uint8Array, flipped: Uint8Array, axis: "horizontal" | "vertical") {
  const a = await imageData(source); const b = await imageData(flipped); assert.deepEqual([b.width, b.height], [a.width, a.height]); let difference = 0; let samples = 0;
  for (let y = 0; y < a.height; y += 3) for (let x = 0; x < a.width; x += 3) { const ai = (y * a.width + x) * 4; const targetX = axis === "horizontal" ? b.width - 1 - x : x; const targetY = axis === "vertical" ? b.height - 1 - y : y; const bi = (targetY * b.width + targetX) * 4; if (Math.min(a.pixels[ai], a.pixels[ai + 1], a.pixels[ai + 2], b.pixels[bi], b.pixels[bi + 1], b.pixels[bi + 2]) > 245) continue; difference += Math.abs(a.pixels[ai] - b.pixels[bi]) + Math.abs(a.pixels[ai + 1] - b.pixels[bi + 1]) + Math.abs(a.pixels[ai + 2] - b.pixels[bi + 2]); samples += 3; }
  assert.ok(samples > 300, "visual comparison must include non-white source content");
  return difference / samples;
}

test("P1.2 option schemas are versioned, normalized, bounded and public", () => {
  assert.deepEqual(validateToolOptions("resize-pages", {}), { pageSize: "a4", orientation: "preserve", fit: "contain" });
  assert.deepEqual(validateToolOptions("alternate-mix", {}), { startWith: "first", reverseSecond: false });
  assert.deepEqual(validateToolOptions("flip-pages", { axis: "vertical", pages: "1-3, 5" }), { axis: "vertical", pages: "1-3, 5" });
  for (const id of ["resize-pages", "alternate-mix", "flip-pages"] as const) { assert.equal(toolRegistry[id].version, "1"); assert.equal(toolRegistry[id].optionSchemaVersion, "1"); assert.equal(toolRegistry[id].optionSchema["x-schema-version"], "1"); }
  const alternateFiles = (toolRegistry["alternate-mix"].inputSchema.properties as { fileIds: { minItems: number; maxItems: number } }).fileIds; assert.deepEqual(alternateFiles, { type: "array", minItems: 2, maxItems: 2 });
  assert.throws(() => validateToolOptions("resize-pages", { pageSize: "executive" }), ToolOptionsValidationError);
  assert.throws(() => validateToolOptions("alternate-mix", { reverseSecond: "yes" }), /boolean/);
  assert.throws(() => validateToolOptions("flip-pages", { pages: "1;rm" }), /invalid format/);
});

test("Workflow and Agent apply the shared P1.2 option contracts", () => {
  const workflow = { schemaVersion: 1, nodes: [{ id: "resize", toolId: "resize-pages", toolVersion: "1", dependsOn: [], inputs: [{ source: "workflow", input: "documents" }], options: { pageSize: "unknown" } }] };
  assert.ok(validateWorkflowDefinition(workflow).issues.some((issue) => issue.code === "WORKFLOW_PARAMETERS_INVALID"));
  const draft: AgentPlanDraft = { schemaVersion: 1, planId: "plan", version: 1, steps: [{ stepId: "flip", toolId: "flip-pages", toolVersion: "1", dependsOn: [], inputs: [{ source: "request", input: "documents" }], options: { axis: "diagonal" }, reason: "Flip pages" }] };
  const scope: ResolvedAgentScope = { inputs: { documents: [{ id: "11111111-1111-4111-8111-111111111111", mimeType: "application/pdf", size: 100, pageCount: 4 }] }, fileIds: ["11111111-1111-4111-8111-111111111111"] };
  const context: TrustedAgentContext = { userId: "user", correlationId: "correlation", locale: "ar", allowedToolIds: new Set(["flip-pages"]), entitlements: PLAN_POLICIES.PRO, budget: { maxSteps: 20, maxInputTokens: 1, maxOutputTokens: 1, maxCredits: 100, maxExecutionMs: 60_000 }, approvalPolicyVersion: "v1", policyVersion: "v1" };
  assert.ok(validateAgentPlan(draft, scope, context).issues.some((issue) => issue.path.endsWith(".options")));
});

test("Resize Pages handles mixed sizes and 0/90/180/270 rotations and reopens cleanly", async () => {
  const source = await mixedFixture(); const [output] = await runPdfWorkerTool("resize-pages", [source], { pageSize: "a4", orientation: "preserve", fit: "contain" }); await validateWorkerOutputs([output], 4);
  const reopened = await PDFDocument.load(output.bytes); assert.equal(reopened.getPageCount(), 4); assert.deepEqual(reopened.getPages().map((page) => page.getRotation().angle), [0, 90, 180, 270]);
  const visualSizes = reopened.getPages().map((page) => { const quarter = [90, 270].includes(page.getRotation().angle); return quarter ? [page.getHeight(), page.getWidth()] : [page.getWidth(), page.getHeight()]; });
  assert.deepEqual(visualSizes.map(([width, height]) => [Math.round(width), Math.round(height)]), [[595, 842], [842, 595], [595, 842], [842, 595]]);
  const rendered = await renderPdfToJpegs(output.bytes, 0.92); assert.equal(rendered.length, 4); for (const page of rendered) assert.ok((await imageData(page.bytes)).pixels.some((value) => value < 80), "resized page must retain visible English and Arabic content");
});

test("Alternate & Mix interleaves unequal PDFs and reverses the second input", async () => {
  const first = await PDFDocument.create(); for (const text of ["FIRST-1", "FIRST-2", "FIRST-3"]) first.addPage().drawText(text);
  const second = await PDFDocument.create(); for (const text of ["SECOND-1", "SECOND-2"]) second.addPage().drawText(text);
  const [output] = await runPdfWorkerTool("alternate-mix", [await first.save(), await second.save()], { startWith: "first", reverseSecond: true }); await validateWorkerOutputs([output], 5);
  const reopened = await PDFDocument.load(output.bytes); assert.equal(reopened.getPageCount(), 5); const text = await extractPdfTextServer(output.bytes); assert.deepEqual(text.map((page) => page.text.trim()), ["FIRST-1", "SECOND-2", "FIRST-2", "SECOND-1", "FIRST-3"]);
  const oneInput = await first.save(); await assert.rejects(() => runPdfWorkerTool("alternate-mix", [oneInput], {}), /exactly two PDFs/);
});

test("Flip Pages mirrors the visual horizontal axis for every page rotation", async () => {
  const source = await mixedFixture(); const before = await renderPdfToJpegs(source, 0.95); const [output] = await runPdfWorkerTool("flip-pages", [source], { axis: "horizontal", pages: "1-4" }); await validateWorkerOutputs([output], 4);
  const reopened = await PDFDocument.load(output.bytes); assert.deepEqual(reopened.getPages().map((page) => page.getRotation().angle), [0, 90, 180, 270]); const after = await renderPdfToJpegs(output.bytes, 0.95);
  for (let index = 0; index < before.length; index += 1) assert.ok(await visualMirrorError(before[index].bytes, after[index].bytes, "horizontal") < 18, `page ${index + 1} must be mirrored horizontally in visual coordinates`);
  const [vertical] = await runPdfWorkerTool("flip-pages", [source], { axis: "vertical", pages: "1-4" }); const verticalPages = await renderPdfToJpegs(vertical.bytes, 0.95); for (let index = 0; index < before.length; index += 1) assert.ok(await visualMirrorError(before[index].bytes, verticalPages[index].bytes, "vertical") < 18, `page ${index + 1} must be mirrored vertically in visual coordinates`);
  await assert.rejects(() => runPdfWorkerTool("flip-pages", [source], { axis: "horizontal", pages: "5" }), /outside the document/);
});

test("P1.2 golden PDFs can be written for visual regression review", { skip: process.env.WRITE_P1_2_GOLDEN !== "1" }, async () => {
  const directory = join(process.cwd(), "tmp", "pdfs", "phase1-p1.2"); await mkdir(directory, { recursive: true }); const source = await mixedFixture(); const second = await mixedFixture("SECOND");
  for (const [tool, inputs, options] of [["resize-pages", [source], { pageSize: "a4", orientation: "preserve", fit: "contain" }], ["alternate-mix", [source, second], { startWith: "first", reverseSecond: true }], ["flip-pages", [source], { axis: "horizontal", pages: "1-4" }]] as const) { const [output] = await runPdfWorkerTool(tool, [...inputs], options); await writeFile(join(directory, output.name), output.bytes); const pages = await renderPdfToJpegs(output.bytes, 0.92); for (let index = 0; index < pages.length; index += 1) await writeFile(join(directory, `${tool}-page-${index + 1}.jpg`), pages[index].bytes); }
});
