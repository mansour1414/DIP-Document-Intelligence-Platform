import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createCanvas, loadImage } from "@napi-rs/canvas";
import { degrees, PDFDocument, rgb } from "pdf-lib";
import { PLAN_POLICIES } from "../src/lib/entitlements/policy";
import { validateAgentPlan } from "../src/lib/agent/validator";
import type { AgentPlanDraft, ResolvedAgentScope, TrustedAgentContext } from "../src/lib/agent/types";
import { runPdfWorkerTool } from "../src/lib/pdf/server";
import { renderPdfToJpegs } from "../src/lib/pdf/server-canvas";
import { extractPdfTextServer } from "../src/lib/pdf/text-server";
import { validateWorkerOutputs } from "../src/lib/outputs/validation";
import { ToolOptionsValidationError, validateToolOptions } from "../src/lib/tools/options";
import { toolRegistry } from "../src/lib/tools/registry";
import { validateWorkflowDefinition } from "../src/lib/workflows/validator";

async function mixedFixture() {
  const document = await PDFDocument.create();
  const first = document.addPage([600, 800]); first.drawText("VISIBLE ENGLISH", { x: 220, y: 400 }); first.drawText("HIDDEN_SECRET", { x: 8, y: 8, size: 10, color: rgb(0, 0, 0) });
  const second = document.addPage([800, 500]); second.setRotation(degrees(90)); second.drawText("ROTATED PAGE", { x: 300, y: 250 });
  return document.save({ useObjectStreams: true });
}

async function darkPixels(bytes: Uint8Array, band: "top" | "bottom") {
  const image = await loadImage(bytes); const canvas = createCanvas(image.width, image.height); const context = canvas.getContext("2d"); context.drawImage(image, 0, 0); const pixels = context.getImageData(0, 0, image.width, image.height).data;
  const startY = band === "top" ? 0 : Math.floor(image.height * 0.72); const endY = band === "top" ? Math.ceil(image.height * 0.28) : image.height; let count = 0;
  for (let y = startY; y < endY; y += 1) for (let x = 0; x < image.width; x += 1) { const offset = (y * image.width + x) * 4; if (pixels[offset] < 180 && pixels[offset + 1] < 180 && pixels[offset + 2] < 180) count += 1; }
  return count;
}

test("versioned tool options reject unknown, missing and unsafe values", () => {
  assert.deepEqual(validateToolOptions("crop-pdf", { topPercent: 5 }), { topPercent: 5, rightPercent: 0, bottomPercent: 0, leftPercent: 0 });
  assert.equal(toolRegistry["crop-pdf"].optionSchemaVersion, "1");
  assert.throws(() => validateToolOptions("crop-pdf", { topPercent: 0 }), ToolOptionsValidationError);
  assert.throws(() => validateToolOptions("page-numbers", { format: "total only" }), /include \{page\}/);
  assert.throws(() => validateToolOptions("header-footer", { headerText: "", footerText: "", shell: true }), /Unknown option shell/);
});

test("Workflow and Agent use the same option validation contract", () => {
  const workflow = { schemaVersion: 1, nodes: [{ id: "crop", toolId: "crop-pdf", toolVersion: "1", dependsOn: [], inputs: [{ source: "workflow", input: "documents" }], options: { topPercent: 60 } }] };
  assert.ok(validateWorkflowDefinition(workflow).issues.some((issue) => issue.code === "WORKFLOW_PARAMETERS_INVALID"));
  const draft: AgentPlanDraft = { schemaVersion: 1, planId: "plan", version: 1, steps: [{ stepId: "number", toolId: "page-numbers", toolVersion: "1", dependsOn: [], inputs: [{ source: "request", input: "documents" }], options: { format: "invalid" }, reason: "Number pages" }] };
  const scope: ResolvedAgentScope = { inputs: { documents: [{ id: "11111111-1111-4111-8111-111111111111", mimeType: "application/pdf", size: 100, pageCount: 2 }] }, fileIds: ["11111111-1111-4111-8111-111111111111"] };
  const context: TrustedAgentContext = { userId: "user", correlationId: "correlation", locale: "en", allowedToolIds: new Set(["page-numbers"]), entitlements: PLAN_POLICIES.PRO, budget: { maxSteps: 20, maxInputTokens: 1, maxOutputTokens: 1, maxCredits: 100, maxExecutionMs: 60_000 }, approvalPolicyVersion: "v1", policyVersion: "v1" };
  assert.ok(validateAgentPlan(draft, scope, context).issues.some((issue) => issue.path.endsWith(".options")));
});

test("Crop updates CropBox on mixed sizes and rotations but preserves hidden content", async () => {
  const source = await mixedFixture(); const [output] = await runPdfWorkerTool("crop-pdf", [source], { topPercent: 10, rightPercent: 5, bottomPercent: 10, leftPercent: 5 });
  await validateWorkerOutputs([output], 2); const reopened = await PDFDocument.load(output.bytes); const [first, second] = reopened.getPages();
  assert.deepEqual(first.getCropBox(), { x: 30, y: 80, width: 540, height: 640 }); assert.equal(second.getRotation().angle, 90); const secondBox = second.getCropBox(); assert.deepEqual({ x: secondBox.x, y: secondBox.y, width: Math.round(secondBox.width), height: secondBox.height }, { x: 40, y: 50, width: 720, height: 400 });
  const visibleText = (await extractPdfTextServer(output.bytes)).map((page) => page.text).join(" "); assert.doesNotMatch(visibleText, /HIDDEN_SECRET/); assert.match(visibleText, /VISIBLE ENGLISH/);
  const restored = await PDFDocument.load(output.bytes); for (const page of restored.getPages()) { const media = page.getMediaBox(); page.setCropBox(media.x, media.y, media.width, media.height); } const restoredText = (await extractPdfTextServer(await restored.save())).map((page) => page.text).join(" "); assert.match(restoredText, /HIDDEN_SECRET/, "restoring CropBox must reveal that cropped content was never deleted");
});

test("Page Numbers and Header Footer render English and Arabic on mixed rotated pages", async () => {
  const source = await mixedFixture();
  const [numbered] = await runPdfWorkerTool("page-numbers", [source], { format: "Page {page} of {total}", position: "bottom-center", startNumber: 3, fontSize: 14, margin: 18 });
  const [labeled] = await runPdfWorkerTool("header-footer", [source], { headerText: "DIP CONFIDENTIAL", footerText: "وثيقة عربية سرية", alignment: "right", fontSize: 13, margin: 18 });
  await validateWorkerOutputs([numbered], 2); await validateWorkerOutputs([labeled], 2);
  for (const rendered of await renderPdfToJpegs(numbered.bytes, 0.9)) assert.ok(await darkPixels(rendered.bytes, "bottom") > 80, "page number must remain visible after page rotation");
  for (const rendered of await renderPdfToJpegs(labeled.bytes, 0.9)) { assert.ok(await darkPixels(rendered.bytes, "top") > 80); assert.ok(await darkPixels(rendered.bytes, "bottom") > 80); }
});

test("P1.1 golden artifacts can be written for visual regression review", { skip: process.env.WRITE_P1_1_GOLDEN !== "1" }, async () => {
  const directory = join(process.cwd(), "tmp", "pdfs", "phase1-p1.1"); await mkdir(directory, { recursive: true }); const source = await mixedFixture();
  for (const [tool, options] of [["crop-pdf", { topPercent: 10, rightPercent: 5, bottomPercent: 10, leftPercent: 5 }], ["page-numbers", { format: "صفحة {page} من {total}", position: "bottom-center", startNumber: 1, fontSize: 14, margin: 18 }], ["header-footer", { headerText: "DIP Report", footerText: "تقرير عربي", alignment: "center", fontSize: 13, margin: 18 }]] as const) { const [output] = await runPdfWorkerTool(tool, [source], options); await writeFile(join(directory, output.name), output.bytes); const pages = await renderPdfToJpegs(output.bytes, 0.9); for (let index = 0; index < pages.length; index += 1) await writeFile(join(directory, `${tool}-page-${index + 1}.jpg`), pages[index].bytes); }
});
