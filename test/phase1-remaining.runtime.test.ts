import assert from "node:assert/strict";
import test from "node:test";
import { degrees, PDFDocument, PDFHexString, PDFName, rgb, StandardFonts } from "pdf-lib";
import { assertSplitOutputCount, findTextBoundaries } from "@/lib/pdf/phase1";
import { runPdfWorkerTool } from "@/lib/pdf/server";
import { renderPdfToJpegs } from "@/lib/pdf/server-canvas";
import { validateToolOptions } from "@/lib/tools/options";
import { toolRegistry, workerToolIds } from "@/lib/tools/registry";
import { isPublicApiTool } from "@/lib/tools/registry";
import { validateWorkflowDefinition } from "@/lib/workflows/validator";
import { validateAgentPlan } from "@/lib/agent/validator";
import { PLAN_POLICIES } from "@/lib/entitlements/policy";
import type { AgentPlanDraft, TrustedAgentContext } from "@/lib/agent/types";
import { runtimeLimits } from "@/lib/runtime/config";

async function corpus(pages = 4) {
  const pdf = await PDFDocument.create(); const font = await pdf.embedFont(StandardFonts.Helvetica);
  for (let index = 0; index < pages; index += 1) {
    const page = pdf.addPage(index % 2 ? [792, 612] : [420 + index * 30, 600 + index * 20]);
    page.setRotation(degrees(([0, 90, 180, 270] as const)[index % 4]));
    page.drawText(index === 1 || index === 3 ? `SECTION ${index}` : `Page ${index + 1}`, { x: 40, y: 80, size: 24, font, color: rgb(0.1 * index, 0.2, 0.7) });
  }
  return pdf.save({ useObjectStreams: true });
}

async function reopen(outputs: Awaited<ReturnType<typeof runPdfWorkerTool>>) {
  for (const output of outputs) { assert.equal(output.mimeType, "application/pdf"); assert.ok(output.bytes.byteLength); assert.ok((await PDFDocument.load(output.bytes)).getPageCount() > 0); }
}

test("remaining Phase 1 registry entries expose v1 deterministic contracts", () => {
  for (const id of ["split-pdf-by-size", "split-pdf-by-bookmarks", "split-pdf-by-text", "n-up-pdf", "remove-annotations"]) {
    const tool = toolRegistry[id]; assert.ok(tool); assert.equal(tool.version, "1"); assert.equal(tool.optionSchemaVersion, "1"); assert.equal(tool.aiFlag, false); assert.deepEqual(tool.locales, ["en", "ar"]); assert.equal(workerToolIds.has(id), true);
  }
  assert.throws(() => validateToolOptions("split-pdf-by-size", { targetSizeMb: 0 }), /below its minimum/);
  assert.throws(() => validateToolOptions("split-pdf-by-text", { matchText: "" }), /required/);
  assert.throws(() => validateToolOptions("n-up-pdf", { layout: 3 }), /unsupported/);
  assert.throws(() => assertSplitOutputCount(runtimeLimits.maxOutputFiles + 1), /too many output files/);
});

test("remaining tools share Workflow, Agent, and Public API option validation", () => {
  const workflow = validateWorkflowDefinition({ schemaVersion: 1, inputs: { document: { mimeTypes: ["application/pdf"], maxFiles: 1 } }, nodes: [{ id: "split", toolId: "split-pdf-by-text", toolVersion: "1", dependsOn: [], inputs: [{ source: "workflow", input: "document" }], options: { matchText: "الفصل", caseSensitive: false } }] }, PLAN_POLICIES.PRO);
  assert.equal(workflow.valid, true, JSON.stringify(workflow.issues));
  const invalidWorkflow = validateWorkflowDefinition({ schemaVersion: 1, nodes: [{ id: "split", toolId: "split-pdf-by-text", toolVersion: "1", dependsOn: [], inputs: [{ source: "workflow", input: "document" }], options: { regex: ".*" } }] });
  assert.equal(invalidWorkflow.valid, false); assert.match(JSON.stringify(invalidWorkflow.issues), /Unknown option regex/);
  const draft: AgentPlanDraft = { schemaVersion: 1, planId: "11111111-1111-4111-8111-111111111111", version: 1, steps: [{ stepId: "nup", toolId: "n-up-pdf", toolVersion: "1", dependsOn: [], inputs: [{ source: "request", input: "documents" }], options: { layout: 4 }, reason: "تجميع الصفحات" }] };
  const context: TrustedAgentContext = { userId: "user", correlationId: "correlation", locale: "ar", allowedToolIds: new Set(["n-up-pdf"]), entitlements: PLAN_POLICIES.PRO, budget: { maxSteps: 20, maxInputTokens: 1, maxOutputTokens: 1, maxCredits: 100, maxExecutionMs: 60_000 }, approvalPolicyVersion: "v1", policyVersion: "v1" };
  const agent = validateAgentPlan(draft, { inputs: { documents: [{ id: "file", mimeType: "application/pdf", size: 10_000, pageCount: 4 }] }, fileIds: ["file"] }, context); assert.equal(agent.valid, true, JSON.stringify(agent.issues));
  for (const id of ["split-pdf-by-size", "split-pdf-by-bookmarks", "split-pdf-by-text", "n-up-pdf", "remove-annotations"]) assert.equal(isPublicApiTool(toolRegistry[id]), true);
});

test("Split by Size is deterministic, bounded, reopenable, and permits an unavoidable oversized single page", async () => {
  const input = await corpus(3);
  const first = await runPdfWorkerTool("split-pdf-by-size", [input], { targetSizeMb: 0.0001 });
  const second = await runPdfWorkerTool("split-pdf-by-size", [input], { targetSizeMb: 0.0001 });
  assert.equal(first.length, 3); assert.deepEqual(first.map((x) => x.name), second.map((x) => x.name));
  assert.ok(first.every((x) => x.bytes.byteLength > 0.0001 * 1024 * 1024));
  await reopen(first);
});

test("Split by Text uses literal matching, handles repeated matches, Arabic RTL text, case, and no-match", async () => {
  assert.deepEqual(findTextBoundaries([{ page: 1, text: "مقدمة" }, { page: 2, text: "القسم العربي" }, { page: 3, text: "القسم العربي القسم العربي" }], "القسم العربي", false), [1, 2]);
  assert.deepEqual(findTextBoundaries([{ page: 1, text: "Section" }], "section", false), [0]);
  assert.deepEqual(findTextBoundaries([{ page: 1, text: "Section" }], "section", true), []);
  const input = await corpus(4); const outputs = await runPdfWorkerTool("split-pdf-by-text", [input], { matchText: "SECTION", caseSensitive: true });
  assert.deepEqual(await Promise.all(outputs.map(async (x) => (await PDFDocument.load(x.bytes)).getPageCount())), [1, 2, 1]);
  await assert.rejects(() => runPdfWorkerTool("split-pdf-by-text", [input], { matchText: "not present", caseSensitive: false }), /not found|Image-only/i);
  await reopen(outputs);
});

async function bookmarkedPdf(remote = false) {
  const pdf = await PDFDocument.create(); const pages = [pdf.addPage(), pdf.addPage(), pdf.addPage(), pdf.addPage()];
  const child = pdf.context.obj({ Title: PDFHexString.fromText("الفصل العربي"), Dest: pdf.context.obj([pages[2].ref, PDFName.of("Fit")]) });
  const childRef = pdf.context.register(child);
  const second = pdf.context.obj({ Title: PDFHexString.fromText("Duplicate"), Dest: pdf.context.obj([pages[1].ref, PDFName.of("Fit")]), First: childRef });
  const secondRef = pdf.context.register(second);
  const first = remote
    ? pdf.context.obj({ Title: PDFHexString.fromText("Remote"), A: pdf.context.obj({ S: PDFName.of("GoToR"), F: PDFHexString.fromText("other.pdf") }) })
    : pdf.context.obj({ Title: PDFHexString.fromText("Duplicate"), Dest: pdf.context.obj([pages[0].ref, PDFName.of("Fit")]), Next: secondRef });
  const firstRef = pdf.context.register(first); const outlines = pdf.context.obj({ First: firstRef }); const outlinesRef = pdf.context.register(outlines); pdf.catalog.set(PDFName.of("Outlines"), outlinesRef);
  return pdf.save({ useObjectStreams: false });
}

test("Split by Bookmarks supports nested/duplicate/Arabic titles and rejects missing or remote destinations", async () => {
  const outputs = await runPdfWorkerTool("split-pdf-by-bookmarks", [await bookmarkedPdf()], {});
  assert.deepEqual(await Promise.all(outputs.map(async (x) => (await PDFDocument.load(x.bytes)).getPageCount())), [1, 1, 2]); await reopen(outputs);
  const noBookmarks = await corpus(1); const remote = await bookmarkedPdf(true);
  await assert.rejects(() => runPdfWorkerTool("split-pdf-by-bookmarks", [noBookmarks], {}), /does not contain bookmarks/);
  await assert.rejects(() => runPdfWorkerTool("split-pdf-by-bookmarks", [remote], {}), /Remote or external/);
});

test("N-up handles supported layouts, mixed sizes/rotations, reopens, and renders a golden sanity image", async () => {
  const input = await corpus(7);
  for (const layout of [2, 4, 6, 9]) {
    const outputs = await runPdfWorkerTool("n-up-pdf", [input], { layout, orientation: layout === 2 ? "landscape" : "portrait", pageSize: "a4", margin: 18, order: layout === 6 ? "column" : "row" });
    const document = await PDFDocument.load(outputs[0].bytes); assert.equal(document.getPageCount(), Math.ceil(7 / layout));
    const rendered = await renderPdfToJpegs(outputs[0].bytes, 0.8); assert.equal(rendered.length, Math.ceil(7 / layout)); assert.ok(rendered[0].bytes.byteLength > 1_000);
    await reopen(outputs);
  }
});

test("Remove Annotations removes only selected safe subtypes, preserves widgets/forms, and rejects signatures", async () => {
  const pdf = await PDFDocument.create(); const page = pdf.addPage();
  const comment = pdf.context.register(pdf.context.obj({ Type: PDFName.of("Annot"), Subtype: PDFName.of("Text"), Rect: [10, 10, 30, 30] }));
  const link = pdf.context.register(pdf.context.obj({ Type: PDFName.of("Annot"), Subtype: PDFName.of("Link"), Rect: [30, 30, 60, 60] }));
  const widget = pdf.context.register(pdf.context.obj({ Type: PDFName.of("Annot"), Subtype: PDFName.of("Widget"), Rect: [60, 60, 90, 90] }));
  page.node.set(PDFName.of("Annots"), pdf.context.obj([comment, link, widget])); const input = await pdf.save({ useObjectStreams: false });
  const commentsOnly = await runPdfWorkerTool("remove-annotations", [input], { policy: "comments" });
  const firstAnnots = (await PDFDocument.load(commentsOnly[0].bytes)).getPage(0).node.Annots(); assert.equal(firstAnnots?.size(), 2);
  const commentsLinks = await runPdfWorkerTool("remove-annotations", [input], { policy: "comments-and-links" });
  const secondAnnots = (await PDFDocument.load(commentsLinks[0].bytes)).getPage(0).node.Annots(); assert.equal(secondAnnots?.size(), 1);
  const signedMarker = new TextEncoder().encode("\n% /ByteRange [0 1 2 3]\n"); const signed = new Uint8Array(input.length + signedMarker.length); signed.set(input); signed.set(signedMarker, input.length);
  await assert.rejects(() => runPdfWorkerTool("remove-annotations", [signed], { policy: "comments" }), /signed PDFs/);
  await reopen(commentsOnly); await reopen(commentsLinks);
});
