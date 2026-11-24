/**
 * Stage 2 `fill-forms` — contract, authorization and wiring tests.
 *
 * Everything here executes without Postgres or a generated Prisma client, so it
 * is the part of the Stage 2 suite that runs in *every* environment. It proves
 * the tool is registered consistently, that the typed payload cannot leak into
 * the flat option contract, that persisted workflows and the Agent refuse it
 * explicitly, and that the job boundary and worker accept, bound and re-validate
 * the payload rather than trusting the caller.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { isPublicApiTool, toolRegistry, workerToolIds } from "../src/lib/tools/registry";
import { requiresDedicatedJobParameters, toolOptionContracts, validateToolOptions } from "../src/lib/tools/options";
import { validateWorkflowDefinition } from "../src/lib/workflows/validator";
import { toolsConfig, getTool } from "../src/config";
import { mvpToolIds } from "../src/lib/seo/tool-content";
import { toolGroups } from "../src/components/tools/tool-catalog";

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

test("S2 fill-forms registry: one versioned definition consistent with the catalogue", () => {
  const tool = getTool("fill-forms");
  assert.ok(tool, "fill-forms is not in toolsConfig");
  const definition = toolRegistry["fill-forms"];
  assert.ok(definition, "fill-forms is not in the tool registry");
  assert.equal(definition.toolId, "fill-forms");
  assert.equal(definition.version, "1");
  assert.equal(definition.optionSchemaVersion, toolOptionContracts["fill-forms"].version);
  assert.equal(definition.executionMode, "server");
  assert.equal(definition.securityClass, "restricted");
  assert.equal(definition.aiFlag, false);
  assert.deepEqual(definition.mime.input, ["application/pdf"]);
  assert.deepEqual(definition.mime.output, ["application/pdf"]);
  assert.equal(definition.limits.maxFiles, 1);
  assert.equal(definition.limits.maxPages, 200);
  assert.ok(workerToolIds.has("fill-forms"), "the document worker must own fill-forms");
  assert.ok(mvpToolIds.includes("fill-forms"));
  assert.ok((toolGroups.find((group) => group.id === "organize")?.tools ?? []).includes("fill-forms"));
  // Every registry key still matches a configured tool (the invariant other tests rely on).
  assert.equal(Object.keys(toolRegistry).length, toolsConfig.length);
  assert.equal(workerToolIds.size, toolsConfig.length);
});

test("S2 fill-forms options: only `flatten` is an option; the typed payload is a separate parameter", () => {
  const contract = toolOptionContracts["fill-forms"];
  assert.deepEqual(Object.keys(contract.properties), ["flatten"]);
  assert.equal(contract.version, "1");
  assert.deepEqual(validateToolOptions("fill-forms", {}), { flatten: false });
  assert.deepEqual(validateToolOptions("fill-forms", { flatten: true }), { flatten: true });
  assert.throws(() => validateToolOptions("fill-forms", { flatten: "yes" as unknown as boolean }));
  // Field values must never be accepted as a flat option or a JSON string.
  assert.throws(() => validateToolOptions("fill-forms", { fields: { a: "x" } } as unknown as Record<string, string>));
  assert.throws(() => validateToolOptions("fill-forms", { fields: '{"a":"x"}' } as unknown as Record<string, string>));
  assert.equal(requiresDedicatedJobParameters("fill-forms"), true);
  assert.equal(requiresDedicatedJobParameters("merge-pdf"), false);
  // The schema advertises the reserved parameter name for API consumers.
  assert.equal(toolRegistry["fill-forms"].fieldsParameter, "fields");
  assert.equal(toolRegistry["merge-pdf"].fieldsParameter, undefined);
});

test("S2 fill-forms integration: persisted workflows and the Agent refuse the typed payload explicitly", () => {
  const result = validateWorkflowDefinition({ schemaVersion: 1, nodes: [{ id: "fill", toolId: "fill-forms", toolVersion: "1", dependsOn: [], inputs: [{ source: "workflow", input: "documents" }] }] });
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === "WORKFLOW_TYPED_INPUT_UNSUPPORTED"), "a workflow can silently persist an unfillable fill-forms node");
  // Existing behaviour must be unchanged for ordinary tools.
  assert.equal(validateWorkflowDefinition({ schemaVersion: 1, nodes: [{ id: "merge", toolId: "merge-pdf", toolVersion: "1", dependsOn: [], inputs: [{ source: "workflow", input: "documents" }] }] }).valid, true);
  const agent = read("src/lib/agent/runtime.ts");
  assert.match(agent, /agentExcludedTools = new Set\(\[[^\]]*"fill-forms"/u);
});

test("S2 fill-forms API surface: public job API advertises the parameter, sync route stays closed", () => {
  const definition = toolRegistry["fill-forms"];
  // Public API eligibility is deliberate: /v1/jobs accepts extra multipart parts
  // and the payload is validated server-side, so the tool is API-eligible.
  assert.equal(isPublicApiTool(definition), true);
  const syncRoute = read("src/app/api/tools/[tool]/route.ts");
  assert.match(syncRoute, /SYNC_PROCESSING_DISABLED/u);
  assert.doesNotMatch(syncRoute, /fillFormPdf|form-fill/u, "the legacy synchronous route must never reach the form engine");
});

test("S2 fill-forms boundary: the job route bounds the payload before it is read, parsed and forwarded", () => {
  const route = read("src/app/api/jobs/[tool]/route.ts");
  assert.match(route, /form\.get\("fields"\)/u);
  assert.match(route, /64 \* 1024/u, "the API must reject an oversized payload before parsing it");
  assert.match(route, /FIELDS_INPUT_INVALID/u);
  assert.match(route, /fields \? \{ fields \} : \{\}/u, "the payload must reach createToolJob as data");
  assert.match(route, /FORM_VALUE_INVALID|FORM_UNSUPPORTED|FORM_NOT_FOUND|FORM_RESTRICTED/u, "form rejections must map to a 422 with a real code");
});

test("S2 fill-forms worker: the engine is invoked by the pipeline, never by a route or by the client bundle", () => {
  const pipeline = read("src/lib/jobs/document-pipeline.ts");
  assert.match(pipeline, /job\.toolId === "fill-forms"/u);
  assert.match(pipeline, /parseFieldsPayload\(rawParams\.fields\)/u, "the worker must re-validate the stored payload");
  assert.match(pipeline, /fillFormPdf\(bytes\[0\]/u);
  assert.match(pipeline, /"fill-forms"/u);
  // The output screening step must run for the filled PDF like any other tool.
  assert.match(pipeline, /screenAndStoreWorkerOutputs/u);
  // No route module imports the engine.
  for (const path of ["src/app/api/jobs/[tool]/route.ts", "src/app/api/fill-forms/inspect/route.ts", "src/app/api/tools/[tool]/route.ts"]) {
    assert.doesNotMatch(read(path), /fillFormPdf\b|document-pipeline|runPdfWorkerTool/u, `${path} must not run the fill engine`);
  }
  // Inspection is the one read-only engine entry point a route may use, and only
  // to describe the form — never to produce a document.
  assert.doesNotMatch(read("src/app/api/fill-forms/inspect/route.ts"), /inspectFormPdf[\s\S]{0,400}fillFormPdf/u);
  // The inspect route is read-only: no job, no storage, no queue.
  const inspect = read("src/app/api/fill-forms/inspect/route.ts");
  assert.match(inspect, /inspectFormPdf/u);
  assert.doesNotMatch(inspect, /createToolJob|enqueueJob|getStorage|tx\.job/u);
});

test("S2 fill-forms browser safety: the client never imports pdf-lib and never builds its own request", () => {
  for (const path of ["src/components/tools/fill-forms-workspace.tsx", "src/lib/client/form-inspection.ts"]) {
    const source = read(path);
    assert.doesNotMatch(source, /from "pdf-lib"|from "@napi-rs\/canvas"/u, `${path} must stay browser-safe`);
    // Shared validation comes from the pure module, not the PDF-touching one.
    assert.doesNotMatch(source, /@\/lib\/pdf\/form-schema/u, `${path} must not import pdf-lib transitively`);
  }
  const workspace = read("src/components/tools/fill-forms-workspace.tsx");
  assert.doesNotMatch(workspace, /fetch\(/u);
  assert.doesNotMatch(workspace, /new FormData\(/u);
  assert.match(workspace, /inspectFillForm/u);
  assert.match(workspace, /submitServerToolJob/u);
  assert.match(workspace, /pollJobOutput/u);
  assert.match(workspace, /downloadServerToolOutputWithRetry/u);
  assert.match(workspace, /validateFillValues/u, "the browser must use the same validator as the worker");
  assert.match(workspace, /parseFieldsPayload/u);
});

test("S2 fill-forms client contract: fields travel as their own multipart part and are fingerprinted", () => {
  const client = read("src/lib/client/server-tool-job.ts");
  assert.match(client, /form\.set\("fields", JSON\.stringify\(input\.fields\)\)/u);
  assert.match(client, /fields\?: Record<string, unknown>/u);
  const fingerprint = client.slice(client.indexOf("export function submissionFingerprint"), client.indexOf("export function idempotencyFor"));
  assert.match(fingerprint, /request\.fields/u, "editing a value must produce a new idempotency fingerprint");
});

test("S2 fill-forms public API: /v1/jobs accepts the bounded fields part and binds it into the idempotency hash", () => {
  const source = read("src/lib/public-api/jobs.ts");
  assert.match(source, /form\.get\("fields"\)/u);
  assert.match(source, /assertFieldsPayloadSize\(rawFields\)/u, "the public API must bound the payload before parsing");
  assert.match(source, /parseFieldsPayload\(parsed\)/u);
  assert.match(source, /requiresDedicatedJobParameters\(toolId\) && !fields/u, "the payload must be mandatory for fill-forms");
  assert.match(source, /requiresDedicatedJobParameters\(toolId\) && fields[^\n]*does not accept a fields payload/u);
  // A replay with the same key must not be served for different values.
  assert.match(source, /Object\.entries\(fields\)/u);
  assert.match(source, /requestHash/u);
  // The payload reaches the orchestrator as data, alongside options.
  assert.match(source, /createToolJob\(\{[^}]*fields: input\.fields/u);
});
