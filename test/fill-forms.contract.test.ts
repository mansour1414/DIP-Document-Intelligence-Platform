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
import { FormFillError } from "../src/lib/pdf/form-validation";
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
  // FF-03: the worker reads the values from the encrypted, tenant+job-bound
  // reference and re-validates them there. Plaintext `fields` in `params` is
  // exactly what this changed, so the assertion now pins the new invariant: the
  // reference is read, the payload is re-validated, and no raw `fields` is
  // trusted as the primary source.
  assert.match(pipeline, /parseFieldsPayload\(/u, "the worker must re-validate the stored payload");
  assert.match(pipeline, /readFormFields\(\{ reference: rawParams\.fieldsRef/u, "the worker must read values from the encrypted payload reference");
  // The *creation* site is where plaintext used to be persisted; the orchestrator
  // must write the reference only.
  const orchestrator = read("src/lib/jobs/orchestrator.ts");
  assert.match(orchestrator, /params: \{ inputFileIds: files\.map\(\(file\) => file\.id\), options, \.\.\.\(fieldsRef \? \{ fieldsRef \} : \{\}\)/u, "job params must carry the encrypted reference, not raw values");
  assert.doesNotMatch(orchestrator, /\{ fields \} : \{\}/u, "raw fields must never be written into job params");
  // B31-02: the engine is no longer called on this thread. The pipeline invokes the
  // bounded child, and the engine is reached only from inside the child. Asserting
  // the *absence* here is the point — `withTimeout(..., fillFormPdf(...))` bounded
  // the wait, not the work, because a timer cannot interrupt a synchronous parse.
  assert.doesNotMatch(pipeline, /fillFormPdf\(/u, "the pipeline must not call the engine on the main thread");
  assert.match(pipeline, /fillPdfBounded\(/u, "the pipeline must reach the engine through the bounded child");
  const child = read("src/lib/pdf/form-worker-child.ts");
  assert.match(child, /fillFormPdf\(/u, "the child is where the engine runs");
  assert.match(pipeline, /"fill-forms"/u);
  // The output screening step must run for the filled PDF like any other tool.
  assert.match(pipeline, /screenAndStoreWorkerOutputs/u);
  // No route module imports the engine.
  for (const path of ["src/app/api/jobs/[tool]/route.ts", "src/app/api/fill-forms/inspect/route.ts", "src/app/api/tools/[tool]/route.ts"]) {
    assert.doesNotMatch(read(path), /fillFormPdf\b|document-pipeline|runPdfWorkerTool/u, `${path} must not run the fill engine`);
  }
  // Inspection is the one read-only engine entry point a route may use, and only
  // to describe the form — never to produce a document.
  assert.doesNotMatch(read("src/app/api/fill-forms/inspect/route.ts"), /processPdfBounded[\s\S]{0,400}fillFormPdf/u);
  // The inspect route is read-only: no job, no storage, no queue — and, since
  // FF-04 round 2, it no longer parses the PDF in the web process at all. The
  // route hands the bytes to the bounded child and receives an inventory.
  const inspect = read("src/app/api/fill-forms/inspect/route.ts");
  assert.match(inspect, /processPdfBounded\(/u, "the route must delegate parsing to the bounded boundary");
  assert.doesNotMatch(inspect, /inspectFormPdf\(|PDFDocument\.load/u, "the web process must never parse a PDF itself");
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

// ----------------------------------------------------------------- FF-10 / FF-01

test("FF-10: the 64 KiB fields limit is measured in UTF-8 bytes, not UTF-16 code units", async () => {
  const { assertFieldsPayloadSize, fieldsPayloadBytes, parseFieldsPart } = await import("../src/lib/pdf/form-validation");
  // Review evidence: 35,121 Arabic characters (70,121 UTF-8 bytes) were accepted
  // because the old check compared `.length`, which counts code units.
  const arabic = "م".repeat(35_121);
  assert.equal(arabic.length, 35_121);
  assert.equal(fieldsPayloadBytes(arabic), 70_242, "Arabic is two bytes per code unit in UTF-8");
  assert.throws(() => assertFieldsPayloadSize(arabic), (error: unknown) => error instanceof FormFillError && error.code === "FORM_VALUE_INVALID");
  // The same payload in ASCII is comfortably inside the limit, so the check is
  // about bytes rather than about the string being large.
  assert.doesNotThrow(() => assertFieldsPayloadSize("a".repeat(35_121)));
  // A payload just over the boundary is rejected; just under is accepted.
  assert.doesNotThrow(() => assertFieldsPayloadSize("a".repeat(64 * 1024)));
  assert.throws(() => assertFieldsPayloadSize("a".repeat(64 * 1024 + 1)));
  // Arabic inside an otherwise small document still counts correctly through the
  // same helper the API routes use.
  assert.equal(fieldsPayloadBytes("{\"a\":\"نورة\"}"), Buffer.byteLength("{\"a\":\"نورة\"}", "utf8"));
  void parseFieldsPart;
});

test("FF-10: duplicate JSON keys are rejected before JSON.parse can collapse them", async () => {
  const { assertNoDuplicateJsonKeys, parseFieldsPart } = await import("../src/lib/pdf/form-validation");
  // Review evidence: duplicate keys were last-wins.
  assert.throws(() => assertNoDuplicateJsonKeys('{"a":1,"a":2}'), (error: unknown) => error instanceof FormFillError);
  assert.throws(() => assertNoDuplicateJsonKeys('{"a":{"x":1,"x":2}}'), (error: unknown) => error instanceof FormFillError);
  // Escapes are decoded first, so `"a\u0062"` and `"ab"` are the same key.
  assert.throws(() => assertNoDuplicateJsonKeys('{"a\\u0062":1,"ab":2}'), (error: unknown) => error instanceof FormFillError);
  // A repeated name in *different* objects is legitimate.
  assert.doesNotThrow(() => assertNoDuplicateJsonKeys('{"a":{"x":1},"b":{"x":2}}'));
  assert.doesNotThrow(() => assertNoDuplicateJsonKeys('{"a":["x","y"],"b":"x"}'));
  // Trailing content after the document is not JSON and is refused.
  assert.throws(() => assertNoDuplicateJsonKeys('{"a":1}x'), (error: unknown) => error instanceof FormFillError);
  // And the `fields` part parser applies both the byte bound and the key check.
  assert.throws(() => parseFieldsPart('{"a":1,"a":2}'), (error: unknown) => error instanceof FormFillError && error.code === "FORM_VALUE_INVALID");
  assert.deepEqual(parseFieldsPart('{"a":"x"}'), { a: "x" });
});

test("FF-10: the Web API and the Public API each require exactly one `fields` part", () => {
  const webRoute = read("src/app/api/jobs/[tool]/route.ts");
  const publicApi = read("src/lib/public-api/jobs.ts");
  for (const [name, source] of [["web route", webRoute], ["public API", publicApi]] as const) {
    // `form.get()` returns the first of several parts without saying so, so the
    // count must be asserted rather than assumed.
    assert.match(source, /form\.getAll\("fields"\)\.length !== 1/u, `${name} must reject repeated parts`);
    assert.match(source, /assertNoDuplicateJsonKeys/u, `${name} must reject duplicate keys`);
    // And both must measure bytes, not code units.
    assert.match(source, /fieldsPayloadBytes|assertFieldsPayloadSize/u, `${name} must bound the payload in UTF-8 bytes`);
    assert.doesNotMatch(source, /rawFields\.length > 64 \* 1024/u, `${name} must not measure the payload in code units`);
  }
});

test("FF-01: the inspect route's import graph contains no renderer and no module-scope font resolution", () => {
  // The build failure was `dirname(require.resolve(...))` receiving Turbopack's
  // numeric module id while the app route was evaluated. The route therefore
  // must not reach the appearance module at all, directly or transitively.
  const inspection = read("src/lib/pdf/form-inspection.ts");
  // Only `import`/`require` statements matter: the module's doc comment explains
  // which dependencies it deliberately avoids, and that prose must not trip the
  // check.
  const imports = inspection.split("\n").filter((line) => /^\s*(import|export .* from|const .* = require\()/u.test(line)).join("\n");
  assert.doesNotMatch(imports, /form-appearance/u, "inspection must not import the renderer");
  assert.doesNotMatch(imports, /napi-rs/u, "inspection must not import the rasteriser");
  assert.doesNotMatch(imports, /fontsource/u, "inspection must not import font assets");
  assert.doesNotMatch(imports, /node:module|createRequire/u, "inspection must not resolve modules at run time");

  const route = read("src/app/api/fill-forms/inspect/route.ts");
  assert.match(route, /from "@\/lib\/pdf\/form-inspection"/u, "the route must import the renderer-free module");
  assert.doesNotMatch(route, /@\/lib\/pdf\/form-fill"/u, "the route must not import the fill engine");
  assert.doesNotMatch(route, /@\/lib\/pdf\/form-appearance/u);

  // And the renderer itself must not resolve fonts while the module is evaluated.
  const appearance = read("src/lib/pdf/form-appearance.ts");
  // Module scope is *top-level* code: a `require()` inside a function body is
  // lazy and fine, however early in the file that function is declared. Track
  // brace depth over code only (comments stripped) and keep depth-0 lines.
  let depth = 0;
  const topLevel: string[] = [];
  let inBlockComment = false;
  for (const line of appearance.split("\n")) {
    const trimmed = line.trim();
    if (inBlockComment) { if (trimmed.includes("*/")) inBlockComment = false; continue; }
    if (trimmed.startsWith("/*")) { if (!trimmed.includes("*/")) inBlockComment = true; continue; }
    if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
    if (depth === 0) topLevel.push(line);
    for (const character of line) {
      if (character === "{") depth += 1;
      else if (character === "}") depth = Math.max(0, depth - 1);
    }
  }
  const moduleCode = topLevel.join("\n");
  // `createRequire(import.meta.url)` itself touches no filesystem and is fine at
  // module scope. What must not happen there is *resolution*: `require.resolve`,
  // `require(...)` or `dirname(...)` against a bundled specifier.
  assert.doesNotMatch(moduleCode, /require\.resolve\(|\brequire\(\s*[A-Za-z"'\[]|dirname\(/u, "font resolution must not run at module scope");
  assert.match(appearance, /function fontDirectory\(\)/u, "font resolution must live behind a lazy accessor");
  assert.match(appearance, /if \(fontSource === undefined\)/u, "resolution must be memoised on first use");
  // The guard against a non-path id is what turns a build failure into a coded
  // render-time error if a bundler ever rewrites the specifier again.
  assert.ok(appearance.includes("package\\.json$/u"), "a non-path resolve result must be rejected explicitly");
});

test("FF-04: the inspect route bounds the request before buffering and screens before parsing", () => {
  const route = read("src/app/api/fill-forms/inspect/route.ts");
  // Measure inside `POST` only: the prose above it legitimately mentions
  // `request.formData()` while explaining why it used to be wrong.
  const body = route.slice(route.indexOf("export async function POST"));
  // The size guard is a helper defined above `POST`; what matters is that it is
  // *called* inside `POST` before `formData()` buffers the body.
  // Round 2: the header check survives as an early exit, but enforcement moved to a
  // counting stream. Both must precede the buffering call.
  const declaredAt = body.indexOf("declaredLength(request)");
  const boundedAt = body.indexOf("boundedMultipartRequest(request");
  const formDataAt = Math.max(body.indexOf("bounded.formData()"), body.indexOf("request.formData()"));
  const screeningAt = body.indexOf("requireCleanUpload(bytes)");
  const parseAt = body.indexOf("processPdfBounded(");
  const cheapAt = body.indexOf("assertCheapPdfShape(bytes)");
  assert.ok(declaredAt > 0 && declaredAt < formDataAt, "the declared length must be checked before formData()");
  assert.ok(boundedAt > 0 && boundedAt < formDataAt, "the body must be bounded before formData() consumes it");
  // The derived request must be the one formData() is called on: bounding a request
  // and then parsing the original is the regression that broke every endpoint.
  assert.match(body, /const bounded = boundedMultipartRequest\(request/u);
  assert.match(body, /await bounded\.formData\(\)/u);
  assert.doesNotMatch(body, /Object\.defineProperty\(request, "body"/u, "substituting .body in place leaves formData() unusable");
  assert.ok(cheapAt > 0 && cheapAt < screeningAt, "cheap shape checks must precede screening");
  assert.ok(screeningAt > 0 && screeningAt < parseAt, "malware screening must precede the PDF parse");
  // Round 2: admission is an atomic Lua lease with per-tenant AND global ceilings,
  // and it must still happen before the body is read.
  const admissionAt = body.indexOf("acquireInspectionLease(user.id)");
  assert.ok(admissionAt > 0 && admissionAt < formDataAt, "admission must run before the body is read");
  const admission = read("src/lib/http/inspection-lease.ts");
  assert.match(admission, /redis\.eval\(/u, "admission must be one atomic script, not INCR+EXPIRE");
  assert.match(admission, /global/u, "a global ceiling must exist alongside the per-tenant one");
});

test("FF-03: no raw field value reaches `Job.params`, and every terminal path purges the reference", () => {
  const orchestrator = read("src/lib/jobs/orchestrator.ts");
  const pipeline = read("src/lib/jobs/document-pipeline.ts");
  const publicApi = read("src/lib/public-api/jobs.ts");
  const payload = read("src/lib/pdf/form-payload.ts");

  // Creation persists only the reference.
  assert.match(orchestrator, /putFormFields\(\{ tenantId: input\.userId, jobId, fields \}\)/u);
  assert.match(orchestrator, /fieldsRef \? \{ fieldsRef \} : \{\}/u);
  // Enqueue/transaction failure purges it.
  assert.match(orchestrator, /purgeFormFields\(fieldsRef\)/u);

  // The worker reads by reference and never trusts plaintext as the first source.
  assert.match(pipeline, /readFormFields\(\{ reference: rawParams\.fieldsRef/u);

  // Every terminal transition the pipeline owns purges it.
  assert.match(pipeline, /purgeFormFields\(rawParams\.fieldsRef\)\.catch\(\(\) => logger\.warn\("fill_forms\.payload_purge_failed", \{ \.\.\.context, reason: "SUCCESS" \}\)/u);
  assert.match(pipeline, /reason: "FINAL_FAILURE"/u);
  assert.ok(pipeline.indexOf('job.status === "CANCELLED" || job.status === "EXPIRED"') >= 0);
  // …and so does API cancellation.
  assert.match(publicApi, /purgeFormFields\(cancelled\.fieldsRef\)/u);

  // The read must be non-destructive: a retry has to find the payload again.
  assert.doesNotMatch(payload, /getdel/u, "the payload read must not be destructive");
  assert.match(payload, /async get\(key\) \{ return \(await getReadyQueueConnection\(\)\)\.get\(key\); \}/u);
  // Tenant and job are bound into the AAD, not just into the key name.
  assert.match(payload, /const aad = \(tenantId: string, jobId: string\) => Buffer\.from\(`v1\\0\$\{tenantId\}\\0\$\{jobId\}\\0\$\{PURPOSE\}`\)/u);
});

test("FF-06: `fill-forms` is inspected after screening and before billing/storage/enqueue", () => {
  const orchestrator = read("src/lib/jobs/orchestrator.ts");
  const screeningAt = orchestrator.indexOf("await requireCleanUpload(upload.bytes)");
  // B31-01 moved the preflight *earlier* — ahead of `validateUpload`, so the API does
  // not parse the document in-process before reaching this boundary. Locate the call
  // site by name rather than by one exact argument expression, so the invariant
  // (screened, and before any durable effect) is what is asserted and a further move
  // within those bounds does not produce a false red.
  // The definition and the call both match `/assertFillableInput\(/`; the call is the
  // one that is preceded by `await`.
  const callPattern = /await assertFillableInput\(/u;
  const preflightAt = callPattern.test(orchestrator) ? orchestrator.search(callPattern) : -1;
  const billingAt = orchestrator.indexOf("await enforceJobCreation(");
  const storageAt = orchestrator.indexOf("await storage.put(");
  const enqueueAt = orchestrator.indexOf("await enqueueJob(queuedJob, queueOptions)");
  assert.ok(preflightAt > 0, "the preflight must exist");
  assert.ok(screeningAt > 0 && preflightAt > screeningAt, "the preflight must follow malware screening");
  assert.ok(preflightAt < billingAt, "the preflight must precede any billing attempt");
  assert.ok(preflightAt < storageAt, "the preflight must precede object storage");
  assert.ok(preflightAt < enqueueAt, "the preflight must precede queueing");
});

test("FF-06: the authorization charge is released only when no job committed", () => {
  const enforcement = read("src/lib/usage/enforcement.ts");
  const orchestrator = read("src/lib/jobs/orchestrator.ts");
  // Authorization still happens where it always did — before storage — but it now
  // hands back a release handle.
  assert.match(enforcement, /charge: creditReused \? undefined : \{ release:/u, "authorization must return a release handle");
  assert.match(enforcement, /reverseCredits\(/u, "the release must reverse the ledger entry");
  assert.match(enforcement, /job-release:\$\{input\.toolId\}:\$\{input\.idempotencyKey\}/u, "the reversal must be idempotent per idempotency key");
  // Round 3: the release is conditional. An unconditional `Promise.all` of every
  // cleanup released the charge after the job row had already committed — giving
  // away work that may be queued and running, and deleting inputs a QUEUED job
  // still references.
  assert.match(orchestrator, /let committedJobId: string \| undefined/u, "the commit point must be tracked");
  const postCommit = orchestrator.slice(orchestrator.indexOf("if (committedJobId) {"));
  assert.equal(
    postCommit.slice(0, postCommit.indexOf("throw error")).includes("charge?.release()"),
    false,
    "a post-commit failure must not release the charge",
  );
  const preCommit = orchestrator.slice(orchestrator.indexOf("No job row: release the charge"));
  assert.match(preCommit.slice(0, 400), /charge\?\.release\(\)/u, "a pre-commit failure must release it");
  // The ordering the earlier test pins must not have moved.
  const preflightAt = orchestrator.indexOf("processPdfBounded(bytes");
  const billingAt = orchestrator.indexOf("await enforceJobCreation(");
  assert.ok(preflightAt > 0 && preflightAt < billingAt, "preflight must still precede billing");
});
