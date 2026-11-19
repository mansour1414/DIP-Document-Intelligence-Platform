import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const root = new URL("../", import.meta.url).pathname;
const read = (rel: string) => readFileSync(join(root, rel), "utf8");

const serverTools = ["word-to-pdf", "pdf-to-word", "excel-to-pdf", "powerpoint-to-pdf", "ocr-pdf"] as const;

test("PR-0: legacy /api/tools/[tool] route is fail-closed and never executes processing", async () => {
  const source = read("src/app/api/tools/[tool]/route.ts");
  assert.doesNotMatch(source, /processServerDocument/);
  assert.doesNotMatch(source, /beginJob|finishJob/);
  assert.doesNotMatch(source, /requireUser/);
  assert.doesNotMatch(source, /DocumentProcessingError/);
  assert.match(source, /SYNC_PROCESSING_DISABLED/);
  assert.match(source, /\/api\/jobs\/\$\{tool\}/);

  const { POST } = await import("../src/app/api/tools/[tool]/route");
  for (const tool of serverTools) {
    const response = await POST(new Request("http://localhost/api/tools/" + tool, { method: "POST" }), { params: Promise.resolve({ tool }) });
    assert.equal(response.status, 409, tool);
    const body = await response.json() as { code?: string; message?: string };
    assert.equal(body.code, "SYNC_PROCESSING_DISABLED", tool);
    assert.match(body.message ?? "", new RegExp("/api/jobs/" + tool.replace(/-/g, "\\-")));
  }
  const unknown = await POST(new Request("http://localhost/api/tools/merge-pdf", { method: "POST" }), { params: Promise.resolve({ tool: "merge-pdf" }) });
  assert.equal(unknown.status, 404);
  assert.equal((await unknown.json() as { code?: string }).code, "NOT_FOUND");
});

test("PR-0: no HTTP route invokes Office/OCR processing directly", () => {
  const apiDir = join(root, "src/app/api");
  const routeFiles: string[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) walk(full);
      else if (entry === "route.ts") routeFiles.push(full);
    }
  };
  walk(apiDir);
  assert.ok(routeFiles.length > 0);
  for (const file of routeFiles) {
    const source = readFileSync(file, "utf8");
    assert.doesNotMatch(source, /processServerDocument/, file);
    assert.doesNotMatch(source, /runPdfWorkerTool/, file);
  }
  // The only production callers of processServerDocument are the worker and the lib itself.
  const worker = read("workers/document-worker.ts");
  assert.match(worker, /processServerDocument/);
});

test("PR-0: ServerToolWorkspace uses the async job pipeline with existing contracts", () => {
  const source = read("src/components/tools/server-tool-workspace.tsx");
  assert.doesNotMatch(source, /\/api\/tools\//);
  assert.match(source, /\/api\/jobs\/\$\{tool\.id\}/);
  assert.match(source, /\/api\/jobs\/status\/\$\{jobId\}/);
  assert.match(source, /\/api\/files\/\$\{outputFileIds\[0\]\}/);
  assert.match(source, /form\.append\("files", file\)/);
  assert.match(source, /form\.set\("options", JSON\.stringify\(isOcr \? \{ language \} : \{\}\)\)/);
  assert.match(source, /"Idempotency-Key": crypto\.randomUUID\(\)/);
  assert.match(source, /"X-Correlation-Id": crypto\.randomUUID\(\)/);
  assert.doesNotMatch(source, /form\.set\("file"/);
  assert.doesNotMatch(source, /form\.set\("language"/);
});

test("PR-0: polling is bounded and OCR-aware (not a fixed 120s timeout)", () => {
  const source = read("src/components/tools/server-tool-workspace.tsx");
  assert.match(source, /const maxAttempts = isOcr \? 390 : 210/);
  assert.match(source, /setTimeout\(resolve, 1000\)/);
  assert.match(source, /OCR timeout is 300s/);
  assert.match(source, /never unbounded/);
  // Terminal states and missing-output handling are explicit.
  assert.match(source, /\["failed", "cancelled", "expired"\]/);
  assert.match(source, /OUTPUT_MISSING/);
  assert.match(source, /OUTPUT_DOWNLOAD_FAILED/);
});

test("PR-0: five tools, MIME accepts, and OCR language options are preserved", () => {
  const source = read("src/components/tools/server-tool-workspace.tsx");
  for (const tool of serverTools) assert.match(source, new RegExp(tool.replace(/-/g, "\\-")));
  assert.match(source, /application\/msword/);
  assert.match(source, /application\/vnd\.ms-excel/);
  assert.match(source, /application\/vnd\.ms-powerpoint/);
  assert.match(source, /image\/jpeg,image\/png/);
  assert.match(source, /\["ara\+eng",/);
  assert.match(source, /\["ara",/);
  assert.match(source, /\["eng",/);
  // Registry still exposes all five as worker tools with OCR language contract.
  const registry = read("src/lib/tools/registry.ts");
  for (const tool of serverTools) assert.match(registry, new RegExp('"' + tool + '"'));
  const options = read("src/lib/tools/options.ts");
  assert.match(options, /"ocr-pdf": \{ version: "1", properties: \{ language:/);
});

test("PR-0: job ingress boundary order is validateUpload -> requireCleanUpload -> storage.put -> enqueue", () => {
  const orchestrator = read("src/lib/jobs/orchestrator.ts");
  const validateIdx = orchestrator.indexOf("validateUpload(");
  const scanIdx = orchestrator.indexOf("requireCleanUpload(");
  const storeIdx = orchestrator.indexOf("storage.put(");
  const enqueueIdx = orchestrator.indexOf("enqueueJob(");
  assert.ok(validateIdx >= 0 && scanIdx > validateIdx && storeIdx > scanIdx && enqueueIdx > storeIdx);
  const jobsRoute = read("src/app/api/jobs/[tool]/route.ts");
  assert.match(jobsRoute, /createToolJob/);
  assert.match(jobsRoute, /workerToolIds\.has\(tool\)/);
});

test("PR-0: retention copy no longer claims outputs are not retained", () => {
  const source = read("src/components/tools/server-tool-workspace.tsx");
  assert.doesNotMatch(source, /not retained by DIP/);
  assert.doesNotMatch(source, /لا يحتفظ DIP به/);
  assert.doesNotMatch(source, /removed after the result is created/);
  assert.doesNotMatch(source, /يُحذف مباشرةً بعد إنشاء النتيجة/);
  assert.match(source, /stored in private object storage under the retention policy/);
  assert.match(source, /يُخزَّن في تخزين كائني خاص وفق سياسة الاحتفاظ/);
  assert.match(source, /stored under the retention policy and can be downloaded now/);
  assert.match(source, /يُخزَّن وفق سياسة الاحتفاظ ويمكن تنزيله الآن/);
});
