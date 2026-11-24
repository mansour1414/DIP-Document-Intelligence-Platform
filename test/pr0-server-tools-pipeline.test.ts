/**
 * PR-0 source-contract tests.
 *
 * These are structural assertions over files, not executed behaviour. The
 * behavioural evidence for the same contracts lives in
 * pr0-server-tools.behavior.test.ts (fake fetch/clock over the real client
 * module and the real route handler).
 */
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const root = new URL("../", import.meta.url).pathname;
const read = (rel: string) => readFileSync(join(root, rel), "utf8");

const serverTools = ["word-to-pdf", "pdf-to-word", "excel-to-pdf", "powerpoint-to-pdf", "ocr-pdf"] as const;
const workspace = "src/components/tools/server-tool-workspace.tsx";
const clientModule = "src/lib/client/server-tool-job.ts";

test("PR-0 (structure): the legacy route contains no processing, auth, job or storage path", () => {
  const source = read("src/app/api/tools/[tool]/route.ts");
  for (const forbidden of [/processServerDocument/, /beginJob|finishJob/, /requireUser/, /DocumentProcessingError/, /getStorage/, /@\/lib\/db/, /@\/lib\/queue/]) {
    assert.doesNotMatch(source, forbidden);
  }
  assert.match(source, /SYNC_PROCESSING_DISABLED/);
  assert.match(source, /\/api\/jobs\/\$\{tool\}/);
  // The fail-closed contract is documented next to the worker boundary.
  const readme = read("workers/README.md");
  assert.match(readme, /SYNC_PROCESSING_DISABLED/);
  assert.match(readme, /409/);
});

test("PR-0 (structure): no HTTP route invokes Office/OCR processing directly", () => {
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
    // PR-1 moved the job body into the pipeline module; routes must not reach it either.
    assert.doesNotMatch(source, /jobs\/document-pipeline/, file);
  }
  // The document worker remains the only production caller of the engines: the
  // worker runs the pipeline module, and the pipeline is the only module that
  // invokes the Office/OCR engines.
  assert.match(read("workers/document-worker.ts"), /processDocumentJob/);
  assert.match(read("src/lib/jobs/document-pipeline.ts"), /processServerDocument/);
});

test("PR-0 (structure): the UI transports jobs only through the client pipeline module", () => {
  const source = read(workspace);
  assert.doesNotMatch(source, /\/api\/tools\//);
  assert.doesNotMatch(source, /new FormData\(/);
  assert.doesNotMatch(source, /fetch\(/);
  assert.match(source, /submitServerToolJob/);
  assert.match(source, /pollJobOutput/);
  assert.match(source, /downloadServerToolOutput/);
  const clientSource = read(clientModule);
  assert.match(clientSource, /`\/api\/jobs\/\$\{input\.toolId\}`/);
  assert.match(clientSource, /`\/api\/jobs\/status\/\$\{input\.jobId\}`/);
  assert.match(clientSource, /`\/api\/files\/\$\{input\.fileId\}`/);
  assert.match(clientSource, /form\.append\("files", input\.file/);
  assert.match(clientSource, /form\.set\("options", JSON\.stringify/);
  assert.match(clientSource, /"Idempotency-Key": input\.idempotencyKey/);
  assert.match(clientSource, /"X-Correlation-Id": correlationId/);
});

test("PR-0 (structure): polling budgets are bounded, clamped and server-derived", () => {
  const clientSource = read(clientModule);
  assert.match(clientSource, /JOB_POLL_MIN_BUDGET_MS = 30_000/);
  assert.match(clientSource, /JOB_POLL_MAX_BUDGET_MS = 30 \* 60_000/);
  assert.match(clientSource, /export function resolvePollBudgetMs/);
  assert.match(clientSource, /STILL_PROCESSING/);
  const statusRoute = read("src/app/api/jobs/status/[jobId]/route.ts");
  assert.match(statusRoute, /findJobForUser/);
  assert.match(statusRoute, /pollBudgetMs: jobPollBudgetMs\(job\.toolId\)/);
  assert.match(read("src/lib/runtime/config.ts"), /export function jobPollBudgetMs/);
});

test("PR-0 (structure): job and output reads are tenant-scoped through one RLS-aware helper", () => {
  const access = read("src/lib/jobs/access.ts");
  assert.match(access, /requesterId: userId/);
  assert.match(access, /document: \{ userId \}/);
  // Reads run inside the tenant transaction, so RLS applies as well as the predicate.
  assert.match(access, /withTenant\(\{ userId \}/);
  assert.doesNotMatch(access, /db\.job\.findFirst/);
  assert.doesNotMatch(access, /db\.file\.findFirst/);
  assert.match(read("src/app/api/jobs/status/[jobId]/route.ts"), /findJobForUser/);
  assert.match(read("src/app/api/files/[fileId]/route.ts"), /findOutputFileForUser/);
});

test("PR-0 (structure): a retained idempotency key is bound to the submitted request", () => {
  const clientSource = read(clientModule);
  assert.match(clientSource, /export function submissionFingerprint/);
  assert.match(clientSource, /export function idempotencyFor/);
  assert.match(clientSource, /pending\.fingerprint === fingerprint/);
  const source = read(workspace);
  assert.match(source, /idempotencyFor\(pendingSubmissionRef\.current, request\)/);
  assert.doesNotMatch(source, /idempotencyKeyRef/);
  // Identity is scoped to a per-selection token; the module never hashes bytes.
  assert.match(source, /selectionTokenRef\.current = globalThis\.crypto\.randomUUID\(\)/);
  assert.match(source, /selectionToken: selectionTokenRef\.current/);
  assert.match(clientSource, /selection: request\.selectionToken/);
  assert.doesNotMatch(clientSource, /subtle\.digest|crypto\.createHash|sha256\(.*bytes/i);
});

test("PR-0 (structure): output downloads retry transient faults only, through one classifier", () => {
  const clientSource = read(clientModule);
  assert.match(clientSource, /export function isRetryableDownloadError/);
  assert.match(clientSource, /if \(signal\?\.aborted\) return false;/);
  assert.match(clientSource, /error\.code === "OUTPUT_DOWNLOAD_FAILED"/);
  assert.match(clientSource, /error\.name === "AbortError"/);
  assert.match(clientSource, /return true;/);
  assert.match(clientSource, /if \(!isRetryableDownloadError\(error, input\.signal\) \|\| attempt === attempts - 1\) throw error;/);
  // The workspace uses the bounded retry helper, never a bare download.
  const source = read(workspace);
  assert.match(source, /downloadServerToolOutputWithRetry/);
  assert.doesNotMatch(source, /downloadServerToolOutput\(/);
});

test("PR-0 (structure): the workspace guards the processing lifecycle", () => {
  const source = read(workspace);
  // Remove cannot be mistaken for cancelling background work.
  assert.match(source, /if \(busy\) return;/);
  assert.match(source, /disabled=\{busy\}/);
  assert.match(source, /removeBusy/);
  // Stale responses cannot restore a cleared output.
  assert.match(source, /createRunGuard/);
  assert.match(source, /isCurrent\(run\)/);
  assert.match(source, /guardRef\.current\?\.cancel\(\)/);
  // Object URLs are always revoked.
  assert.match(source, /URL\.revokeObjectURL/);
  assert.match(source, /useEffect\(\(\) => \(\) => \{ guardRef\.current\?\.cancel\(\); releaseOutputUrl\(\); \}, \[\]\)/);
  // "Still processing" is resumable without a duplicate job.
  assert.match(source, /checkAgain/);
  assert.match(source, /pendingJobId/);
  assert.match(source, /STILL_PROCESSING/);
  // A finished job whose download failed keeps its output reference and can
  // only be re-downloaded, never re-submitted.
  assert.match(source, /completedOutputFileId/);
  assert.match(source, /retryDownload/);
  assert.match(source, /downloadServerToolOutputWithRetry/);
  assert.match(source, /status !== "output-retry"/);
});

test("PR-0 (structure): five tools, MIME accepts, and OCR language options are preserved", () => {
  const source = read(workspace);
  for (const tool of serverTools) assert.match(source, new RegExp(tool.replace(/-/g, "\\-")));
  assert.match(source, /application\/msword/);
  assert.match(source, /application\/vnd\.ms-excel/);
  assert.match(source, /application\/vnd\.ms-powerpoint/);
  assert.match(source, /image\/jpeg,image\/png/);
  assert.match(source, /\["ara\+eng",/);
  assert.match(source, /\["ara",/);
  assert.match(source, /\["eng",/);
  const registry = read("src/lib/tools/registry.ts");
  for (const tool of serverTools) assert.match(registry, new RegExp('"' + tool + '"'));
  assert.match(read("src/lib/tools/options.ts"), /"ocr-pdf": \{ version: "1", properties: \{ language:/);
  // The registry still declares exactly the 34 catalog tools.
  assert.match(read("test/merge-pdf.runtime.test.ts"), /Object\.keys\(toolRegistry\)\.length, toolsConfig\.length/);
});

test("PR-0 (structure): job ingress order is shape check -> requireCleanUpload -> parse stage -> storage.put -> enqueue", () => {
  const orchestrator = read("src/lib/jobs/orchestrator.ts");
  // Round 6 split validation in two. The parser-free stage (bytes/MIME/magic/size)
  // is the first thing that runs; the page-counting stage must still come after the
  // malware gate, so an infected document is never parsed. Both orderings are
  // asserted, because collapsing them back together would silently reintroduce the
  // parse-before-screen defect.
  const shapeIdx = orchestrator.indexOf("assertCheapPdfShape(");
  const bytesIdx = orchestrator.indexOf("validateUploadBytes(");
  const scanIdx = orchestrator.indexOf("requireCleanUpload(");
  const parseIdx = orchestrator.indexOf("validateUploadWithParse(");
  const storeIdx = orchestrator.indexOf("storage.put(");
  const enqueueIdx = orchestrator.indexOf("enqueueJob(");
  assert.ok(shapeIdx >= 0 && scanIdx > shapeIdx, "cheap shape checks must precede screening");
  assert.ok(bytesIdx >= 0 && bytesIdx < scanIdx, "the parser-free stage must precede screening");
  assert.ok(parseIdx > scanIdx, "the page-counting parse must not precede screening");
  assert.ok(storeIdx > parseIdx && enqueueIdx > storeIdx);
  const jobsRoute = read("src/app/api/jobs/[tool]/route.ts");
  assert.match(jobsRoute, /createToolJob/);
  assert.match(jobsRoute, /workerToolIds\.has\(tool\)/);
});

test("PR-0 (structure): the malware gate resolves persistence lazily and still fails closed", () => {
  const source = read("src/lib/malware/index.ts");
  assert.doesNotMatch(source, /^import \{ db \} from "@\/lib\/db";$/m);
  assert.match(source, /const \{ db \} = await import\("@\/lib\/db"\)/);
  const rejectionIdx = source.indexOf("if (scan.result !== \"CLEAN\")");
  assert.ok(rejectionIdx > 0 && source.indexOf("throw new MalwareScanError(scan.result)", rejectionIdx) > rejectionIdx);
});

test("PR-0 (structure): retention copy describes the verified lifecycle without a period", () => {
  const source = read(workspace);
  for (const wrong of [/not retained by DIP/, /لا يحتفظ DIP به/, /removed after the result is created/, /يُحذف مباشرةً بعد إنشاء النتيجة/, /\b7 days\b/, /30 days/, /7 أيام/, /30 يوماً/]) {
    assert.doesNotMatch(source, wrong);
  }
  assert.match(source, /stored in private object storage under the retention policy/);
  assert.match(source, /يُخزَّن في تخزين كائني خاص وفق سياسة الاحتفاظ/);
  assert.match(source, /stored under the retention policy and can be downloaded now/);
  assert.match(source, /يُخزَّن وفق سياسة الاحتفاظ ويمكن تنزيله الآن/);
});
