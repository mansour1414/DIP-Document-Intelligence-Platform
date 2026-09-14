import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { mapPublicError, publicErrorResponse, PublicApiError } from "../src/lib/public-api/errors";
import { parsePublicJobRequest } from "../src/lib/public-api/jobs";
import { rateLimitDecision } from "../src/lib/public-api/request";
import { publicToolDto } from "../src/lib/public-api/tools";
import { getToolDefinition } from "../src/lib/tools/registry";
import { IdempotencyConflictError } from "../src/lib/api-platform/idempotency";

test("public job multipart validation requires tool, files, and idempotency", async () => {
  await assert.rejects(() => parsePublicJobRequest(new Request("https://example.test/v1/jobs", { method: "POST", body: "{}", headers: { "content-type": "application/json" } })), /multipart/);
  const form = new FormData(); form.set("toolId", "compress-pdf"); form.append("files", new File(["%PDF-"], "a.pdf", { type: "application/pdf" }));
  await assert.rejects(() => parsePublicJobRequest(new Request("https://example.test/v1/jobs", { method: "POST", body: form })), /Idempotency-Key/);
  const parsed = await parsePublicJobRequest(new Request("https://example.test/v1/jobs", { method: "POST", body: form, headers: { "idempotency-key": "retry-1" } })); assert.equal(parsed.toolId, "compress-pdf"); assert.equal(parsed.uploads.length, 1); assert.equal(parsed.bytesIn, 5); assert.match(parsed.requestHash, /^[a-f0-9]{64}$/);
});

test("public error envelope maps conflicts and hides internal details", async () => {
  assert.equal(mapPublicError(new IdempotencyConflictError()).code, "CONFLICT"); const response = publicErrorResponse(new Error("password=secret database exploded"), "00000000-0000-4000-8000-000000000001"); assert.equal(response.status, 500); const body = await response.json() as { error: { code: string; message: string; requestId: string } }; assert.deepEqual(body, { error: { code: "INTERNAL_ERROR", message: "The request could not be completed.", requestId: "00000000-0000-4000-8000-000000000001" } });
});

test("rate-limit denial is stable and includes safe retry timing", () => { assert.doesNotThrow(() => rateLimitDecision({ allowed: true, retryAfterMs: 0 })); assert.throws(() => rateLimitDecision({ allowed: false, retryAfterMs: 1500 }), (error: unknown) => error instanceof PublicApiError && error.code === "RATE_LIMITED" && error.details?.retryAfterSeconds === 2); });
test("tool discovery DTO comes only from the canonical registry", () => { const tool = getToolDefinition("compress-pdf"); assert.deepEqual(publicToolDto(tool).inputSchema, tool.inputSchema); assert.equal(publicToolDto(tool).version, tool.version); assert.equal(tool.apiEligible, true); });

test("public routes preserve the auth-policy-registry-orchestrator boundary", async () => {
  const root = new URL("../", import.meta.url); const routes = await Promise.all(["src/app/v1/tools/route.ts", "src/app/v1/jobs/route.ts", "src/app/v1/jobs/[jobId]/route.ts", "src/app/v1/jobs/[jobId]/cancel/route.ts", "src/app/v1/jobs/[jobId]/result/route.ts"].map((path) => readFile(new URL(path, root), "utf8"))); const jobService = await readFile(new URL("src/lib/public-api/jobs.ts", root), "utf8");
  assert.ok(routes.every((source) => /handlePublicApi/.test(source))); assert.match(jobService, /createToolJob/); assert.match(jobService, /getPublicTool/); assert.doesNotMatch(routes.join("\n"), /worker|enqueue|processServerDocument|runPdfWorkerTool/); assert.doesNotMatch(jobService, /documentWorker|aiWorker|processServerDocument|runPdfWorkerTool/);
});
