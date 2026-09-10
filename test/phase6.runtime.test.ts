import test from "node:test";
import assert from "node:assert/strict";
import { PDFDocument } from "pdf-lib";
import { validateWorkerOutputs } from "../src/lib/outputs/validation";
import { withTimeout } from "../src/lib/runtime/timeout";
import { redactLogContext } from "../src/lib/logging";
import { selectExpiredCandidates, selectOrphans } from "../src/lib/retention/policy";
import { runtimeLimits } from "../src/lib/runtime/config";
import { recordMetric, setMetricSink, type MetricPoint } from "../src/lib/observability/metrics";
import { scrubSentryEvent } from "../src/lib/observability/sentry-scrub";
import { estimateJobCost } from "../src/lib/cost/model";
import { retentionPolicy, RETENTION_POLICY_VERSION } from "../src/lib/retention/config";

async function pdfFixture(pages = 1) { const pdf = await PDFDocument.create(); for (let index = 0; index < pages; index += 1) pdf.addPage().drawText(`generated page ${index + 1}`); return pdf.save(); }

test("timeout rejects with a classified terminal failure", async () => {
  await assert.rejects(() => withTimeout("fixture", 5, new Promise((resolve) => setTimeout(resolve, 50))), { code: "PROCESSING_TIMEOUT" });
});

test("output validation rejects corrupt PDF and JPEG outputs", async () => {
  await assert.rejects(() => validateWorkerOutputs([{ name: "bad.pdf", mimeType: "application/pdf", bytes: new Uint8Array([1, 2, 3]) }]), { code: "OUTPUT_VALIDATION_FAILED" });
  await assert.rejects(() => validateWorkerOutputs([{ name: "bad.jpg", mimeType: "image/jpeg", bytes: new Uint8Array([1, 2, 3]) }]), { code: "OUTPUT_VALIDATION_FAILED" });
});

test("golden generated PDF is parseable and page preservation is enforced", async () => {
  const bytes = await pdfFixture(2);
  assert.deepEqual(await validateWorkerOutputs([{ name: "golden.pdf", mimeType: "application/pdf", bytes }], 2), { outputCount: 1, totalBytes: bytes.byteLength });
  await assert.rejects(() => validateWorkerOutputs([{ name: "golden.pdf", mimeType: "application/pdf", bytes }], 1), { code: "OUTPUT_VALIDATION_FAILED" });
});

test("max output count is enforced before registration", async () => {
  const output = { name: "x.jpg", mimeType: "image/jpeg", bytes: new Uint8Array([0xff, 0xd8, 0xff, 0xd9]) };
  await assert.rejects(() => validateWorkerOutputs(Array.from({ length: runtimeLimits.maxOutputFiles + 1 }, () => output)), { code: "OUTPUT_VALIDATION_FAILED" });
});

test("retention preserves active data and orphan selection is idempotent", () => {
  const now = new Date("2026-09-10T00:00:00Z"); const old = new Date("2026-08-01T00:00:00Z");
  const expired = selectExpiredCandidates([{ id: "active", createdAt: old, hasActiveJob: true, alreadyDeleted: false }, { id: "expired", createdAt: old, hasActiveJob: false, alreadyDeleted: false }, { id: "done", createdAt: old, hasActiveJob: false, alreadyDeleted: true }], now, 7);
  assert.deepEqual(expired.map((item) => item.id), ["expired"]);
  assert.equal(selectOrphans([{ fileReferenceCount: 0, alreadyDeleted: false }, { fileReferenceCount: 0, alreadyDeleted: true }, { fileReferenceCount: 1, alreadyDeleted: false }]).length, 1);
});

test("structured logs redact sensitive fields", () => {
  assert.deepEqual(redactLogContext({ prompt: "secret document", api_key: "key", job_id: "safe", input_tokens: 4 }), { prompt: "[REDACTED]", api_key: "[REDACTED]", job_id: "safe", input_tokens: 4 });
});

test("metrics foundation emits exact names without high-cardinality user labels", () => {
  const points: MetricPoint[] = []; setMetricSink((point) => points.push(point));
  recordMetric("jobs_success_total", 1, "count", { tool_id: "merge-pdf", engine: "pdf-lib", engine_version: "1", status: "succeeded", user_id: "must-not-leak" }); setMetricSink();
  assert.equal(points[0].name, "jobs_success_total"); assert.equal(points[0].labels.user_id, undefined); assert.equal(points[0].labels.tool_id, "merge-pdf");
});

test("Sentry scrub removes request bodies and sensitive nested fields", () => {
  const fixture = { request: { data: "document", cookies: { session: "secret" }, headers: { authorization: "bearer", accept: "json" } }, extra: { prompt: "private", correlation_id: "safe" } } as unknown as Parameters<typeof scrubSentryEvent>[0];
  const event = scrubSentryEvent(fixture);
  assert.equal(event.request?.data, undefined); assert.equal(event.request?.cookies, undefined); assert.equal(event.request?.headers?.authorization, "[REDACTED]"); assert.equal(event.extra?.prompt, "[REDACTED]"); assert.equal(event.extra?.correlation_id, "safe");
});

test("retention and cost models are versioned and deterministic", () => {
  assert.match(RETENTION_POLICY_VERSION, /^2026-09-provisional-v\d+$/); assert.equal(retentionPolicy.plans.FREE.inputDays, 7); assert.equal(retentionPolicy.plans.PRO.outputDays, 30);
  const cost = estimateJobCost({ cpuDurationMs: 10, memoryClassMb: 256, storageBytes: 100, storageOperations: 2, aiInputTokens: 0, aiOutputTokens: 0, ocrPages: 0, officeDurationMs: 0, succeeded: true }, { cpuPerMs: 1, memoryMbMs: 0, storageByte: 0.1, storageOperation: 2, aiInputToken: 0, aiOutputToken: 0, ocrPage: 0, officeMs: 0 });
  assert.equal(cost.estimatedTotal, 24); assert.equal(cost.costPerSuccessfulJob, 24);
});
