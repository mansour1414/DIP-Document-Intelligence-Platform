import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { createCanvas } from "@napi-rs/canvas";
import { PDFDocument } from "pdf-lib";
import { extractEmbeddedImages } from "@/lib/pdf/extract-images";
import { validateWorkerOutputs } from "@/lib/outputs/validation";
import { deletePhase1Secret, PHASE1_SECRET_TTL_SECONDS, putPhase1Secret, takePhase1Secret, validatePhase1Secrets, type SecretStore } from "@/lib/secrets/phase1";
import { toolRegistry, workerToolIds, isPublicApiTool } from "@/lib/tools/registry";
import { validateToolOptions } from "@/lib/tools/options";
import { validateWorkflowDefinition } from "@/lib/workflows/validator";
import { validateUpload } from "@/lib/uploads/validation";
import { parsePublicJobRequest } from "@/lib/public-api/jobs";
import { redactLogContext } from "@/lib/logging";
import { scrubSentryEvent } from "@/lib/observability/sentry-scrub";

class MemoryStore implements SecretStore {
  values = new Map<string, string>(); ttl = 0; deleted = 0;
  async set(key: string, value: string, ttl: number) { assert.equal(this.values.has(key), false); this.values.set(key, value); this.ttl = ttl; }
  async take(key: string) { const value = this.values.get(key) ?? null; this.values.delete(key); return value; }
  async delete(key: string) { this.deleted += this.values.delete(key) ? 1 : 0; }
}

const key = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
test("ephemeral secrets are encrypted, bound, short-lived, one-time, and cleanable", async () => {
  const previous = process.env.PHASE1_SECRET_ENCRYPTION_KEY; process.env.PHASE1_SECRET_ENCRYPTION_KEY = key;
  try {
    const store = new MemoryStore(); const payload = { userPassword: "سري-user", ownerPassword: "سري-owner" }; const reference = await putPhase1Secret({ tenantId: "tenant-a", jobId: "job-a", purpose: "protect-pdf", payload }, store);
    assert.equal(store.ttl, PHASE1_SECRET_TTL_SECONDS); assert.match(reference, /^[0-9a-f-]{36}$/u); const encoded = [...store.values.values()][0]; assert.doesNotMatch(encoded, /سري|user|owner/u);
    await assert.rejects(() => takePhase1Secret({ reference, tenantId: "tenant-b", jobId: "job-a", purpose: "protect-pdf" }, store), { code: "SECRET_REFERENCE_INVALID" });
    const second = await putPhase1Secret({ tenantId: "tenant-a", jobId: "job-b", purpose: "protect-pdf", payload }, store); assert.deepEqual(await takePhase1Secret({ reference: second, tenantId: "tenant-a", jobId: "job-b", purpose: "protect-pdf" }, store), payload);
    await assert.rejects(() => takePhase1Secret({ reference: second, tenantId: "tenant-a", jobId: "job-b", purpose: "protect-pdf" }, store), { code: "SECRET_REFERENCE_EXPIRED" });
    const third = await putPhase1Secret({ tenantId: "tenant-a", jobId: "job-c", purpose: "protect-pdf", payload }, store); await deletePhase1Secret(third, store); assert.equal(store.values.size, 0); assert.equal(store.deleted, 1);
  } finally { if (previous === undefined) delete process.env.PHASE1_SECRET_ENCRYPTION_KEY; else process.env.PHASE1_SECRET_ENCRYPTION_KEY = previous; }
});

test("secret input policy rejects empty, oversized, newline, and unauthorized unlock inputs", () => {
  assert.throws(() => validatePhase1Secrets("protect-pdf", { userPassword: "", ownerPassword: "owner" }), { code: "SECRET_INPUT_INVALID" });
  assert.throws(() => validatePhase1Secrets("unlock-pdf", { password: "valid" }), { code: "SECRET_INPUT_INVALID" });
  assert.throws(() => validatePhase1Secrets("unlock-pdf", { password: "bad\nvalue", authorizedUseAcknowledged: true }), { code: "SECRET_INPUT_INVALID" });
  assert.throws(() => validatePhase1Secrets("pdf-permissions", { ownerPassword: "x".repeat(129) }), { code: "SECRET_INPUT_INVALID" });
});

test("security tools use v1 contracts, remain public/direct, and secret-bearing workflows are denied", () => {
  for (const id of ["extract-images", "protect-pdf", "unlock-pdf", "pdf-permissions", "repair-pdf"]) { const tool = toolRegistry[id]; assert.ok(tool); assert.equal(tool.version, "1"); assert.equal(tool.optionSchemaVersion, "1"); assert.equal(tool.aiFlag, false); assert.equal(workerToolIds.has(id), true); assert.equal(isPublicApiTool(tool), true); }
  assert.deepEqual(validateToolOptions("pdf-permissions", {}), { printing: "full", extraction: true, assembly: true, forms: true, annotations: true });
  for (const id of ["protect-pdf", "unlock-pdf", "pdf-permissions"]) { const result = validateWorkflowDefinition({ schemaVersion: 1, nodes: [{ id: "secure", toolId: id, toolVersion: "1", dependsOn: [], inputs: [{ source: "workflow", input: "documents" }] }] }); assert.ok(result.issues.some((issue) => issue.code === "WORKFLOW_SECRET_INPUT_UNSUPPORTED")); }
  const agent = readFileSync(new URL("../src/lib/agent/runtime.ts", import.meta.url), "utf8"); assert.match(agent, /agentExcludedTools/); for (const id of ["protect-pdf", "unlock-pdf", "pdf-permissions"]) assert.match(agent, new RegExp(`agentExcludedTools = new Set\\(\\[[^\\]]*"${id}"`));
});

test("persisted and queued job contracts carry only opaque secret references", () => {
  const orchestrator = readFileSync(new URL("../src/lib/jobs/orchestrator.ts", import.meta.url), "utf8"); const queue = readFileSync(new URL("../src/lib/queue/index.ts", import.meta.url), "utf8"); const worker = readFileSync(new URL("../workers/document-worker.ts", import.meta.url), "utf8"); const publicJobs = readFileSync(new URL("../src/lib/public-api/jobs.ts", import.meta.url), "utf8"); const qpdf = readFileSync(new URL("../src/lib/pdf/qpdf.ts", import.meta.url), "utf8");
  assert.match(orchestrator, /params:\s*\{ inputFileIds:[^}]+options,[^}]+secretRef/u); assert.doesNotMatch(orchestrator, /params:\s*\{[^}]*secrets/u); assert.doesNotMatch(queue, /password|secretRef|secrets/u);
  assert.match(worker, /job\.status === "CANCELLED" \|\| job\.status === "EXPIRED"[^}]+deletePhase1Secret/u); assert.match(worker, /takePhase1Secret/); assert.match(worker, /finally \{ await deletePhase1Secret/); assert.match(publicJobs, /cancelPublicJob[\s\S]+deletePhase1Secret\(cancelled\.secretRef\)/u); assert.match(qpdf, /spawn\([^,]+, \[`@\$\{argumentFile\}`\]/u); assert.match(qpdf, /--suppress-password-recovery/u); assert.doesNotMatch(qpdf, /--force-R6/u); assert.match(qpdf, /shell:\s*false/u); assert.doesNotMatch(qpdf, /exec\(|execSync|shell:\s*true/u);
});

test("Public API transports passwords outside options and excludes them from the request hash and observability", async () => {
  const document = await PDFDocument.create(); document.addPage(); const bytes = await document.save(); const form = new FormData(); form.set("toolId", "protect-pdf"); form.set("options", "{}"); form.set("userPassword", "api-user-secret"); form.set("ownerPassword", "api-owner-secret"); form.append("files", new File([bytes as BlobPart], "input.pdf", { type: "application/pdf" }));
  const parsed = await parsePublicJobRequest(new Request("http://localhost/v1/jobs", { method: "POST", headers: { "idempotency-key": "security-contract" }, body: form })); assert.deepEqual(parsed.options, {}); assert.deepEqual(parsed.secrets, { userPassword: "api-user-secret", ownerPassword: "api-owner-secret" }); assert.doesNotMatch(parsed.requestHash, /secret/); assert.equal(parsed.requestHash.length, 64);
  assert.equal(redactLogContext({ password: "api-user-secret" }).password, "[REDACTED]"); const event = scrubSentryEvent({ request: { data: { ownerPassword: "api-owner-secret" }, url: "https://example.test/path?password=leak" }, exception: { values: [{ value: "api-user-secret" }] } } as never); assert.equal(event.request?.data, undefined); assert.equal(event.request?.url, "https://example.test/path"); assert.equal(event.exception?.values?.[0].value, "[REDACTED_ERROR_MESSAGE]");
});

test("encrypted/repair preflight is scoped and normal PDF validation stays strict", async () => {
  const malformed = new TextEncoder().encode("%PDF-1.7\nmalformed"); const unlock = await validateUpload({ toolId: "unlock-pdf", declaredMime: "application/pdf", bytes: malformed }); assert.equal(unlock.controlledWorkerPreflight, true); const repair = await validateUpload({ toolId: "repair-pdf", declaredMime: "application/pdf", bytes: malformed }); assert.equal(repair.controlledWorkerPreflight, true);
  await assert.rejects(() => validateUpload({ toolId: "protect-pdf", declaredMime: "application/pdf", bytes: malformed }), { code: "PDF_INVALID" });
});

test("Extract Images emits decoded embedded PNGs, deduplicates, reports policy, and never renders pages", async () => {
  const canvas = createCanvas(8, 6); const context = canvas.getContext("2d"); context.fillStyle = "#e11d48"; context.fillRect(0, 0, 8, 6); const png = canvas.toBuffer("image/png");
  const pdf = await PDFDocument.create(); const embedded = await pdf.embedPng(png); const first = pdf.addPage([100, 100]); first.drawImage(embedded, { x: 10, y: 10, width: 40, height: 30 }); const second = pdf.addPage([120, 80]); second.drawImage(embedded, { x: 20, y: 10, width: 40, height: 30 });
  const outputs = await extractEmbeddedImages(await pdf.save({ useObjectStreams: true })); assert.equal(outputs.filter((output) => output.mimeType === "image/png").length, 1); const report = JSON.parse(new TextDecoder().decode(outputs.at(-1)!.bytes)); assert.equal(report.mode, "decoded-embedded-images"); assert.equal(report.originalStreamsPreserved, false); assert.equal(report.duplicatesSkipped, 1); assert.match(report.note, /not rendered page screenshots/); await validateWorkerOutputs(outputs);
  const source = readFileSync(new URL("../src/lib/pdf/extract-images.ts", import.meta.url), "utf8"); assert.doesNotMatch(source, /page\.render|renderPdfTo/u);
});

test("production qpdf gate proves exact version, safe argfiles, AES-256, Unicode, permissions, repair, sandbox, Ghostscript absence, and SBOM", () => {
  const workflow = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8"); const gate = readFileSync(new URL("../scripts/verify-qpdf-security-runtime.mjs", import.meta.url), "utf8");
  assert.match(workflow, /verify-qpdf-security-runtime\.mjs/); assert.match(workflow, /--read-only/); assert.match(workflow, /qpdf-worker\.spdx\.json/); assert.match(gate, /11\.3\.0-1\+deb12u1/); assert.match(gate, /AESv3/); assert.match(gate, /R\\s\*=\\s\*6/u); assert.doesNotMatch(gate, /--force-R6/u); assert.match(gate, /كلمة-مرور-آمنة/); assert.match(gate, /--suppress-password-recovery/u); assert.match(gate, /wrongPasswordRejected/); assert.match(gate, /modify annotations: not allowed/); assert.match(gate, /repairUnrecoverableRejected/); assert.match(gate, /Ghostscript is present/); assert.match(gate, /Apache-2\.0/); assert.doesNotMatch(gate, /shell:\s*true/u);
});
