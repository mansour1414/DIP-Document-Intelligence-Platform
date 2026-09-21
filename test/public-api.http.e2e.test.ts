import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { PDFDocument } from "pdf-lib";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const integration = process.env.PUBLIC_API_HTTP_E2E === "1" ? test : test.skip;

integration("Public API v1 authenticates, executes on BullMQ, isolates tenants and secures results", { timeout: 180_000 }, async () => {
  const { db } = await import("../src/lib/db/index");
  const { createOrganization } = await import("../src/lib/business/organizations");
  const { createApiClient, createApiKey, revokeApiKey } = await import("../src/lib/api-platform/clients");
  const { closeQueueResources, getJobQueue } = await import("../src/lib/queue/index");
  const { getStorage, closeStorage } = await import("../src/lib/storage/index"); const storage = getStorage();
  const base = process.env.PUBLIC_API_BASE_URL ?? "http://127.0.0.1:3000";
  const userA = randomUUID(); const userB = randomUUID();
  await db.user.create({ data: { id: userA, email: `${userA}@example.invalid`, creditLedger: { create: { type: "BONUS", amount: 100, balance: 100, idempotencyKey: "public-api-e2e-seed", reason: "PROMOTIONAL_GRANT" } } } });
  await db.user.create({ data: { id: userB, email: `${userB}@example.invalid` } });
  const orgA = await createOrganization(userA, "Release B A"); const orgB = await createOrganization(userB, "Release B B");
  const clientA = await createApiClient(userA, orgA.id, "Release B client A"); const clientB = await createApiClient(userB, orgB.id, "Release B client B");
  const keyA = await createApiKey(userA, orgA.id, clientA.id, "Release B key A", ["*"]); const keyB = await createApiKey(userB, orgB.id, clientB.id, "Release B key B", ["*"]);
  const request = (path: string, key: string, init: RequestInit = {}) => fetch(`${base}${path}`, { ...init, headers: { authorization: `Bearer ${key}`, ...(init.headers ?? {}) } });
  const expectStatus = async (path: string, key: string, expected: number, init: RequestInit = {}) => { const response = await request(path, key, init); if (response.status !== expected) { const body = (await response.clone().text()).replace(/Bearer\s+\S+/gi, "Bearer [REDACTED]").replace(/dip_v1_[A-Za-z0-9_-]+/g, "[REDACTED_API_KEY]").slice(0, 2_000); assert.equal(response.status, expected, `${init.method ?? "GET"} ${path} returned ${response.status}: ${body}`); } return response; };
  const pdf = await PDFDocument.create(); pdf.addPage().drawText("DIP public API Release B"); const bytes = await pdf.save();
  const form = (label = "a") => { const value = new FormData(); value.set("toolId", "compress-pdf"); value.set("files", new File([bytes as BlobPart], `${label}.pdf`, { type: "application/pdf" })); return value; };
  try {
    await expectStatus("/v1/tools", keyA.key, 200); await expectStatus("/v1/tools/compress-pdf", keyA.key, 200); await expectStatus("/v1/tools/internal-missing", keyA.key, 404);
    const insufficient = await request("/v1/jobs", keyB.key, { method: "POST", headers: { "idempotency-key": "release-b-insufficient" }, body: form("insufficient") }); assert.equal(insufficient.status, 402); assert.equal((await insufficient.json() as { error: { code: string } }).error.code, "CREDIT_EXHAUSTED");
    const createdResponse = await request("/v1/jobs", keyA.key, { method: "POST", headers: { "idempotency-key": "release-b-http" }, body: form() }); assert.equal(createdResponse.status, 202);
    const created = await createdResponse.json() as { data: { id: string } }; const jobId = created.data.id;
    const debitKey = `job:compress-pdf:api:${clientA.id}:release-b-http`; const debit = await db.creditLedger.findUniqueOrThrow({ where: { userId_idempotencyKey: { userId: userA, idempotencyKey: debitKey } } }); assert.equal(Number(debit.amount), -1); assert.equal(Number(debit.balance), 99);
    const replay = await request("/v1/jobs", keyA.key, { method: "POST", headers: { "idempotency-key": "release-b-http" }, body: form() }); assert.equal(replay.status, 200); assert.equal((await replay.json() as { data: { id: string } }).data.id, jobId);
    assert.equal(await db.creditLedger.count({ where: { userId: userA, idempotencyKey: debitKey } }), 1, "idempotent replay must not double-charge credits");
    const conflict = await request("/v1/jobs", keyA.key, { method: "POST", headers: { "idempotency-key": "release-b-http" }, body: form("different") }); assert.equal(conflict.status, 409); assert.equal((await conflict.json() as { error: { code: string } }).error.code, "CONFLICT");
    assert.equal((await request(`/v1/jobs/${jobId}`, keyB.key)).status, 404); assert.equal((await request(`/v1/jobs/${jobId}/result`, keyB.key)).status, 404);
    let status = ""; for (let index = 0; index < 300; index += 1) { const response = await request(`/v1/jobs/${jobId}`, keyA.key); const body = await response.json() as { data: { status: string } }; status = body.data.status; if (["succeeded", "failed", "cancelled", "expired"].includes(status)) break; await new Promise((resolve) => setTimeout(resolve, 250)); } assert.equal(status, "succeeded");
    const resultResponse = await request(`/v1/jobs/${jobId}/result`, keyA.key); assert.equal(resultResponse.status, 200); const result = await resultResponse.json() as { data: { files: Array<{ id: string; downloadUrl: string }> } }; assert.ok(result.data.files.length);
    const download = await request(result.data.files[0].downloadUrl, keyA.key); assert.equal(download.status, 200); assert.ok((await download.arrayBuffer()).byteLength > 0); assert.equal((await request(result.data.files[0].downloadUrl, keyB.key)).status, 404);
    await getJobQueue().pause(); const cancelResponse = await request("/v1/jobs", keyA.key, { method: "POST", headers: { "idempotency-key": "release-b-cancel" }, body: form("cancel") }); const cancelId = (await cancelResponse.json() as { data: { id: string } }).data.id; assert.equal((await request(`/v1/jobs/${cancelId}/cancel`, keyA.key, { method: "POST" })).status, 200); await getJobQueue().resume();
    await getJobQueue().pause(); const expiryResponse = await request("/v1/jobs", keyA.key, { method: "POST", headers: { "idempotency-key": "release-b-expiry" }, body: form("expiry") }); const expiryId = (await expiryResponse.json() as { data: { id: string } }).data.id; const expiryJob = await db.job.findUniqueOrThrow({ where: { id: expiryId }, include: { inputFile: { include: { storageObject: true } } } }); const expiryFile = expiryJob.inputFile; assert.ok(expiryFile?.storageObject); const expiryKey = expiryFile.storageKey; const old = new Date("2020-01-01T00:00:00Z"); await db.$transaction([db.job.update({ where: { id: expiryId }, data: { createdAt: old } }), db.document.update({ where: { id: expiryFile.documentId }, data: { createdAt: old } }), db.file.update({ where: { id: expiryFile.id }, data: { createdAt: old } }), db.storageObject.update({ where: { id: expiryFile.storageObject.id }, data: { createdAt: old } })]); await execFileAsync(process.execPath, ["--import", "./scripts/node-platform-compat.mjs", "--import", "tsx", "scripts/cleanup-expired-jobs.ts"], { env: { ...process.env, RETENTION_APPLY: "1" } }); assert.equal((await db.job.findUniqueOrThrow({ where: { id: expiryId } })).status, "EXPIRED"); assert.equal(await storage.exists(expiryKey), false); await getJobQueue().resume(); await new Promise((resolve) => setTimeout(resolve, 1000)); const expired = await db.job.findUniqueOrThrow({ where: { id: expiryId }, include: { toolExecutions: true } }); assert.equal(expired.toolExecutions.length, 0); assert.equal(expired.outputFileId, null);
    const usage = await db.apiUsage.findMany({ where: { organizationId: orgA.id, apiClientId: clientA.id } }); assert.ok(usage.length >= 6); assert.ok(usage.every((entry) => entry.organizationId === orgA.id && entry.apiClientId === clientA.id));
    let limited: Response | undefined; for (let index = 0; index < 140; index += 1) { const response = await request("/v1/tools", keyA.key); if (response.status === 429) { limited = response; break; } } assert.ok(limited); assert.equal((await limited.json() as { error: { code: string; requestId: string } }).error.code, "RATE_LIMITED");
    assert.equal((await request("/v1/tools", keyB.key)).status, 200, "rate limits must use authenticated client/organization identity");
    await revokeApiKey(userA, orgA.id, keyA.id); const denied = await request("/v1/tools", keyA.key); assert.equal(denied.status, 401); assert.equal((await denied.json() as { error: { code: string } }).error.code, "UNAUTHORIZED");
  } finally { await getJobQueue().resume().catch(() => undefined); await Promise.allSettled([closeQueueResources(), closeStorage(), db.$disconnect()]); }
});
