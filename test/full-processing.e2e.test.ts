import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { PDFDocument } from "pdf-lib";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

const integration = process.env.FULL_PROCESSING_E2E === "1" ? test : test.skip;
async function fixture(pages: number) { const pdf = await PDFDocument.create(); for (let i = 0; i < pages; i += 1) pdf.addPage().drawText(`DIP E2E page ${i + 1}`); return pdf.save(); }

integration("orchestrator to DB, Redis, worker, S3 and multi-output is idempotent", { timeout: 90_000 }, async () => {
  const { db } = await import("../src/lib/db/index"); const { createToolJob } = await import("../src/lib/jobs/orchestrator"); const { getStorage } = await import("../src/lib/storage/index");
  const { documentWorker, aiWorker } = await import("../workers/document-worker");
  const userId = randomUUID(); const email = `phase6-${userId}@example.invalid`; const storage = getStorage();
  await db.user.create({ data: { id: userId, email, creditLedger: { create: { type: "BONUS", amount: 100, balance: 100, idempotencyKey: "e2e-seed", reason: "PROMOTIONAL_GRANT" } } } });
  const wait = async (id: string) => { for (let i = 0; i < 180; i += 1) { const job = await db.job.findUniqueOrThrow({ where: { id }, include: { toolExecutions: true } }); if (["SUCCEEDED", "FAILED", "CANCELLED", "EXPIRED"].includes(job.status)) return job; await new Promise((resolve) => setTimeout(resolve, 250)); } throw new Error("E2E_JOB_STUCK"); };
  try {
    const first = await fixture(1); const second = await fixture(2); const correlationId = randomUUID();
    const merge = await createToolJob({ userId, toolId: "merge-pdf", idempotencyKey: "merge-e2e", correlationId, uploads: [{ filename: "a.pdf", mimeType: "application/pdf", bytes: first }, { filename: "b.pdf", mimeType: "application/pdf", bytes: second }] });
    const merged = await wait(merge.id); assert.equal(merged.status, "SUCCEEDED"); assert.equal(merged.correlationId, correlationId); assert.equal(merged.toolExecutions.length, 1); assert.ok(merged.outputFileId);
    const repeated = await createToolJob({ userId, toolId: "merge-pdf", idempotencyKey: "merge-e2e", correlationId, uploads: [{ filename: "a.pdf", mimeType: "application/pdf", bytes: first }, { filename: "b.pdf", mimeType: "application/pdf", bytes: second }] });
    assert.equal(repeated.id, merge.id); assert.equal(repeated.reused, true);
    const jpg = await createToolJob({ userId, toolId: "pdf-to-jpg", idempotencyKey: "jpg-e2e", correlationId: randomUUID(), uploads: [{ filename: "multi.pdf", mimeType: "application/pdf", bytes: second }] });
    const converted = await wait(jpg.id); assert.equal(converted.status, "SUCCEEDED"); const result = converted.result as { outputFileIds: string[] }; assert.equal(result.outputFileIds.length, 2); assert.equal(converted.toolExecutions.length, 1);
    const outputs = await db.file.findMany({ where: { id: { in: result.outputFileIds } } }); for (const output of outputs) assert.equal(await storage.exists(output.storageKey), true);
    const wordBytes = await readFile(join(process.cwd(), "test", "fixtures", "processing", "word-en.docx"));
    const office = await createToolJob({ userId, toolId: "word-to-pdf", idempotencyKey: "office-e2e", correlationId: randomUUID(), uploads: [{ filename: "word-en.docx", mimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", bytes: wordBytes }] });
    const convertedOffice = await wait(office.id); assert.equal(convertedOffice.status, "SUCCEEDED"); assert.equal(convertedOffice.toolExecutions.length, 1); assert.ok(convertedOffice.outputFileId);
  } finally {
    await documentWorker.close(); await aiWorker.close(); const { getAiJobQueue, getJobQueue, getQueueConnection } = await import("../src/lib/queue/index"); await getJobQueue().close(); await getAiJobQueue().close(); await getQueueConnection().quit();
    const docs = await db.document.findMany({ where: { userId }, include: { files: true } }); for (const doc of docs) for (const file of doc.files) await storage.deleteObject(file.storageKey).catch(() => undefined);
    await db.$disconnect();
  }
});

integration("retention scheduler deletes expired storage, preserves running inputs and retries idempotently", { timeout: 30_000 }, async () => {
  const { db } = await import("../src/lib/db/index"); const { runRetentionCleanup } = await import("../src/lib/retention/service"); const userId = randomUUID(); const old = new Date("2020-01-01T00:00:00Z");
  await db.user.create({ data: { id: userId, email: `retention-${userId}@example.invalid` } });
  const expired = await db.document.create({ data: { userId, title: "expired", createdAt: old, files: { create: { originalName: "expired.pdf", mimeType: "application/pdf", size: 1, storageKey: `expired/${userId}`, createdAt: old, storageObject: { create: { provider: "s3", bucket: "test", objectKey: `expired/${userId}`, size: 1, createdAt: old } } } } }, include: { files: true } });
  const active = await db.document.create({ data: { userId, title: "protected", createdAt: old, files: { create: { originalName: "active.pdf", mimeType: "application/pdf", size: 1, storageKey: `active/${userId}`, createdAt: old, storageObject: { create: { provider: "s3", bucket: "test", objectKey: `active/${userId}`, size: 1, createdAt: old } } } } }, include: { files: true } });
  await db.job.create({ data: { toolId: "merge-pdf", idempotencyKey: `protected-${userId}`, requesterId: userId, inputFileId: active.files[0].id, status: "RUNNING" } });
  const deleted: string[] = []; const fakeStorage = { createUploadKey: () => "", put: async () => ({ key: "", bucket: "", contentType: "", size: 0 }), get: async () => new Uint8Array(), head: async () => ({ key: "", bucket: "", contentType: "", size: 0 }), exists: async () => true, deleteObject: async (key: string) => { deleted.push(key); } };
  const first = await runRetentionCleanup({ now: new Date("2026-09-10T00:00:00Z"), dryRun: false, storage: fakeStorage }); assert.equal(first.deletedDocuments, 1); assert.deepEqual(deleted, [`expired/${userId}`]);
  assert.equal((await db.document.findUniqueOrThrow({ where: { id: expired.id } })).status, "DELETED"); assert.equal((await db.document.findUniqueOrThrow({ where: { id: active.id } })).status, "ACTIVE");
  const second = await runRetentionCleanup({ now: new Date("2026-09-10T00:00:00Z"), dryRun: false, storage: fakeStorage }); assert.equal(second.deletedDocuments, 0); assert.deepEqual(deleted, [`expired/${userId}`]); await db.$disconnect();
});
