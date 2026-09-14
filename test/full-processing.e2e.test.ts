import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { PDFDocument } from "pdf-lib";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

const integration = process.env.FULL_PROCESSING_E2E === "1" ? test : test.skip;
async function fixture(pages: number) { const pdf = await PDFDocument.create(); for (let i = 0; i < pages; i += 1) pdf.addPage().drawText(`DIP E2E page ${i + 1}`); return pdf.save(); }

integration("orchestrator to DB, Redis, production worker, S3, Office and bilingual OCR is idempotent", { timeout: 240_000 }, async () => {
  const { db } = await import("../src/lib/db/index"); const { createToolJob } = await import("../src/lib/jobs/orchestrator"); const { getStorage } = await import("../src/lib/storage/index"); const { getJobQueue, getAiJobQueue } = await import("../src/lib/queue/index");
  const localWorkers = process.env.EXTERNAL_WORKER_E2E === "1" ? null : await import("../workers/document-worker");
  const userId = randomUUID(); const email = `phase6-${userId}@example.invalid`; const storage = getStorage();
  await db.user.create({ data: { id: userId, email, creditLedger: { create: { type: "BONUS", amount: 100, balance: 100, idempotencyKey: "e2e-seed", reason: "PROMOTIONAL_GRANT" } } } });
  const wait = async (id: string) => { for (let i = 0; i < 600; i += 1) { const job = await db.job.findUniqueOrThrow({ where: { id }, include: { steps: true, toolExecutions: true } }); if (["SUCCEEDED", "CANCELLED", "EXPIRED"].includes(job.status)) return job; if (job.status === "FAILED") { const queued = await (job.toolId.startsWith("summarize-") || job.toolId === "chat-with-pdf" || job.toolId === "extract-data" ? getAiJobQueue() : getJobQueue()).getJob(id); const queueState = await queued?.getState(); if (queueState === "failed") { const safe = (value: unknown) => String(value ?? "").replace(/Bearer\s+\S+/gi, "Bearer [REDACTED]").replace(/postgres(?:ql)?:\/\/[^@\s]+@/gi, "postgresql://[REDACTED]@").slice(-2000); throw new Error(`RELEASE_B_JOB_FAILED ${JSON.stringify({ jobId: job.id, toolId: job.toolId, status: job.status, errorCode: job.errorCode, error: safe((job.error as { message?: string } | null)?.message), queueState, failedReason: safe(queued?.failedReason), attemptsMade: queued?.attemptsMade, jobSteps: job.steps.map((step) => ({ name: step.name, status: step.status, errorCode: step.errorCode, error: safe((step.error as { message?: string } | null)?.message) })), toolExecutions: job.toolExecutions.map((execution) => ({ mode: execution.mode, errorCode: execution.errorCode, engine: execution.engine })) })}`); } } await new Promise((resolve) => setTimeout(resolve, 250)); } throw new Error(`E2E_JOB_STUCK:${id}`); };
  const waitForFailure = async (id: string) => { for (let i = 0; i < 600; i += 1) { const job = await db.job.findUniqueOrThrow({ where: { id }, include: { toolExecutions: true } }); if (job.status === "FAILED") { const queued = await getAiJobQueue().getJob(id); const queueState = await queued?.getState(); if (queueState === "failed") return { job, queueState }; } else if (["SUCCEEDED", "CANCELLED", "EXPIRED"].includes(job.status)) { throw new Error(`EXPECTED_JOB_FAILURE:${id}:${job.status}`); } await new Promise((resolve) => setTimeout(resolve, 250)); } throw new Error(`E2E_FAILED_JOB_STUCK:${id}`); };
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
    for (const [name, language] of [["ocr-en.pdf", "eng"], ["ocr-ar.pdf", "ara"]] as const) {
      const ocrBytes = await readFile(join(process.cwd(), "test", "fixtures", "processing", name));
      const ocr = await createToolJob({ userId, toolId: "ocr-pdf", idempotencyKey: `ocr-${language}-e2e`, correlationId: randomUUID(), options: { language }, uploads: [{ filename: name, mimeType: "application/pdf", bytes: ocrBytes }] });
      const convertedOcr = await wait(ocr.id); assert.equal(convertedOcr.status, "SUCCEEDED"); assert.equal(convertedOcr.toolExecutions.length, 1); assert.ok(convertedOcr.outputFileId);
    }
    if (process.env.GEMINI_E2E === "1") {
      assert.ok(process.env.GEMINI_API_KEY, "GEMINI_API_KEY is required for mandatory Release B AI E2E");
      for (const [toolId, options] of [["summarize-pdf", { locale: "en" }], ["chat-with-pdf", { locale: "en", question: "What page contains DIP E2E page 1? Cite the page." }], ["extract-data", { locale: "en" }]] as const) {
        const ai = await createToolJob({ userId, toolId, idempotencyKey: `${toolId}-gemini-e2e`, correlationId: randomUUID(), options, uploads: [{ filename: "grounded.pdf", mimeType: "application/pdf", bytes: first }] });
        const completed = await wait(ai.id); assert.equal(completed.status, "SUCCEEDED"); assert.equal(completed.engine, "gemini"); assert.ok(completed.engineVersion);
        const successfulExecutions = completed.toolExecutions.filter((execution) => execution.errorCode === null && execution.output !== null);
        assert.equal(successfulExecutions.length, 1, "BullMQ retries may retain failed attempt records, but exactly one execution may produce the successful side effect");
        assert.ok(completed.toolExecutions.filter((execution) => execution.id !== successfulExecutions[0].id).every((execution) => execution.errorCode !== null && execution.output === null), "non-successful ToolExecution rows must be failed attempt history only");
        assert.equal(await db.aiUsage.count({ where: { userId, jobId: ai.id } }), 1, "AI retries must reuse one usage record per job");
        assert.equal(await db.creditLedger.count({ where: { userId, idempotencyKey: `job:${toolId}:${toolId}-gemini-e2e` } }), 1, "AI retries must not duplicate the job credit debit");
        const result = completed.result as { content?: string; data?: { citations?: unknown[] } }; assert.ok(result.content?.length); assert.ok(JSON.stringify(result.data).match(/page|citation/i));
      }
      assert.equal(await db.aiUsage.count({ where: { userId } }), 3); assert.equal(await db.aiUsage.count({ where: { userId, provider: "gemini" } }), 3);
      const credit = await db.creditLedger.findFirstOrThrow({ where: { userId }, orderBy: { createdAt: "desc" } }); assert.ok(Number(credit.balance) < 100, "AI execution must debit the existing credit ledger");
      const scoped = await createToolJob({ userId, toolId: "chat-with-pdf", idempotencyKey: "cross-document-gemini-e2e", correlationId: randomUUID(), options: { locale: "en", question: "Read another document", documentId: randomUUID() }, uploads: [{ filename: "grounded.pdf", mimeType: "application/pdf", bytes: first }] });
      const deniedTerminal = await waitForFailure(scoped.id); const denied = deniedTerminal.job; assert.equal(deniedTerminal.queueState, "failed"); assert.equal(denied.status, "FAILED"); assert.equal(denied.errorCode, "DOCUMENT_SCOPE_VIOLATION"); assert.equal(denied.result, null); assert.equal(denied.outputFileId, null);
      assert.equal(denied.toolExecutions.filter((execution) => execution.errorCode === null || execution.output !== null).length, 0, "scope rejection must not produce a successful ToolExecution");
      assert.equal(await db.aiUsage.count({ where: { userId, jobId: scoped.id } }), 0, "scope rejection must happen before provider usage accounting");
    }
  } finally {
    const { closeQueueResources } = await import("../src/lib/queue/index"); const { closeStorage } = await import("../src/lib/storage/index");
    if (localWorkers) await Promise.allSettled([localWorkers.documentWorker.close(), localWorkers.aiWorker.close()]);
    try { const docs = await db.document.findMany({ where: { userId }, include: { files: true } }); for (const doc of docs) for (const file of doc.files) await storage.deleteObject(file.storageKey).catch(() => undefined); }
    finally { await Promise.allSettled([closeQueueResources(), closeStorage(), db.$disconnect()]); }
  }
});

integration("retention scheduler deletes expired storage, preserves running inputs and retries idempotently", { timeout: 30_000 }, async () => {
  const { db } = await import("../src/lib/db/index"); const { runRetentionCleanup } = await import("../src/lib/retention/service"); const userId = randomUUID(); const old = new Date("2020-01-01T00:00:00Z");
  try { await db.user.create({ data: { id: userId, email: `retention-${userId}@example.invalid` } });
  const expired = await db.document.create({ data: { userId, title: "expired", createdAt: old, files: { create: { originalName: "expired.pdf", mimeType: "application/pdf", size: 1, storageKey: `expired/${userId}`, createdAt: old, storageObject: { create: { provider: "s3", bucket: "test", objectKey: `expired/${userId}`, size: 1, createdAt: old } } } } }, include: { files: true } });
  const active = await db.document.create({ data: { userId, title: "protected", createdAt: old, files: { create: { originalName: "active.pdf", mimeType: "application/pdf", size: 1, storageKey: `active/${userId}`, createdAt: old, storageObject: { create: { provider: "s3", bucket: "test", objectKey: `active/${userId}`, size: 1, createdAt: old } } } } }, include: { files: true } });
  await db.job.create({ data: { toolId: "merge-pdf", idempotencyKey: `protected-${userId}`, requesterId: userId, inputFileId: active.files[0].id, status: "RUNNING" } });
  const deleted: string[] = []; const fakeStorage = { createUploadKey: () => "", put: async () => ({ key: "", bucket: "", contentType: "", size: 0 }), get: async () => new Uint8Array(), head: async () => ({ key: "", bucket: "", contentType: "", size: 0 }), exists: async () => true, deleteObject: async (key: string) => { deleted.push(key); }, close: async () => undefined };
  const first = await runRetentionCleanup({ now: new Date("2026-09-10T00:00:00Z"), dryRun: false, storage: fakeStorage }); assert.equal(first.deletedDocuments, 1); assert.deepEqual(deleted, [`expired/${userId}`]);
  assert.equal((await db.document.findUniqueOrThrow({ where: { id: expired.id } })).status, "DELETED"); assert.equal((await db.document.findUniqueOrThrow({ where: { id: active.id } })).status, "ACTIVE");
  const second = await runRetentionCleanup({ now: new Date("2026-09-10T00:00:00Z"), dryRun: false, storage: fakeStorage }); assert.equal(second.deletedDocuments, 0); assert.deepEqual(deleted, [`expired/${userId}`]);
  } finally { await db.$disconnect(); }
});
