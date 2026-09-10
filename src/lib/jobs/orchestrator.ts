import { randomUUID } from "crypto";
import { db } from "@/lib/db";
import { enqueueAiJob, enqueueJob } from "@/lib/queue";
import { getStorage } from "@/lib/storage";
import { getToolDefinition } from "@/lib/tools/registry";
import { validateUpload } from "@/lib/uploads/validation";
import { logger } from "@/lib/logging";
import { enforceJobCreation } from "@/lib/usage/enforcement";
import { measure, recordMetric } from "@/lib/observability/metrics";

type Upload = { filename: string; mimeType: string; bytes: Uint8Array };
export async function createToolJob(input: { userId: string; toolId: string; uploads: Upload[]; options?: Record<string, string | number | boolean>; idempotencyKey: string; correlationId?: string }) {
  const apiStarted = performance.now();
  const tool = getToolDefinition(input.toolId);
  const minimumFiles = input.toolId === "merge-pdf" ? 2 : 1;
  if (input.uploads.length < minimumFiles || input.uploads.length > tool.limits.maxFiles) throw new Error("INPUT_FILE_COUNT_INVALID");
  if (input.uploads.reduce((total, upload) => total + upload.bytes.byteLength, 0) > tool.limits.maxBytes) throw new Error("TOTAL_SIZE_LIMIT_EXCEEDED");
  const correlationId = input.correlationId ?? randomUUID();
  const existing = await measure("db_job_idempotency_query", { tool_id: tool.toolId }, () => db.job.findUnique({ where: { toolId_idempotencyKey: { toolId: tool.toolId, idempotencyKey: input.idempotencyKey } }, select: { id: true, status: true } }));
  if (existing) return { ...existing, reused: true };
  const storage = getStorage();
  const prepared = await Promise.all(input.uploads.map(async (upload) => ({ upload, validation: await validateUpload({ toolId: tool.toolId, declaredMime: upload.mimeType, bytes: upload.bytes }) })));
  const monetization = await enforceJobCreation({ userId: input.userId, toolId: tool.toolId, idempotencyKey: input.idempotencyKey, correlationId, options: input.options, files: prepared.map(({upload,validation})=>({size:upload.bytes.byteLength,pageCount:validation.pageCount})) });
  const stored: Array<{ key: string; bucket: string; upload: Upload; validation: Awaited<ReturnType<typeof validateUpload>> }> = [];
  try {
    for (const item of prepared) { const key = storage.createUploadKey({ userId: input.userId, filename: item.upload.filename }); const object = await storage.put({ key, bytes: item.upload.bytes, contentType: item.validation.mimeType, checksum: item.validation.checksum }); stored.push({ key: object.key, bucket: object.bucket, upload: item.upload, validation: item.validation }); }
    const job = await db.$transaction(async (tx) => {
      const document = await tx.document.create({ data: { userId: input.userId, title: `${tool.name} input` } });
      const files = await Promise.all(stored.map(async (item) => { const file = await tx.file.create({ data: { document: { connect: { id: document.id } }, originalName: item.upload.filename.slice(0, 255), mimeType: item.validation.mimeType, size: BigInt(item.upload.bytes.byteLength), storageKey: item.key, checksum: item.validation.checksum, pageCount: item.validation.pageCount, storageObject: { connectOrCreate: { where: { provider_bucket_objectKey: { provider: "s3", bucket: item.bucket, objectKey: item.key } }, create: { provider: "s3", bucket: item.bucket, objectKey: item.key, size: BigInt(item.upload.bytes.byteLength), checksum: item.validation.checksum } } } } }); await tx.fileVersion.create({ data: { fileId: file.id, ownerId: input.userId, version: 1, storageKey: item.key, checksum: item.validation.checksum } }); return file; }));
      return tx.job.create({ data: { toolId: tool.toolId, idempotencyKey: input.idempotencyKey, requesterId: input.userId, inputFileId: files[0].id, status: "QUEUED", params: { inputFileIds: files.map((file) => file.id), options: input.options ?? {} }, correlationId, steps: { create: { name: tool.toolId, idempotencyKey: `${input.idempotencyKey}:${tool.toolId}`, status: "QUEUED", correlationId } } }, select: { id: true, status: true } });
    });
    const queuedJob = { jobId: job.id, toolId: tool.toolId, idempotencyKey: input.idempotencyKey, correlationId };
    const queueOptions = { priority: monetization.entitlements.processingPriority === "high" ? 1 : 5 };
    if (tool.aiFlag) await enqueueAiJob(queuedJob, queueOptions); else await enqueueJob(queuedJob, queueOptions);
    logger.info("job.queued", { job_id: job.id, correlation_id: correlationId, tool_id: tool.toolId });
    recordMetric("api_job_creation_latency", performance.now() - apiStarted, "ms", { job_id: job.id, correlation_id: correlationId, tool_id: tool.toolId });
    recordMetric("jobs_total", 1, "count", { tool_id: tool.toolId });
    return { ...job, reused: false };
  } catch (error) { await Promise.all(stored.map((object) => storage.deleteObject(object.key).catch(() => undefined))); throw error; }
}

export function createMergePdfJob(input: { userId: string; uploads: Upload[]; idempotencyKey: string; correlationId?: string }) {
  return createToolJob({ ...input, toolId: "merge-pdf" });
}
