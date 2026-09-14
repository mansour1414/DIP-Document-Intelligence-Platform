import { randomUUID } from "crypto";
import { enqueueAiJob, enqueueJob } from "@/lib/queue";
import { getStorage } from "@/lib/storage";
import { getToolDefinition } from "@/lib/tools/registry";
import { validateUpload } from "@/lib/uploads/validation";
import { logger } from "@/lib/logging";
import { enforceJobCreation } from "@/lib/usage/enforcement";
import { measure, recordMetric } from "@/lib/observability/metrics";
import { withTenant } from "@/lib/db/tenant";

type Upload = { filename: string; mimeType: string; bytes: Uint8Array };
export async function createToolJob(input: { userId: string; toolId: string; uploads: Upload[]; options?: Record<string, string | number | boolean>; idempotencyKey: string; correlationId?: string; organizationId?: string; apiClientId?: string }) {
  const apiStarted = performance.now();
  const tool = getToolDefinition(input.toolId);
  const minimumFiles = input.toolId === "merge-pdf" ? 2 : 1;
  if (input.uploads.length < minimumFiles || input.uploads.length > tool.limits.maxFiles) throw new Error("INPUT_FILE_COUNT_INVALID");
  if (input.uploads.reduce((total, upload) => total + upload.bytes.byteLength, 0) > tool.limits.maxBytes) throw new Error("TOTAL_SIZE_LIMIT_EXCEEDED");
  const correlationId = input.correlationId ?? randomUUID();
  const existing = await measure("db_job_idempotency_query", { tool_id: tool.toolId }, () => withTenant({ userId: input.userId }, (tx) => tx.job.findUnique({ where: { toolId_idempotencyKey: { toolId: tool.toolId, idempotencyKey: input.idempotencyKey } }, select: { id: true, status: true } })));
  if (existing) return { ...existing, reused: true };
  const storage = getStorage();
  const prepared = await Promise.all(input.uploads.map(async (upload) => ({ upload, validation: await validateUpload({ toolId: tool.toolId, declaredMime: upload.mimeType, bytes: upload.bytes }) })));
  const monetization = await enforceJobCreation({ userId: input.userId, toolId: tool.toolId, idempotencyKey: input.idempotencyKey, correlationId, options: input.options, files: prepared.map(({upload,validation})=>({size:upload.bytes.byteLength,pageCount:validation.pageCount})) });
  const stored: Array<{ key: string; bucket: string; upload: Upload; validation: Awaited<ReturnType<typeof validateUpload>> }> = [];
  try {
    for (const item of prepared) { const key = storage.createUploadKey({ userId: input.userId, filename: item.upload.filename }); const object = await storage.put({ key, bytes: item.upload.bytes, contentType: item.validation.mimeType, checksum: item.validation.checksum }); stored.push({ key: object.key, bucket: object.bucket, upload: item.upload, validation: item.validation }); }
    const job = await withTenant({ userId: input.userId }, async (tx) => {
      const document = await tx.document.create({ data: { userId: input.userId, organizationId: input.organizationId, title: `${tool.name} input` } });
      const files = await Promise.all(stored.map(async (item) => { const file = await tx.file.create({ data: { document: { connect: { id: document.id } }, originalName: item.upload.filename.slice(0, 255), mimeType: item.validation.mimeType, size: BigInt(item.upload.bytes.byteLength), storageKey: item.key, checksum: item.validation.checksum, pageCount: item.validation.pageCount, storageObject: { connectOrCreate: { where: { provider_bucket_objectKey: { provider: "s3", bucket: item.bucket, objectKey: item.key } }, create: { provider: "s3", bucket: item.bucket, objectKey: item.key, size: BigInt(item.upload.bytes.byteLength), checksum: item.validation.checksum } } } } }); await tx.fileVersion.create({ data: { fileId: file.id, ownerId: input.userId, version: 1, storageKey: item.key, checksum: item.validation.checksum } }); return file; }));
      return tx.job.create({ data: { toolId: tool.toolId, idempotencyKey: input.idempotencyKey, requesterId: input.userId, organizationId: input.organizationId, apiClientId: input.apiClientId, inputFileId: files[0].id, status: "QUEUED", params: { inputFileIds: files.map((file) => file.id), options: input.options ?? {} }, correlationId, steps: { create: { name: tool.toolId, idempotencyKey: `${input.idempotencyKey}:${tool.toolId}`, status: "QUEUED", correlationId } } }, select: { id: true, status: true } });
    });
    const queuedJob = { jobId: job.id, toolId: tool.toolId, idempotencyKey: input.idempotencyKey, correlationId, userId: input.userId };
    const queueOptions = { priority: monetization.entitlements.processingPriority === "high" ? 1 : 5 };
    if (tool.aiFlag) await enqueueAiJob(queuedJob, queueOptions); else await enqueueJob(queuedJob, queueOptions);
    logger.info("job.queued", { job_id: job.id, correlation_id: correlationId, tool_id: tool.toolId });
    recordMetric("api_job_creation_latency_ms", performance.now() - apiStarted, "ms", { tool_id: tool.toolId });
    recordMetric("jobs_total", 1, "count", { tool_id: tool.toolId });
    return { ...job, reused: false };
  } catch (error) { await Promise.all(stored.map((object) => storage.deleteObject(object.key).catch(() => undefined))); throw error; }
}

export function createMergePdfJob(input: { userId: string; uploads: Upload[]; idempotencyKey: string; correlationId?: string }) {
  return createToolJob({ ...input, toolId: "merge-pdf" });
}

/** Trusted internal-file boundary used by workflows. Browser-provided storage keys are never accepted. */
export async function createToolJobFromFiles(input: { userId: string; toolId: string; fileIds: string[]; options?: Record<string, string | number | boolean>; idempotencyKey: string; correlationId: string; workflowRunId: string; workflowNodeId: string }) {
  const tool = getToolDefinition(input.toolId);
  const existing = await withTenant({ userId: input.userId }, (tx) => tx.job.findUnique({ where: { toolId_idempotencyKey: { toolId: tool.toolId, idempotencyKey: input.idempotencyKey } }, select: { id: true, status: true } }));
  if (existing) return { ...existing, reused: true };
  const files = await withTenant({ userId: input.userId }, (tx) => tx.file.findMany({ where: { id: { in: input.fileIds }, document: { userId: input.userId } }, select: { id: true, size: true, pageCount: true, mimeType: true } }));
  if (files.length !== input.fileIds.length) throw Object.assign(new Error("WORKFLOW_ARTIFACT_UNAUTHORIZED"), { code: "WORKFLOW_ARTIFACT_UNAUTHORIZED" });
  if (input.fileIds.length < (input.toolId === "merge-pdf" ? 2 : 1) || input.fileIds.length > tool.limits.maxFiles) throw new Error("INPUT_FILE_COUNT_INVALID");
  if (files.some((file) => !tool.mime.input.includes(file.mimeType))) throw Object.assign(new Error("WORKFLOW_MIME_INCOMPATIBLE"), { code: "WORKFLOW_MIME_INCOMPATIBLE" });
  const monetization = await enforceJobCreation({ userId: input.userId, toolId: tool.toolId, idempotencyKey: input.idempotencyKey, correlationId: input.correlationId, options: input.options, files: files.map((file) => ({ size: Number(file.size), pageCount: file.pageCount ?? undefined })) });
  const job = await withTenant({ userId: input.userId }, (tx) => tx.job.create({ data: { toolId: tool.toolId, idempotencyKey: input.idempotencyKey, requesterId: input.userId, inputFileId: input.fileIds[0], status: "QUEUED", params: { inputFileIds: input.fileIds, options: input.options ?? {} }, correlationId: input.correlationId, workflowRunId: input.workflowRunId, workflowNodeId: input.workflowNodeId, steps: { create: { name: tool.toolId, idempotencyKey: `${input.idempotencyKey}:${tool.toolId}`, status: "QUEUED", correlationId: input.correlationId } } }, select: { id: true, status: true } }));
  const queued = { jobId: job.id, toolId: tool.toolId, idempotencyKey: input.idempotencyKey, correlationId: input.correlationId, userId: input.userId, workflowRunId: input.workflowRunId };
  const queueOptions = { priority: monetization.entitlements.processingPriority === "high" ? 1 : 5 };
  if (tool.aiFlag) await enqueueAiJob(queued, queueOptions); else await enqueueJob(queued, queueOptions);
  logger.info("workflow.node.queued", { workflow_run_id: input.workflowRunId, workflow_node_id: input.workflowNodeId, job_id: job.id, correlation_id: input.correlationId, tool_id: tool.toolId });
  return { ...job, reused: false };
}
