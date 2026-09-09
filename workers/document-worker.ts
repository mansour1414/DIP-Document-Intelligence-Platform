import { Worker } from "bullmq";
import { randomUUID } from "crypto";
import { db } from "@/lib/db";
import { getQueueConnection, JOB_QUEUE_NAME, type QueuedJob } from "@/lib/queue";
import { getStorage } from "@/lib/storage";
import { mergePdfBytes } from "@/lib/pdf/server";
import { logger } from "@/lib/logging";

async function processDocumentJob(message: QueuedJob) {
  const job = await db.job.findUnique({ where: { id: message.jobId }, include: { steps: true } });
  if (!job) throw new Error("JOB_NOT_FOUND");
  const context = { job_id: job.id, correlation_id: job.correlationId ?? message.correlationId, tool_id: job.toolId };
  if (job.status === "SUCCEEDED" || job.outputFileId) { logger.info("job.idempotent_skip", context); return; }
  if (job.status === "CANCELLED" || job.status === "EXPIRED") return;
  const step = job.steps.find((item) => item.name === job.toolId);
  try {
    await db.job.update({ where: { id: job.id }, data: { status: "RUNNING", startedAt: job.startedAt ?? new Date(), error: undefined, errorCode: null } });
    if (step) await db.jobStep.update({ where: { id: step.id }, data: { status: "RUNNING", startedAt: new Date() } });
    const ids = (job.params as { inputFileIds?: string[] }).inputFileIds;
    if (job.toolId !== "merge-pdf" || !ids || ids.length < 2) throw Object.assign(new Error("Unsupported job payload"), { code: "INVALID_JOB_INPUT" });
    const files = await db.file.findMany({ where: { id: { in: ids } }, include: { document: true } });
    if (files.length !== ids.length) throw Object.assign(new Error("Input file is missing"), { code: "INPUT_NOT_FOUND" });
    const inputById = new Map(files.map((file) => [file.id, file]));
    const bytes = await Promise.all(ids.map((id) => getStorage().get(inputById.get(id)!.storageKey)));
    const started = Date.now(); const output = await mergePdfBytes(bytes); const storage = getStorage();
    // Stable key makes retries overwrite the same object if a worker crashes after PutObject.
    const outputKey = `output/${job.requesterId ?? "system"}/${job.id}/merged.pdf`;
    const checksum = (await import("crypto")).createHash("sha256").update(output).digest("base64");
    const object = await storage.put({ key: outputKey, bytes: output, contentType: "application/pdf", checksum });
    try {
      await db.$transaction(async (tx) => {
        const current = await tx.job.findUniqueOrThrow({ where: { id: job.id }, select: { outputFileId: true } });
        if (current.outputFileId) return;
        const outputDocument = await tx.document.create({ data: { userId: job.requesterId!, title: "Merged PDF" } });
        const outputFile = await tx.file.create({ data: { document: { connect: { id: outputDocument.id } }, originalName: "merged.pdf", mimeType: "application/pdf", size: BigInt(output.byteLength), storageKey: object.key, checksum, storageObject: { connectOrCreate: { where: { provider_bucket_objectKey: { provider: "s3", bucket: object.bucket, objectKey: object.key } }, create: { provider: "s3", bucket: object.bucket, objectKey: object.key, size: BigInt(output.byteLength), checksum } } } } });
        await tx.fileVersion.create({ data: { fileId: outputFile.id, ownerId: job.requesterId!, version: 1, storageKey: object.key, checksum } });
        await tx.job.update({ where: { id: job.id }, data: { outputFileId: outputFile.id, status: "SUCCEEDED", result: { outputFileId: outputFile.id }, completedAt: new Date() } });
        if (step) await tx.jobStep.update({ where: { id: step.id }, data: { status: "SUCCEEDED", output: { outputFileId: outputFile.id }, completedAt: new Date() } });
        await tx.toolExecution.create({ data: { jobId: job.id, toolId: job.toolId, mode: "SERVER", input: { inputFileIds: ids }, output: { outputFileId: outputFile.id }, correlationId: job.correlationId, engine: "pdf-lib", engineVersion: "1.17.1", durationMs: Date.now() - started } });
      });
    } catch (error) { await storage.deleteObject(object.key).catch(() => undefined); throw error; }
    logger.info("job.succeeded", context);
  } catch (error) {
    const errorCode = typeof error === "object" && error && "code" in error ? String(error.code) : "PROCESSING_FAILED";
    await db.job.update({ where: { id: job.id }, data: { status: "FAILED", errorCode, error: { message: error instanceof Error ? error.message : "Processing failed" }, completedAt: new Date() } });
    if (step) await db.jobStep.update({ where: { id: step.id }, data: { status: "FAILED", errorCode, error: { message: error instanceof Error ? error.message : "Processing failed" }, completedAt: new Date() } });
    logger.error("job.failed", { ...context, error_code: errorCode }); throw error;
  }
}

export const documentWorker = new Worker<QueuedJob>(JOB_QUEUE_NAME, async (message) => processDocumentJob(message.data), { connection: getQueueConnection(), concurrency: 2, stalledInterval: 30_000, maxStalledCount: 1 });
documentWorker.on("failed", async (message) => { if (message && message.attemptsMade < (message.opts.attempts ?? 1)) await db.job.update({ where: { id: message.data.jobId }, data: { status: "RETRYING" } }); });
documentWorker.on("error", (error) => logger.error("worker.error", { error: error.message }));
