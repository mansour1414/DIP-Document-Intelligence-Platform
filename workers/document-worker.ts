import { Worker } from "bullmq";
import { createHash } from "crypto";
import { db } from "@/lib/db";
import { getQueueConnection, JOB_QUEUE_NAME, type QueuedJob } from "@/lib/queue";
import { getStorage } from "@/lib/storage";
import { runPdfWorkerTool, type PdfWorkerTool } from "@/lib/pdf/server";
import { processServerDocument, type ServerToolId } from "@/lib/document-processing/server";
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
    const params = job.params as { inputFileIds?: string[]; options?: Record<string, unknown> }; const ids = params.inputFileIds;
    if (!ids?.length) throw Object.assign(new Error("Unsupported job payload"), { code: "INVALID_JOB_INPUT" });
    const files = await db.file.findMany({ where: { id: { in: ids } }, include: { document: true } });
    if (files.length !== ids.length) throw Object.assign(new Error("Input file is missing"), { code: "INPUT_NOT_FOUND" });
    const inputById = new Map(files.map((file) => [file.id, file]));
    const bytes = await Promise.all(ids.map((id) => getStorage().get(inputById.get(id)!.storageKey))); const options: Record<string, unknown> = { ...(params.options ?? {}), inputMimeTypes: ids.map((id) => inputById.get(id)!.mimeType) };
    const started = Date.now(); let engine = "pdf-lib"; let engineVersion = "1.17.1";
    const pdfTools = new Set(["merge-pdf", "split-pdf", "organize-pdf", "rotate-pdf", "delete-pages", "extract-pages", "jpg-to-pdf"]);
    const documentTools = new Set(["word-to-pdf", "pdf-to-word", "excel-to-pdf", "powerpoint-to-pdf", "ocr-pdf"]);
    let outputs: Array<{ name: string; mimeType: string; bytes: Uint8Array }>;
    if (pdfTools.has(job.toolId)) outputs = await runPdfWorkerTool(job.toolId as PdfWorkerTool, bytes, options);
    else if (documentTools.has(job.toolId)) { const input = inputById.get(ids[0])!; const result = await processServerDocument(job.toolId as ServerToolId, new File([bytes[0] as BlobPart], input.originalName, { type: input.mimeType }), typeof options.language === "string" ? options.language : "ara+eng"); outputs = [{ name: result.filename, mimeType: result.contentType, bytes: result.bytes }]; engine = job.toolId === "ocr-pdf" ? "ocrmypdf" : "libreoffice"; engineVersion = "host"; }
    else throw Object.assign(new Error("Tool is not enabled on this worker"), { code: "TOOL_NOT_WORKER_ENABLED" });
    const storage = getStorage();
    const storedOutputs = await Promise.all(outputs.map(async (output, index) => { const key = `output/${job.requesterId ?? "system"}/${job.id}/${index}-${output.name.replace(/[^a-zA-Z0-9._-]/g, "_")}`; const checksum = createHash("sha256").update(output.bytes).digest("base64"); const object = await storage.put({ key, bytes: output.bytes, contentType: output.mimeType, checksum }); return { output, object, checksum }; }));
    try {
      await db.$transaction(async (tx) => {
        const current = await tx.job.findUniqueOrThrow({ where: { id: job.id }, select: { outputFileId: true } });
        if (current.outputFileId) return;
        const outputDocument = await tx.document.create({ data: { userId: job.requesterId!, title: `${job.toolId} output` } }); const outputFileIds: string[] = [];
        for (const item of storedOutputs) { const outputFile = await tx.file.create({ data: { document: { connect: { id: outputDocument.id } }, originalName: item.output.name, mimeType: item.output.mimeType, size: BigInt(item.output.bytes.byteLength), storageKey: item.object.key, checksum: item.checksum, storageObject: { connectOrCreate: { where: { provider_bucket_objectKey: { provider: "s3", bucket: item.object.bucket, objectKey: item.object.key } }, create: { provider: "s3", bucket: item.object.bucket, objectKey: item.object.key, size: BigInt(item.output.bytes.byteLength), checksum: item.checksum } } } } }); await tx.fileVersion.create({ data: { fileId: outputFile.id, ownerId: job.requesterId!, version: 1, storageKey: item.object.key, checksum: item.checksum } }); outputFileIds.push(outputFile.id); }
        await tx.job.update({ where: { id: job.id }, data: { outputFileId: outputFileIds[0], status: "SUCCEEDED", result: { outputFileIds }, completedAt: new Date() } });
        if (step) await tx.jobStep.update({ where: { id: step.id }, data: { status: "SUCCEEDED", output: { outputFileIds }, completedAt: new Date() } });
        await tx.toolExecution.create({ data: { jobId: job.id, toolId: job.toolId, mode: "SERVER", input: { inputFileIds: ids }, output: { outputFileIds }, correlationId: job.correlationId, engine, engineVersion, durationMs: Date.now() - started } });
      });
    } catch (error) { throw error; }
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
