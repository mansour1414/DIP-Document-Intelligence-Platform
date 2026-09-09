import { Worker } from "bullmq";
import { createHash } from "crypto";
import { db } from "@/lib/db";
import { AI_JOB_QUEUE_NAME, getQueueConnection, JOB_QUEUE_NAME, type QueuedJob } from "@/lib/queue";
import { getStorage } from "@/lib/storage";
import { pdfWorkerEngine, runPdfWorkerTool, type PdfWorkerTool } from "@/lib/pdf/server";
import { processServerDocument, type ServerToolId } from "@/lib/document-processing/server";
import { logger } from "@/lib/logging";
import { executeAiGateway, AiGatewayError, type AiTool } from "@/lib/ai/gateway";
import { extractPdfTextServer, serializePdfPages } from "@/lib/pdf/text-server";

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
    const pdfTools = new Set(["merge-pdf", "split-pdf", "organize-pdf", "rotate-pdf", "delete-pages", "extract-pages", "jpg-to-pdf", "compress-pdf", "pdf-to-jpg", "watermark-pdf"]);
    const documentTools = new Set(["word-to-pdf", "pdf-to-word", "excel-to-pdf", "powerpoint-to-pdf", "ocr-pdf"]);
    let outputs: Array<{ name: string; mimeType: string; bytes: Uint8Array }>;
    if (pdfTools.has(job.toolId)) { const pdfTool = job.toolId as PdfWorkerTool; outputs = await runPdfWorkerTool(pdfTool, bytes, options); ({ engine, engineVersion } = pdfWorkerEngine(pdfTool)); }
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

const aiTools = new Set<AiTool>(["summarize-pdf", "chat-with-pdf", "extract-data"]);

export async function processAiJob(message: QueuedJob) {
  const job = await db.job.findUnique({ where: { id: message.jobId }, include: { steps: true } });
  if (!job) throw Object.assign(new Error("Job not found"), { code: "JOB_NOT_FOUND" });
  const correlationId = job.correlationId ?? message.correlationId;
  const context = { job_id: job.id, correlation_id: correlationId, tool_id: job.toolId, user_id: job.requesterId ?? "" };
  if (!aiTools.has(job.toolId as AiTool)) throw Object.assign(new Error("Tool is not enabled on the AI worker"), { code: "TOOL_NOT_AI_ENABLED" });
  if (job.status === "SUCCEEDED" && job.result) { logger.info("ai.job.idempotent_skip", context); return; }
  if (job.status === "CANCELLED" || job.status === "EXPIRED") return;
  const step = job.steps.find((item) => item.name === job.toolId); const started = Date.now();
  try {
    if (!job.requesterId) throw Object.assign(new Error("AI jobs require a requester"), { code: "AI_REQUESTER_REQUIRED" });
    await db.job.update({ where: { id: job.id }, data: { status: "RUNNING", startedAt: job.startedAt ?? new Date(), error: undefined, errorCode: null } });
    if (step) await db.jobStep.update({ where: { id: step.id }, data: { status: "RUNNING", startedAt: step.startedAt ?? new Date(), error: undefined, errorCode: null } });
    const params = job.params as { inputFileIds?: string[]; options?: Record<string, unknown> }; const ids = params.inputFileIds ?? [];
    if (ids.length !== 1) throw Object.assign(new Error("AI jobs require exactly one scoped document"), { code: "DOCUMENT_SCOPE_VIOLATION" });
    const file = await db.file.findUnique({ where: { id: ids[0] }, include: { document: true } });
    if (!file || file.document.userId !== job.requesterId || file.mimeType !== "application/pdf") throw Object.assign(new Error("The input is outside the document scope"), { code: "DOCUMENT_SCOPE_VIOLATION" });
    const requestedDocumentId = params.options?.documentId;
    if (requestedDocumentId !== undefined && requestedDocumentId !== file.documentId) throw Object.assign(new Error("The requested document does not match the job input"), { code: "DOCUMENT_SCOPE_VIOLATION" });
    const pages = await extractPdfTextServer(await getStorage().get(file.storageKey));
    const task = { toolId: job.toolId as AiTool, locale: params.options?.locale === "ar" ? "ar" as const : "en" as const, documentId: file.documentId, documentText: serializePdfPages(pages), pageCount: pages.length, question: typeof params.options?.question === "string" ? params.options.question : undefined };
    const gateway = await executeAiGateway(task, { jobId: job.id, correlationId, userId: job.requesterId, toolId: task.toolId });
    const result = { content: gateway.output.answer ?? JSON.stringify(gateway.output, null, 2), data: gateway.output, documentId: file.documentId };
    await db.$transaction(async (tx) => {
      const current = await tx.job.findUniqueOrThrow({ where: { id: job.id }, select: { status: true, result: true } });
      if (current.status === "SUCCEEDED" && current.result) return;
      await tx.job.update({ where: { id: job.id }, data: { status: "SUCCEEDED", result, engine: gateway.response.provider, engineVersion: gateway.response.model, completedAt: new Date() } });
      if (step) await tx.jobStep.update({ where: { id: step.id }, data: { status: "SUCCEEDED", output: result, engine: gateway.response.provider, engineVersion: gateway.response.model, completedAt: new Date() } });
      await tx.toolExecution.create({ data: { jobId: job.id, toolId: job.toolId, mode: "AI", input: { inputFileIds: ids, documentId: file.documentId }, output: result, correlationId, engine: gateway.response.provider, engineVersion: gateway.response.model, durationMs: Date.now() - started } });
    });
    logger.info("ai.job.succeeded", { ...context, provider: gateway.response.provider, model: gateway.response.model, input_tokens: gateway.response.inputTokens, output_tokens: gateway.response.outputTokens, latency_ms: gateway.response.latencyMs, estimated_cost: gateway.estimatedCost });
  } catch (error) {
    const errorCode = error instanceof AiGatewayError ? error.code : typeof error === "object" && error && "code" in error ? String(error.code) : "AI_PROCESSING_FAILED";
    const message = error instanceof Error ? error.message : "AI processing failed";
    await db.$transaction(async (tx) => {
      await tx.job.update({ where: { id: job.id }, data: { status: "FAILED", errorCode, error: { message }, completedAt: new Date() } });
      if (step) await tx.jobStep.update({ where: { id: step.id }, data: { status: "FAILED", errorCode, error: { message }, completedAt: new Date() } });
      await tx.toolExecution.create({ data: { jobId: job.id, toolId: job.toolId, mode: "AI", input: { inputFileId: job.inputFileId }, correlationId, errorCode, engine: "ai-gateway", engineVersion: "1", durationMs: Date.now() - started } });
    });
    logger.error("ai.job.failed", { ...context, error_code: errorCode });
    throw error;
  }
}

function boundedInteger(value: string | undefined, fallback: number, maximum: number) { const parsed = Number(value); return Number.isInteger(parsed) && parsed > 0 ? Math.min(parsed, maximum) : fallback; }
export const aiWorker = new Worker<QueuedJob>(AI_JOB_QUEUE_NAME, async (message) => processAiJob(message.data), {
  connection: getQueueConnection(),
  concurrency: boundedInteger(process.env.AI_WORKER_CONCURRENCY, 2, 8),
  limiter: { max: boundedInteger(process.env.AI_RATE_LIMIT_PER_MINUTE, 10, 1_000), duration: 60_000 },
  stalledInterval: 30_000,
  maxStalledCount: 1,
});
aiWorker.on("failed", async (message) => { if (message && message.attemptsMade < (message.opts.attempts ?? 1)) await db.job.update({ where: { id: message.data.jobId }, data: { status: "RETRYING" } }); });
aiWorker.on("error", (error) => logger.error("ai.worker.error", { error: error.message }));
