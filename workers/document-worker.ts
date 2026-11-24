import "../sentry.server.config";
import { Worker } from "bullmq";
import { AI_JOB_QUEUE_NAME, getQueueConnection, JOB_QUEUE_NAME, type QueuedJob } from "@/lib/queue";
import { getStorage } from "@/lib/storage";
import { logger } from "@/lib/logging";
import { executeAiGateway, AiGatewayError, type AiTool } from "@/lib/ai/gateway";
import { extractPdfTextServer, serializePdfPages } from "@/lib/pdf/text-server";
import { runtimeLimits, timeoutFor } from "@/lib/runtime/config";
import { withTimeout } from "@/lib/runtime/timeout";
import { recordMetric } from "@/lib/observability/metrics";
import { captureOperationalError } from "@/lib/observability/errors";
import { withTenant, withTenantScope } from "@/lib/db/tenant";
import { isAuthorizedFileStorageAccess } from "@/lib/storage/metadata";
import { isUnrecoverableAiQueueError, toAiQueueError } from "@/lib/ai/gateway/retry";
import { isUnrecoverableQueueError, toDocumentQueueError } from "@/lib/jobs/queue-errors";
import { classifyAttemptOutcome, retryTransitionTarget } from "@/lib/jobs/payload-lifecycle";
import { purgeFormFields } from "@/lib/pdf/form-payload";
import { processDocumentJob } from "@/lib/jobs/document-pipeline";

export const documentWorker = new Worker<QueuedJob>(JOB_QUEUE_NAME, async (message) => {
  recordMetric("queue_wait_ms", Math.max(0, Date.now() - message.timestamp), "ms", { tool_id: message.data.toolId, queue: "document" });
  // An infected output is deterministic, so it is escalated to an unrecoverable
  // queue error instead of burning the three configured attempts.
  // `attemptsMade` is BullMQ's count of attempts already started before this one;
  // the pipeline needs it to tell a retry (keep the encrypted payload) from a
  // final failure (purge it) — see FF-03 in `document-pipeline.ts`.
  try { return await processDocumentJob(message.data, { attemptsMade: message.attemptsMade, maxAttempts: message.opts.attempts ?? 1 }); } catch (error) { throw toDocumentQueueError(error); }
}, { connection: getQueueConnection(), concurrency: runtimeLimits.documentConcurrency, stalledInterval: runtimeLimits.stalledIntervalMs, maxStalledCount: runtimeLimits.maxStalledCount, lockDuration: Math.min(runtimeLimits.jobTimeoutMs, 10 * 60_000) });
/**
 * Destroy the encrypted payload of a job the queue has finished with.
 *
 * Best-effort and idempotent: the TTL is the backstop, but ordinary terminal
 * cleanup must not rely on it (FF-03).
 */
async function purgeTerminalPayload(message: QueuedJob) {
  if (!message.userId) return;
  await withTenant({ userId: message.userId }, async (tx) => {
    const job = await tx.job.findUnique({ where: { id: message.jobId }, select: { params: true } });
    const reference = (job as { params?: { fieldsRef?: string } } | null)?.params?.fieldsRef;
    if (reference) await purgeFormFields(reference).catch(() => undefined);
  }).catch(() => undefined);
}

async function advanceWorkflow(message: QueuedJob) { if (message.workflowRunId && message.userId) await (await import("@/lib/workflows/service")).advanceWorkflowRun(message.workflowRunId, message.userId); }
async function recordTerminalFailure(message: QueuedJob) {
  if (!message.userId) return;
  await withTenant({ userId: message.userId }, async (tx) => {
    const job = await tx.job.findUnique({ where: { id: message.jobId }, include: { toolExecutions: { select: { id: true } } } });
    if (!job || job.toolExecutions.length) return;
    const params = job.params as { inputFileIds?: string[] };
    await tx.toolExecution.create({ data: { jobId: job.id, toolId: job.toolId, mode: "SERVER", input: { inputFileIds: params.inputFileIds ?? [] }, correlationId: job.correlationId, errorCode: job.errorCode ?? "PROCESSING_FAILED", engine: "worker", engineVersion: "1" } });
  });
}
documentWorker.on("completed", (message) => { void advanceWorkflow(message.data).catch((error) => captureOperationalError(error, { worker: "workflow" })); });
documentWorker.on("failed", async (message, error) => {
  if (!message) return;
  // Unrecoverable errors are terminal on the first attempt: without this the job
  // would be parked in RETRYING with no retry ever scheduled.
  const outcome = classifyAttemptOutcome({
    attemptsMade: message.attemptsMade,
    maxAttempts: message.opts.attempts ?? 1,
    unrecoverable: isUnrecoverableQueueError(error),
  });
  if (!outcome.terminal) {
    recordMetric("retry_total", 1, "count", { tool_id: message.data.toolId, status: "retrying" });
    if (message.data.userId) {
      await withTenant({ userId: message.data.userId }, async (tx) => {
        const current = await tx.job.findUnique({ where: { id: message.data.jobId }, select: { status: true } });
        const target = current ? retryTransitionTarget((current as { status: string }).status) : undefined;
        // FF-03 / architect round 2: a retry must never revive a job another actor
        // already finished. `update()` here rewrote CANCELLED/EXPIRED/SUCCEEDED
        // rows back to RETRYING; the write is now guarded on the same status set
        // the decision was made from, so a concurrent terminal transition wins.
        if (target) {
          await tx.job.updateMany({
            where: { id: message.data.jobId, status: { in: ["QUEUED", "RUNNING", "RETRYING", "FAILED"] } },
            data: { status: target },
          });
        }
      });
    }
  } else {
    await recordTerminalFailure(message.data);
    // A terminal failure is the last moment this job will ever be seen by the
    // queue, so it is where the payload must go. Done here as well as in the
    // pipeline: an `UnrecoverableError` is raised *after* the pipeline already
    // recorded the failure, and the worker is the only actor that knows the queue
    // will not retry.
    await purgeTerminalPayload(message.data);
    await advanceWorkflow(message.data);
  }
});
documentWorker.on("stalled", () => recordMetric("stalled_jobs_total", 1, "count", { status: "stalled" }));
documentWorker.on("error", (error) => { captureOperationalError(error, { worker: "document" }); logger.error("worker.error", { error: error.message }); });

const aiTools = new Set<AiTool>(["summarize-pdf", "chat-with-pdf", "extract-data"]);

export async function processAiJob(message: QueuedJob, attemptNumber = 1) {
  if (!message.userId) throw Object.assign(new Error("AI worker job requires a tenant identity"), { code: "TENANT_CONTEXT_REQUIRED" });
  const tenant = <T>(operation: Parameters<typeof withTenant<T>>[1]) => withTenant({ userId: message.userId! }, operation);
  const job = await tenant((tx) => tx.job.findUnique({ where: { id: message.jobId }, include: { steps: true } }));
  if (!job) throw Object.assign(new Error("Job not found"), { code: "JOB_NOT_FOUND" });
  const correlationId = job.correlationId ?? message.correlationId;
  const context = { job_id: job.id, correlation_id: correlationId, tool_id: job.toolId, user_id: job.requesterId ?? "" };
  if (!aiTools.has(job.toolId as AiTool)) throw Object.assign(new Error("Tool is not enabled on the AI worker"), { code: "TOOL_NOT_AI_ENABLED" });
  if (job.status === "SUCCEEDED" && job.result) { logger.info("ai.job.idempotent_skip", context); return; }
  if (job.status === "CANCELLED" || job.status === "EXPIRED") return;
  const step = job.steps.find((item) => item.name === job.toolId); const started = Date.now();
  try {
    if (!job.requesterId || job.requesterId !== message.userId) throw Object.assign(new Error("AI jobs require a requester"), { code: "AI_REQUESTER_REQUIRED" });
    const aiExecutionScope = { userId: job.requesterId, organizationId: job.organizationId, apiClientId: job.apiClientId };
    await tenant((tx) => tx.job.update({ where: { id: job.id }, data: { status: "RUNNING", startedAt: job.startedAt ?? new Date(), error: undefined, errorCode: null } }));
    if (step) await tenant((tx) => tx.jobStep.update({ where: { id: step.id }, data: { status: "RUNNING", startedAt: step.startedAt ?? new Date(), error: undefined, errorCode: null } }));
    const params = job.params as { inputFileIds?: string[]; options?: Record<string, unknown> }; const ids = params.inputFileIds ?? [];
    if (ids.length !== 1) throw Object.assign(new Error("AI jobs require exactly one scoped document"), { code: "DOCUMENT_SCOPE_VIOLATION" });
    const file = await withTenantScope(aiExecutionScope, (tx) => tx.file.findUnique({ where: { id: ids[0] }, include: { document: true, storageObject: true } }));
    if (!file || !isAuthorizedFileStorageAccess(file, aiExecutionScope) || file.mimeType !== "application/pdf") throw Object.assign(new Error("The input is outside the document scope"), { code: "DOCUMENT_SCOPE_VIOLATION" });
    const requestedDocumentId = params.options?.documentId;
    if (requestedDocumentId !== undefined && requestedDocumentId !== file.documentId) throw Object.assign(new Error("The requested document does not match the job input"), { code: "DOCUMENT_SCOPE_VIOLATION" });
    const pages = await extractPdfTextServer(await getStorage().get(file.storageKey));
    const task = { toolId: job.toolId as AiTool, locale: params.options?.locale === "ar" ? "ar" as const : "en" as const, documentId: file.documentId, documentText: serializePdfPages(pages), pageCount: pages.length, question: typeof params.options?.question === "string" ? params.options.question : undefined };
    const gateway = await executeAiGateway(task, { jobId: job.id, correlationId, userId: job.requesterId, toolId: task.toolId });
    const result = { content: gateway.output.answer ?? JSON.stringify(gateway.output, null, 2), data: gateway.output, documentId: file.documentId };
    await tenant(async (tx) => {
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
    const metadata = error instanceof AiGatewayError ? error.metadata : {};
    const retryable = error instanceof AiGatewayError ? error.retryable : true;
    const failure = {
      message,
      retryable,
      attemptNumber,
      latencyMs: metadata.latencyMs ?? Date.now() - started,
      ...(metadata.provider ? { provider: metadata.provider } : {}),
      ...(metadata.model ? { model: metadata.model } : {}),
      ...(metadata.httpStatus === undefined ? {} : { httpStatus: metadata.httpStatus }),
      ...(metadata.providerCode ? { providerCode: metadata.providerCode } : {}),
      ...(metadata.providerStatus ? { providerStatus: metadata.providerStatus } : {}),
    };
    await tenant(async (tx) => {
      await tx.job.update({ where: { id: job.id }, data: { status: "FAILED", errorCode, error: failure, completedAt: new Date() } });
      if (step) await tx.jobStep.update({ where: { id: step.id }, data: { status: "FAILED", errorCode, error: failure, completedAt: new Date() } });
      await tx.toolExecution.create({ data: { jobId: job.id, toolId: job.toolId, mode: "AI", input: { inputFileId: job.inputFileId }, correlationId, errorCode, engine: metadata.provider ?? "ai-gateway", engineVersion: metadata.model ?? "1", durationMs: Date.now() - started } });
    });
    const failureLabels = { tool_id: job.toolId, provider: metadata.provider, model: metadata.model, status: "failed", error_code: errorCode, retryable };
    recordMetric("ai_provider_failures_total", 1, "count", failureLabels);
    recordMetric("ai_latency_ms", failure.latencyMs, "ms", failureLabels);
    logger.error("ai.job.failed", { ...context, error_code: errorCode, provider: metadata.provider, model: metadata.model, http_status: metadata.httpStatus, provider_code: metadata.providerCode, provider_status: metadata.providerStatus, retryable, attempt_number: attemptNumber, latency_ms: failure.latencyMs });
    throw error;
  }
}

export const aiWorker = new Worker<QueuedJob>(AI_JOB_QUEUE_NAME, async (message) => {
  recordMetric("queue_wait_ms", Math.max(0, Date.now() - message.timestamp), "ms", { tool_id: message.data.toolId, queue: "ai" });
  try { return await withTimeout(message.data.toolId, timeoutFor("ai") + 30_000, processAiJob(message.data, message.attemptsMade + 1)); }
  catch (error) { throw toAiQueueError(error); }
}, {
  connection: getQueueConnection(),
  concurrency: runtimeLimits.aiConcurrency,
  limiter: { max: runtimeLimits.aiRatePerMinute, duration: 60_000 },
  stalledInterval: runtimeLimits.stalledIntervalMs,
  maxStalledCount: runtimeLimits.maxStalledCount,
  lockDuration: Math.min(runtimeLimits.jobTimeoutMs, 10 * 60_000),
});
aiWorker.on("completed", (message) => { void advanceWorkflow(message.data).catch((error) => captureOperationalError(error, { worker: "workflow" })); });
aiWorker.on("failed", async (message, error) => {
  if (!message) return;
  const terminal = isUnrecoverableAiQueueError(error) || message.attemptsMade >= (message.opts.attempts ?? 1);
  if (!terminal) {
    recordMetric("retry_total", 1, "count", { tool_id: message.data.toolId, status: "retrying" });
    if (message.data.userId) await withTenant({ userId: message.data.userId }, (tx) => tx.job.update({ where: { id: message.data.jobId }, data: { status: "RETRYING" } }));
  } else await advanceWorkflow(message.data);
});
aiWorker.on("stalled", () => recordMetric("stalled_jobs_total", 1, "count", { status: "stalled" }));
aiWorker.on("error", (error) => { captureOperationalError(error, { worker: "ai" }); logger.error("ai.worker.error", { error: error.message }); });
