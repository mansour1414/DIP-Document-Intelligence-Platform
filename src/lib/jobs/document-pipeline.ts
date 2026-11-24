import { randomUUID } from "node:crypto";
import type { PrismaClient } from "@prisma/client";
import { getStorage, type ObjectStorage } from "@/lib/storage";
import { pdfWorkerEngine, runPdfWorkerTool, type PdfWorkerTool } from "@/lib/pdf/server";
import { processServerDocument, type ServerToolId } from "@/lib/document-processing/server";
import { logger } from "@/lib/logging";
import { timeoutFor } from "@/lib/runtime/config";
import { withTimeout } from "@/lib/runtime/timeout";
import { validateWorkerOutputs } from "@/lib/outputs/validation";
import { OutputCommitSupersededError, discardStoredObjects, screenAndStoreWorkerOutputs } from "@/lib/outputs/screening";
import { recordMetric } from "@/lib/observability/metrics";
import { configuredCostRates, estimateJobCost } from "@/lib/cost/model";
import { withTenant, withTenantScope } from "@/lib/db/tenant";
import { buildStorageObjectConnectOrCreate, isAuthorizedFileStorageAccess } from "@/lib/storage/metadata";
import type { QueuedJob } from "@/lib/queue";
import { validateToolOptions } from "@/lib/tools/options";
import { deletePhase1Secret, takePhase1Secret, type Phase1SecretPurpose } from "@/lib/secrets/phase1";
import { APPROVED_QPDF_VERSION, runQpdfTool } from "@/lib/pdf/qpdf";
import { FORM_ENGINE, FORM_ENGINE_VERSION, fillFormPdf } from "@/lib/pdf/form-fill";
import { parseFieldsPayload } from "@/lib/pdf/form-schema";
import type { MalwareScanner } from "@/lib/malware";

/**
 * PR-1 moved the document job body out of `workers/document-worker.ts` so the
 * pipeline can be exercised against real Postgres, object storage and clamd
 * without instantiating a BullMQ worker and its Redis connection. Behaviour is
 * unchanged apart from three deliberate additions:
 *   1. generated outputs are screened before the first object write,
 *   2. a failed metadata write deletes the objects it orphaned, and
 *   3. concurrent attempts of the same job are serialised at commit time.
 *
 * PR-1a (concurrency safety) closes the last gap from the PR #25 review. Two
 * attempts of one job can overlap (BullMQ stalled-job recovery) so:
 *   - every attempt writes to its own key prefix (`output/<user>/<job>/<attempt>/…`)
 *     and may only delete objects it wrote and that no committed row references,
 *   - the RUNNING transition and the SUCCEEDED commit are compare-and-set
 *     `updateMany` calls guarded on `outputFileId IS NULL`, so exactly one attempt
 *     can publish, and
 *   - the FAILED and step writes refuse to overwrite a job another attempt has
 *     already committed.
 */
export type DocumentPipelineDeps = {
  /** Test seams. Production resolves the configured S3 adapter and clamd scanner. */
  storage?: ObjectStorage;
  scanner?: MalwareScanner;
  client?: PrismaClient;
  /** Test seam only: pins the attempt id that scopes output keys. Production uses a fresh uuid. */
  attemptId?: string;
};

/** Job states in which no attempt may (re)enter the pipeline. */
const CLOSED_JOB_STATES = ["SUCCEEDED", "CANCELLED", "EXPIRED"] as const;

export async function processDocumentJob(message: QueuedJob, deps: DocumentPipelineDeps = {}) {
  if (!message.userId) throw Object.assign(new Error("Worker job requires a tenant identity"), { code: "TENANT_CONTEXT_REQUIRED" });
  const tenant = <T>(operation: Parameters<typeof withTenant<T>>[1]) => withTenant({ userId: message.userId! }, operation, deps.client);
  const job = await tenant((tx) => tx.job.findUnique({ where: { id: message.jobId }, include: { steps: true } }));
  if (!job) throw new Error("JOB_NOT_FOUND");
  if (!job.requesterId || job.requesterId !== message.userId) throw Object.assign(new Error("Worker job requires a persisted requester identity"), { code: "TENANT_CONTEXT_REQUIRED" });
  const jobExecutionScope = { userId: job.requesterId, organizationId: job.organizationId, apiClientId: job.apiClientId };
  const scopedTenant = <T>(operation: Parameters<typeof withTenantScope<T>>[1]) => withTenantScope(jobExecutionScope, operation, deps.client);
  const attemptId = deps.attemptId ?? randomUUID();
  const context = { job_id: job.id, correlation_id: job.correlationId ?? message.correlationId, tool_id: job.toolId, attempt_id: attemptId };
  const rawParams = job.params as { inputFileIds?: string[]; options?: Record<string, unknown>; secretRef?: string; fields?: unknown };
  if (job.status === "SUCCEEDED" || job.outputFileId) { logger.info("job.idempotent_skip", context); return; }
  if (job.status === "CANCELLED" || job.status === "EXPIRED") { await deletePhase1Secret(rawParams.secretRef).catch(() => undefined); return; }
  const step = job.steps.find((item) => item.name === job.toolId);
  try {
    // Atomic run claim: the fast idempotency read above is not enough on its own,
    // because a duplicate attempt can be between its read and this write when the
    // winner commits. A compare-and-set on `outputFileId IS NULL` plus a closed
    // terminal state makes that window harmless instead of a status rollback.
    const claim = await tenant((tx) => tx.job.updateMany({
      where: { id: job.id, outputFileId: null, status: { notIn: [...CLOSED_JOB_STATES] } },
      data: { status: "RUNNING", startedAt: job.startedAt ?? new Date(), error: undefined, errorCode: null },
    }));
    if (claim.count === 0) {
      const latest = await tenant((tx) => tx.job.findUnique({ where: { id: job.id }, select: { status: true, outputFileId: true } }));
      if (latest?.outputFileId || latest?.status === "SUCCEEDED") logger.info("job.idempotent_skip", context);
      else logger.info("job.terminal_skip", { ...context, result: latest?.status ?? "MISSING" });
      return;
    }
    if (step) await tenant((tx) => tx.jobStep.updateMany({ where: { id: step.id, status: { notIn: [...CLOSED_JOB_STATES] } }, data: { status: "RUNNING", startedAt: new Date() } }));
    const params = rawParams; const ids = params.inputFileIds;
    if (!ids?.length) throw Object.assign(new Error("Unsupported job payload"), { code: "INVALID_JOB_INPUT" });
    const files = await scopedTenant((tx) => tx.file.findMany({ where: { id: { in: ids } }, include: { document: true, storageObject: true } }));
    if (files.length !== ids.length || files.some((file) => !isAuthorizedFileStorageAccess(file, jobExecutionScope))) {
      throw Object.assign(new Error("Input file is missing"), { code: "INPUT_NOT_FOUND" });
    }
    const inputById = new Map(files.map((file) => [file.id, file]));
    const storage = deps.storage ?? getStorage();
    const bytes = await Promise.all(ids.map((id) => storage.get(inputById.get(id)!.storageKey))); const options: Record<string, unknown> = { ...validateToolOptions(job.toolId, params.options ?? {}), inputMimeTypes: ids.map((id) => inputById.get(id)!.mimeType) };
    const started = Date.now(); let engine = "pdf-lib"; let engineVersion = "1.17.1";
    const pdfTools = new Set(["merge-pdf", "split-pdf", "organize-pdf", "rotate-pdf", "delete-pages", "extract-pages", "jpg-to-pdf", "compress-pdf", "pdf-to-jpg", "watermark-pdf", "crop-pdf", "page-numbers", "header-footer", "resize-pages", "alternate-mix", "flip-pages", "split-pdf-by-size", "split-pdf-by-bookmarks", "split-pdf-by-text", "n-up-pdf", "remove-annotations", "extract-images"]);
    const qpdfTools = new Set(["protect-pdf", "unlock-pdf", "pdf-permissions", "repair-pdf"]);
    const documentTools = new Set(["word-to-pdf", "pdf-to-word", "excel-to-pdf", "powerpoint-to-pdf", "ocr-pdf"]);
    let outputs: Array<{ name: string; mimeType: string; bytes: Uint8Array }>;
    if (pdfTools.has(job.toolId)) { const pdfTool = job.toolId as PdfWorkerTool; outputs = await withTimeout(job.toolId, timeoutFor("pdf"), runPdfWorkerTool(pdfTool, bytes, options)); ({ engine, engineVersion } = pdfWorkerEngine(pdfTool)); }
    else if (job.toolId === "fill-forms") {
      // `fields` is a dedicated job parameter, validated here with the same
      // schema module the browser uses. Options remain flat and versioned.
      if (ids.length !== 1) throw Object.assign(new Error("Fill PDF Forms accepts exactly one PDF."), { code: "INPUT_FILE_COUNT_INVALID" });
      const fields = parseFieldsPayload(rawParams.fields);
      const filled = await withTimeout(job.toolId, timeoutFor("pdf"), fillFormPdf(bytes[0], fields, { flatten: options.flatten === true }));
      outputs = [{ name: filled.name, mimeType: filled.mimeType, bytes: filled.bytes }];
      engine = FORM_ENGINE; engineVersion = FORM_ENGINE_VERSION;
      logger.info("fill_forms.succeeded", { ...context, engine, engine_version: engineVersion, filled_fields: filled.report.filled.length, untouched_fields: filled.report.untouched, raster_appearances: filled.report.rasterAppearances.length, flatten: filled.report.flatten, status: "succeeded" });
    }
    else if (qpdfTools.has(job.toolId)) { const secret = params.secretRef ? await takePhase1Secret({ reference: params.secretRef, tenantId: message.userId, jobId: job.id, purpose: job.toolId as Phase1SecretPurpose }) : undefined; outputs = [await withTimeout(job.toolId, timeoutFor("pdf"), runQpdfTool(job.toolId as "protect-pdf" | "unlock-pdf" | "pdf-permissions" | "repair-pdf", bytes[0], options, secret))]; engine = "qpdf"; engineVersion = APPROVED_QPDF_VERSION; }
    else if (documentTools.has(job.toolId)) { const input = inputById.get(ids[0])!; const result = await processServerDocument(job.toolId as ServerToolId, new File([bytes[0] as BlobPart], input.originalName, { type: input.mimeType }), typeof options.language === "string" ? options.language : "ara+eng"); outputs = [{ name: result.filename, mimeType: result.contentType, bytes: result.bytes }]; engine = job.toolId === "ocr-pdf" ? "ocrmypdf" : "libreoffice"; engineVersion = "host"; }
    else throw Object.assign(new Error("Tool is not enabled on this worker"), { code: "TOOL_NOT_WORKER_ENABLED" });
    const preservePages = ["compress-pdf", "rotate-pdf", "watermark-pdf", "crop-pdf", "page-numbers", "header-footer", "fill-forms", "resize-pages", "flip-pages", "remove-annotations", "ocr-pdf"].includes(job.toolId) ? files[0]?.pageCount ?? undefined : undefined;
    const validated = await validateWorkerOutputs(outputs, preservePages, { encryptedPdfAlreadyValidated: job.toolId === "protect-pdf" || job.toolId === "pdf-permissions" });
    recordMetric("storage_bytes_out", validated.totalBytes, "bytes", { tool_id: job.toolId, engine, engine_version: engineVersion, status: "succeeded" });
    if (job.toolId === "compress-pdf") recordMetric("compression_ratio", validated.totalBytes / bytes[0].byteLength, "ratio", { tool_id: job.toolId, engine, engine_version: engineVersion });
    // PR-1: every output is scanned first, then the batch is stored. A rejection
    // throws before the first object write, so no object, file row or SUCCEEDED
    // status can exist for a batch that was not explicitly declared clean.
    const { stored: storedOutputs } = await screenAndStoreWorkerOutputs(outputs, { job, storage, scanner: deps.scanner, attemptId });
    try {
      await scopedTenant(async (tx) => {
        const current = await tx.job.findUniqueOrThrow({ where: { id: job.id }, select: { outputFileId: true } });
        if (current.outputFileId) throw new OutputCommitSupersededError();
        const outputDocument = await tx.document.create({ data: { userId: jobExecutionScope.userId, organizationId: jobExecutionScope.organizationId, title: `${job.toolId} output` } }); const outputFileIds: string[] = [];
        for (const item of storedOutputs) { const outputFile = await tx.file.create({ data: { document: { connect: { id: outputDocument.id } }, originalName: item.output.name, mimeType: item.output.mimeType, size: BigInt(item.output.bytes.byteLength), storageKey: item.object.key, checksum: item.checksum, storageObject: buildStorageObjectConnectOrCreate(jobExecutionScope, { provider: "s3", bucket: item.object.bucket, objectKey: item.object.key, size: BigInt(item.output.bytes.byteLength), checksum: item.checksum }) } }); await tx.fileVersion.create({ data: { fileId: outputFile.id, ownerId: jobExecutionScope.userId, version: 1, storageKey: item.object.key, checksum: item.checksum } }); outputFileIds.push(outputFile.id); }
        // The commit itself is the compare-and-set. Under READ COMMITTED a second
        // attempt blocks on this row, re-evaluates `outputFileId IS NULL` after the
        // winner commits, matches nothing, and rolls its own rows back — so exactly
        // one attempt can ever publish and duplicate metadata is impossible.
        const commit = await tx.job.updateMany({ where: { id: job.id, outputFileId: null, status: { notIn: [...CLOSED_JOB_STATES] } }, data: { outputFileId: outputFileIds[0], status: "SUCCEEDED", result: { outputFileIds }, errorCode: null, completedAt: new Date() } });
        if (commit.count !== 1) throw new OutputCommitSupersededError();
        if (step) await tx.jobStep.updateMany({ where: { id: step.id, status: { notIn: [...CLOSED_JOB_STATES] } }, data: { status: "SUCCEEDED", output: { outputFileIds }, completedAt: new Date() } });
        await tx.toolExecution.create({ data: { jobId: job.id, toolId: job.toolId, mode: "SERVER", input: { inputFileIds: ids }, output: { outputFileIds }, correlationId: job.correlationId, engine, engineVersion, durationMs: Date.now() - started } });
      });
    } catch (error) {
      // The metadata transaction rolled back, so these objects reference no file
      // row. Deleting them keeps a retry from accumulating orphaned outputs — but
      // only the ones this attempt wrote *and* that no committed row points at, so
      // a committed output is never deleted. If ownership cannot be verified, the
      // objects are left in place: an orphan is recoverable, a deleted output is not.
      const keys = storedOutputs.map((item) => item.object.key);
      let referenced: Set<string> | undefined;
      try {
        referenced = new Set((await scopedTenant((tx) => tx.file.findMany({ where: { storageKey: { in: keys } }, select: { storageKey: true } }))).map((row) => row.storageKey));
      } catch {
        logger.error("worker.output_cleanup_unverified", { error_code: "OWNERSHIP_UNKNOWN" });
      }
      if (referenced) { const owned = referenced; await discardStoredObjects(storage, keys, { isReferenced: async (key) => owned.has(key) }); }
      if (error instanceof OutputCommitSupersededError) { logger.info("job.output_commit_superseded", context); return; }
      throw error;
    }
    const durationMs = Date.now() - started;
    recordMetric("job_duration_ms", durationMs, "ms", { tool_id: job.toolId, engine, engine_version: engineVersion, status: "succeeded" });
    recordMetric("tool_execution_duration_ms", durationMs, "ms", { tool_id: job.toolId, engine, engine_version: engineVersion, status: "succeeded" });
    recordMetric("jobs_success_total", 1, "count", { tool_id: job.toolId, engine, engine_version: engineVersion, status: "succeeded" });
    const memoryClassMb = job.toolId === "ocr-pdf" ? 1024 : documentTools.has(job.toolId) ? 512 : 256;
    const estimatedCost = estimateJobCost({ cpuDurationMs: durationMs, memoryClassMb, storageBytes: validated.totalBytes, storageOperations: outputs.length, aiInputTokens: 0, aiOutputTokens: 0, ocrPages: job.toolId === "ocr-pdf" ? files[0]?.pageCount ?? 0 : 0, officeDurationMs: documentTools.has(job.toolId) && job.toolId !== "ocr-pdf" ? durationMs : 0, succeeded: true }, configuredCostRates());
    recordMetric("cost_per_successful_job", estimatedCost.costPerSuccessfulJob ?? 0, "ratio", { tool_id: job.toolId, engine, engine_version: engineVersion, status: "succeeded" });
    logger.info("job.succeeded", { ...context, engine, engine_version: engineVersion, duration_ms: durationMs, status: "succeeded" });
  } catch (error) {
    const errorCode = typeof error === "object" && error && "code" in error ? String(error.code) : "PROCESSING_FAILED";
    // A losing attempt must never fail a job that another attempt committed, and a
    // cancellation or expiry that arrived while the job was running must survive:
    // every terminal state is guarded, not just SUCCEEDED.
    const failed = await tenant((tx) => tx.job.updateMany({ where: { id: job.id, outputFileId: null, status: { notIn: [...CLOSED_JOB_STATES] } }, data: { status: "FAILED", errorCode, error: { message: error instanceof Error ? error.message : "Processing failed" }, completedAt: new Date() } }));
    if (failed.count === 0) {
      // Either another attempt committed, the job was cancelled/expired mid-run, or
      // the row is gone (retention). All mean "do not write"; the log says which.
      const latest = await Promise.resolve(tenant((tx) => tx.job.findUnique({ where: { id: job.id }, select: { status: true, outputFileId: true } }))).catch(() => undefined);
      logger.warn(latest?.outputFileId ? "job.failure_suppressed" : "job.failure_not_recorded", { ...context, result: latest?.status ?? "MISSING" });
    }
    // The step may only follow the job: a terminal job's step is never rewritten,
    // and a terminal step is never revived.
    if (step && failed.count === 1) await tenant((tx) => tx.jobStep.updateMany({ where: { id: step.id, status: { notIn: [...CLOSED_JOB_STATES] } }, data: { status: "FAILED", errorCode, error: { message: error instanceof Error ? error.message : "Processing failed" }, completedAt: new Date() } }));
    recordMetric("jobs_failure_total", 1, "count", { tool_id: job.toolId, status: "failed" });
    logger.error("job.failed", { ...context, error_code: errorCode, status: "failed" }); throw error;
  } finally { await deletePhase1Secret(rawParams.secretRef).catch(() => undefined); }
}
