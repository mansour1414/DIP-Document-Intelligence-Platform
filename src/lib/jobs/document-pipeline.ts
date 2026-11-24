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
import { purgeFormFields, readFormFields } from "@/lib/pdf/form-payload";
import { jobErrorRecord, publicErrorCode } from "@/lib/jobs/error-boundary";
import { classifyAtProcessorEntry } from "@/lib/jobs/payload-lifecycle";
import { isUnrecoverableQueueError } from "@/lib/jobs/queue-errors";
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
  /**
   * BullMQ attempt accounting, passed by the worker so a terminal failure can be
   * told apart from one that will be retried (FF-03): the encrypted form payload
   * must survive a retry and be purged on the last attempt.
   */
  attemptsMade?: number;
  maxAttempts?: number;
};

/** Job states in which no attempt may (re)enter the pipeline. */
const CLOSED_JOB_STATES = ["SUCCEEDED", "CANCELLED", "EXPIRED"] as const;

/**
 * The job's id, typed explicitly.
 *
 * Prisma's row type degrades to `{}` when the generated client is unavailable, so
 * a direct `job.id` becomes a type error in that setup. Reading it through a
 * narrow view keeps the module type-clean in both environments.
 */
const jobIdOf = (job: unknown) => (job as { id: string }).id;

/** Narrow, explicit view of the loaded job row (see `jobIdOf`). */
type LoadedJob = {
  id: string;
  requesterId: string | null;
  organizationId: string | null;
  apiClientId: string | null;
  toolId: string;
  correlationId: string | null;
  status: string;
  startedAt: Date | null;
  outputFileId: string | null;
  params: unknown;
  steps: Array<{ id: string; name: string; status: string; startedAt: Date | null }>;
};
const asJob = (row: unknown) => row as unknown as LoadedJob;

/** Every state a job can never leave; a scrub is only safe once it is here. */
const TERMINAL_JOB_STATES = ["SUCCEEDED", "FAILED", "CANCELLED", "EXPIRED"] as const;

/**
 * Remove legacy plaintext `fields` from a job row (FF-03).
 *
 * Before the encrypted payload existed, values were written into `Job.params`
 * verbatim. Rows created then still exist, and they must not keep the caller's
 * data any longer than the job needs it. This scrubs such a row once it reaches a
 * terminal state.
 *
 * Written as a `updateMany` **guarded on the terminal states** rather than a
 * plain `update`: job state is never written unconditionally in this module (see
 * `test/pr1-output-screening.structure.test.ts`), and the guard also means a row
 * that is still live — and may still need its values — is left alone.
 */
/**
 * The JSON shape `Job.params` accepts.
 *
 * Declared structurally rather than as `Prisma.InputJsonValue` so this module does
 * not need the generated `Prisma` namespace just to describe its own payload — the
 * namespace import is unavailable whenever the client is not generated, and the
 * resulting error would be indistinguishable from a real one. The runtime check
 * above is what actually guarantees the value is JSON.
 */
type JobParamsJson = { [key: string]: string | number | boolean | null | JobParamsJson | Array<string | number | boolean | null | JobParamsJson> };

/**
 * Convert a plain object to that JSON shape.
 *
 * `Record<string, unknown>` is not assignable to `InputJsonValue` because `unknown`
 * admits `undefined`, functions and symbols — values JSON cannot represent. The
 * conversion is a round trip through `JSON`, which is what the column will do
 * anyway, and it is *checked* rather than asserted: the result is re-validated as
 * JSON before it is handed to Prisma. This is the contract change the CI failure
 * (`TS2322` at this line) was reporting; casting it away would have hidden a value
 * that Prisma would reject at runtime.
 */
function toJsonInput(value: Record<string, unknown>): JobParamsJson {
  const serialised = JSON.stringify(value);
  if (serialised === undefined) throw new Error("JSON_SERIALISATION_FAILED");
  const parsed: unknown = JSON.parse(serialised);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("JSON_SERIALISATION_FAILED");
  return parsed as JobParamsJson;
}

async function scrubLegacyFields(
  tenant: <T>(operation: Parameters<typeof withTenant<T>>[1]) => Promise<T>,
  jobId: string,
  params: Record<string, unknown> | undefined,
) {
  const { fields: _discarded, ...rest } = (params ?? {}) as Record<string, unknown>;
  void _discarded;
  await tenant((tx) => tx.job.updateMany({
    where: { id: jobId, status: { in: [...TERMINAL_JOB_STATES] } },
    data: { params: toJsonInput(rest) },
  })).catch(() => undefined);
}

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
  const rawParams = job.params as { inputFileIds?: string[]; options?: Record<string, unknown>; secretRef?: string; fieldsRef?: string; fields?: unknown };
  // Legacy rows created before FF-03 still carry plaintext `fields`. They are
  // readable for exactly one reason — an already-queued job must not fail on
  // deploy — and are scrubbed from the row on their next terminal transition.
  const legacyFields = rawParams.fields;
  if (job.status === "SUCCEEDED" || job.outputFileId) {
    // Duplicate delivery of a job whose output is already committed.
    //
    // The commit already happened, so there is nothing to write — but the payload
    // purge that follows a commit is *not* guaranteed to have run. The attempt that
    // committed may have crashed between the commit and the purge, and a queue
    // redelivery is the last moment anyone will look at this job. Cleanup is
    // therefore retried here rather than skipped; it is idempotent, so a redelivery
    // after a successful purge is a no-op.
    await purgeFormFields((job as { params?: { fieldsRef?: string } | null }).params?.fieldsRef)
      .catch(() => logger.warn("fill_forms.payload_purge_failed", { ...context, reason: "IDEMPOTENT_REDELIVERY" }));
    logger.info("job.idempotent_skip", context);
    return;
  }
  if (job.status === "CANCELLED" || job.status === "EXPIRED") { await Promise.all([deletePhase1Secret(rawParams.secretRef).catch(() => undefined), purgeFormFields(rawParams.fieldsRef).catch(() => undefined)]); return; }
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
      // FF-03: the values come from the encrypted payload, not from `params`.
      const fields = parseFieldsPayload(rawParams.fieldsRef
        ? await readFormFields({ reference: rawParams.fieldsRef, tenantId: asJob(job).requesterId ?? "", jobId: jobIdOf(job) })
        : legacyFields);
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
    // FF-03: the payload has served its purpose the moment the output is
    // committed. Purged here, after the commit, so a failed commit (which will
    // be retried) still has its values. Failure to purge is logged, not fatal:
    // the TTL backstop is the guarantee, this is the immediate path.
    await purgeFormFields(rawParams.fieldsRef).catch(() => logger.warn("fill_forms.payload_purge_failed", { ...context, reason: "SUCCESS" }));
    if (legacyFields !== undefined) await scrubLegacyFields(tenant, jobIdOf(job), rawParams as Record<string, unknown>);
    const durationMs = Date.now() - started;
    recordMetric("job_duration_ms", durationMs, "ms", { tool_id: job.toolId, engine, engine_version: engineVersion, status: "succeeded" });
    recordMetric("tool_execution_duration_ms", durationMs, "ms", { tool_id: job.toolId, engine, engine_version: engineVersion, status: "succeeded" });
    recordMetric("jobs_success_total", 1, "count", { tool_id: job.toolId, engine, engine_version: engineVersion, status: "succeeded" });
    const memoryClassMb = job.toolId === "ocr-pdf" ? 1024 : documentTools.has(job.toolId) ? 512 : 256;
    const estimatedCost = estimateJobCost({ cpuDurationMs: durationMs, memoryClassMb, storageBytes: validated.totalBytes, storageOperations: outputs.length, aiInputTokens: 0, aiOutputTokens: 0, ocrPages: job.toolId === "ocr-pdf" ? files[0]?.pageCount ?? 0 : 0, officeDurationMs: documentTools.has(job.toolId) && job.toolId !== "ocr-pdf" ? durationMs : 0, succeeded: true }, configuredCostRates());
    recordMetric("cost_per_successful_job", estimatedCost.costPerSuccessfulJob ?? 0, "ratio", { tool_id: job.toolId, engine, engine_version: engineVersion, status: "succeeded" });
    logger.info("job.succeeded", { ...context, engine, engine_version: engineVersion, duration_ms: durationMs, status: "succeeded" });
  } catch (error) {
    // FF-07 / architect round 2: only an allowlisted code is persisted. The raw
    // `error.message` used to be written into both `Job.error` and `JobStep.error`,
    // which made every native, Redis and parser message durable and user-visible.
    // The detail stays in the log line below, which is access-controlled.
    const errorCode = publicErrorCode(error);
    // A losing attempt must never fail a job that another attempt committed, and a
    // cancellation or expiry that arrived while the job was running must survive:
    // every terminal state is guarded, not just SUCCEEDED.
    const failed = await tenant((tx) => tx.job.updateMany({ where: { id: job.id, outputFileId: null, status: { notIn: [...CLOSED_JOB_STATES] } }, data: { status: "FAILED", errorCode, error: jobErrorRecord(error), completedAt: new Date() } }));
    // FF-03: a retry still needs the values, so the payload is only removed when
    // no further attempt can run.
    //
    // This runs on the **processor** side, where `attemptsMade` has not yet been
    // incremented for the current attempt (BullMQ increments inside
    // `moveToFailed`, after the handler throws). The classification therefore uses
    // the processor-entry frame. A previously declared `classifyTerminal` hook was
    // never passed by the worker and has been removed rather than left as dead
    // wiring: the worker classifies its own `failed` event separately, with the
    // post-increment counter, in `classifyFailedEvent`.
    const outcome = classifyAtProcessorEntry({
      attemptsMade: deps.attemptsMade ?? 0,
      maxAttempts: deps.maxAttempts ?? 1,
      unrecoverable: isUnrecoverableQueueError(error instanceof Error ? error : undefined),
    });
    if (outcome.terminal) await purgeFormFields(rawParams.fieldsRef).catch(() => logger.warn("fill_forms.payload_purge_failed", { ...context, reason: "FINAL_FAILURE" }));
    if (failed.count === 0) {
      // Either another attempt committed, the job was cancelled/expired mid-run, or
      // the row is gone (retention). All mean "do not write"; the log says which.
      const latest = await Promise.resolve(tenant((tx) => tx.job.findUnique({ where: { id: job.id }, select: { status: true, outputFileId: true } }))).catch(() => undefined);
      logger.warn(latest?.outputFileId ? "job.failure_suppressed" : "job.failure_not_recorded", { ...context, result: latest?.status ?? "MISSING" });
    }
    // The step may only follow the job: a terminal job's step is never rewritten,
    // and a terminal step is never revived.
    if (step && failed.count === 1) await tenant((tx) => tx.jobStep.updateMany({ where: { id: step.id, status: { notIn: [...CLOSED_JOB_STATES] } }, data: { status: "FAILED", errorCode, error: jobErrorRecord(error), completedAt: new Date() } }));
    recordMetric("jobs_failure_total", 1, "count", { tool_id: job.toolId, status: "failed" });
    logger.error("job.failed", { ...context, error_code: errorCode, status: "failed" }); throw error;
  } finally {
    await deletePhase1Secret(rawParams.secretRef).catch(() => undefined);
    // The encrypted payload is *not* deleted here: a `finally` cannot tell a
    // retryable failure from a final one, and deleting on a retry would break the
    // retry. Terminal paths purge it explicitly (success, CANCELLED/EXPIRED,
    // final failure); the TTL is the backstop for anything else.
    if (legacyFields !== undefined) {
      const state = await Promise.resolve(tenant((tx) => tx.job.findUnique({ where: { id: jobIdOf(job) }, select: { status: true } }))).catch(() => undefined);
      if (state && (TERMINAL_JOB_STATES as readonly string[]).includes(String((state as { status?: string }).status))) await scrubLegacyFields(tenant, jobIdOf(job), rawParams as Record<string, unknown>);
    }
  }
}
