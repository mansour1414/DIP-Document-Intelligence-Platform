import { randomUUID } from "crypto";
import { enqueueAiJob, enqueueJob } from "@/lib/queue";
import { getStorage } from "@/lib/storage";
import { controlledPreflightToolIds, getToolDefinition } from "@/lib/tools/registry";
import { validateUpload } from "@/lib/uploads/validation";
import { logger } from "@/lib/logging";
import { enforceJobCreation } from "@/lib/usage/enforcement";
import { measure, recordMetric } from "@/lib/observability/metrics";
import { withTenant, withTenantScope } from "@/lib/db/tenant";
import { buildStorageObjectConnectOrCreate, isAuthorizedFileStorageAccess } from "@/lib/storage/metadata";
import { requireCleanUpload } from "@/lib/malware";
import { requiresDedicatedJobParameters, validateToolOptions } from "@/lib/tools/options";
import { deletePhase1Secret, enforceUnlockRateLimit, phase1SecretToolIds, putPhase1Secret, type Phase1SecretPayload, type Phase1SecretPurpose } from "@/lib/secrets/phase1";
import { parseFieldsPayload } from "@/lib/pdf/form-schema";
import { assertCheapPdfShape } from "@/lib/pdf/form-inspection";
import { purgeFormFields, putFormFields } from "@/lib/pdf/form-payload";
import { formWorkerLimits, processPdfBounded } from "@/lib/pdf/form-worker";
import { FormFillError } from "@/lib/pdf/form-validation";
import { FORM_ERROR_MESSAGES, isFormFillErrorCode } from "@/lib/pdf/form-types";
import { runtimeLimits } from "@/lib/runtime/config";

type Upload = { filename: string; mimeType: string; bytes: Uint8Array };

/**
 * Restriction preflight for `fill-forms` (FF-06).
 *
 * Uses the same renderer-free inspection path as the browser-facing route, so
 * the API and the worker cannot disagree about what "restricted" means. The
 * error is a `FormFillError`, which the route already maps to a coded 422 with
 * an allowlisted, content-free message.
 */
/**
 * Submission preflight (P3).
 *
 * This previously called `inspectFormPdf` **in-process**, so the submission path
 * parsed the PDF on the web server's main thread while the inspect endpoint parsed
 * it in a bounded child — two different authorities, one of them unbounded, for the
 * same decision. It now goes through `processPdfBounded`, which runs the identical
 * restriction logic (`assertCheapPdfShape` → structural walk →
 * `assertFillableRestrictions` → inventory) in the child, with the deadline, heap
 * cap and minimal environment that the route already relies on.
 */
async function assertFillableInput(bytes: Uint8Array): Promise<number> {
  const result = await processPdfBounded(bytes, formWorkerLimits({ timeoutMs: runtimeLimits.formWorkerTimeoutMs, maxHeapMb: runtimeLimits.formWorkerMaxHeapMb, concurrency: runtimeLimits.formWorkerConcurrency }));
  // The child's verdict is data, and data from a subprocess is not trusted: a
  // malformed reply is a boundary failure, never an implicit "the document is fine".
  if (!result.ok) {
    // Validated, not trusted: an unrecognised code from the child collapses to a
    // generic refusal instead of being forwarded verbatim.
    if (!isFormFillErrorCode(result.code)) throw new FormFillError("FORM_UNSUPPORTED", FORM_ERROR_MESSAGES.FORM_UNSUPPORTED, { boundary: "INVALID_CODE" });
    const details = result.details && typeof result.details === "object" && !Array.isArray(result.details) ? (result.details as Record<string, unknown>) : undefined;
    throw new FormFillError(result.code, FORM_ERROR_MESSAGES[result.code] ?? FORM_ERROR_MESSAGES.FORM_UNSUPPORTED, details);
  }
  if (!result.inventory || !Array.isArray((result.inventory as { fields?: unknown }).fields)) {
    throw new FormFillError("FORM_UNSUPPORTED", FORM_ERROR_MESSAGES.FORM_UNSUPPORTED, { boundary: "INVALID_INVENTORY" });
  }
  // `processPdfBounded` has already rejected a non-integer or negative `pages`, so
  // this is the document's authoritative page count: it is what plan enforcement and
  // the file row receive. It is never taken from the client or from a page-marker
  // estimate.
  return result.pages;
}
function minimumFilesFor(toolId: string) { return ["merge-pdf", "alternate-mix"].includes(toolId) ? 2 : 1; }
export async function createToolJob(input: { userId: string; toolId: string; uploads: Upload[]; options?: Record<string, string | number | boolean>; fields?: Record<string, unknown>; secrets?: Phase1SecretPayload; idempotencyKey: string; correlationId?: string; organizationId?: string; apiClientId?: string }) {
  const apiStarted = performance.now();
  const tool = getToolDefinition(input.toolId);
  const options = validateToolOptions(tool.toolId, input.options ?? {});
  // Tools with a typed per-item payload validate its *shape* before any upload
  // is read, scanned or stored, so a malformed request costs nothing and never
  // reaches the worker. Semantic validation against the actual form happens in
  // the worker, where the PDF is available.
  if (requiresDedicatedJobParameters(tool.toolId) !== (input.fields !== undefined)) {
    throw Object.assign(new Error(requiresDedicatedJobParameters(tool.toolId) ? "Form field values are required for this tool." : "Form field values are not accepted by this tool."), { code: "FIELDS_INPUT_INVALID" });
  }
  const fields = input.fields === undefined ? undefined : parseFieldsPayload(input.fields);
  const minimumFiles = minimumFilesFor(input.toolId);
  if (input.uploads.length < minimumFiles || input.uploads.length > tool.limits.maxFiles) throw new Error("INPUT_FILE_COUNT_INVALID");
  if (input.uploads.reduce((total, upload) => total + upload.bytes.byteLength, 0) > tool.limits.maxBytes) throw new Error("TOTAL_SIZE_LIMIT_EXCEEDED");
  const correlationId = input.correlationId ?? randomUUID();
  const executionScope = { userId: input.userId, organizationId: input.organizationId, apiClientId: input.apiClientId };
  const existing = await measure("db_job_idempotency_query", { tool_id: tool.toolId }, () => withTenantScope(executionScope, (tx) => tx.job.findUnique({ where: { toolId_idempotencyKey: { toolId: tool.toolId, idempotencyKey: input.idempotencyKey } }, select: { id: true, status: true } })));
  if (existing) return { ...existing, reused: true };
  if (phase1SecretToolIds.has(tool.toolId) !== Boolean(input.secrets)) throw Object.assign(new Error("Secure secret input does not match this tool."), { code: "SECRET_INPUT_INVALID" });
  if (tool.toolId === "unlock-pdf") await enforceUnlockRateLimit(input.userId);
  const storage = getStorage();
  // P3: screening precedes complex parsing. `validateUpload` parses the PDF with
  // pdf-lib to count pages, so running it first meant an unscanned document was
  // handed to a parser. Cheap, parser-free checks and the malware gate now run
  // first; only a clean, plausibly-shaped file reaches `validateUpload`.
  const screened = await Promise.all(input.uploads.map(async (upload) => {
    // Parser-free shape checks apply only to documents declared as PDF; other
    // accepted formats go straight to screening.
    //
    // The check is a *substitute* for the generic parse that follows, not an extra
    // gate in front of it, so it must be scoped exactly as broadly as that parse is.
    // `validateUpload` deliberately does not parse for the controlled-preflight tools
    // (Repair PDF and Unlock PDF), because a document they are meant to accept — a
    // damaged or undecryptable one — would fail a shape check for precisely the
    // reason the tool exists. Applying `assertCheapPdfShape` to them anyway leaked a
    // Fill Forms verdict into unrelated tools: a truncated PDF handed to Repair PDF
    // was refused with `FORM_UNSUPPORTED` instead of being repaired. The predicate is
    // therefore the same one `validateUpload` uses, imported rather than restated.
    const looksPdf = upload.mimeType === "application/pdf" || upload.filename.toLowerCase().endsWith(".pdf");
    if (looksPdf && !controlledPreflightToolIds.has(tool.toolId)) assertCheapPdfShape(upload.bytes);
    const malwareScan = await requireCleanUpload(upload.bytes);
    return { upload, malwareScan };
  }));
  // B31-01: Fill Forms must not parse in this process. Its structural verdict and
  // page count come from the bounded child, and the child must run *before*
  // `validateUpload` — otherwise the generic parse happens first and the isolation is
  // decorative, which is exactly what the review found. Malware screening above still
  // precedes it, so no document reaches the inspector unscanned. This runs once per
  // job for a single-file tool, so the document is inspected exactly once.
  const inspectionPages = tool.toolId === "fill-forms" ? await assertFillableInput(screened[0].upload.bytes) : undefined;
  const prepared = await Promise.all(screened.map(async ({ upload, malwareScan }) => ({
    upload,
    malwareScan,
    validation: await validateUpload({ toolId: tool.toolId, declaredMime: upload.mimeType, bytes: upload.bytes, inspectionPages }),
  })));
  // FF-06 / B31-01: prove the document is fillable *before* billing, storage and
  // the queue, and do it in the bounded child rather than in this process. A
  // restricted input previously still created a document, file and file-version row,
  // a job row and a billing attempt, and only then failed in the worker — leaving
  // durable artifacts and a charge for work that could never succeed.
  //
  // Ordering is fixed and deliberate: `requireCleanUpload` (above) → isolated
  // inspection (above) → this. Screening is never skipped or reordered ahead of the
  // malware gate, and no charge is attempted until a page count exists. The worker
  // keeps its own recheck: these bytes are screened and inspected here, but the
  // worker re-reads them from storage and must not trust the API's decision.
  const monetization = await enforceJobCreation({ userId: input.userId, toolId: tool.toolId, idempotencyKey: input.idempotencyKey, correlationId, options, files: prepared.map(({upload,validation})=>({size:upload.bytes.byteLength,pageCount:validation.pageCount})) });
  const stored: Array<{ key: string; bucket: string; upload: Upload; validation: Awaited<ReturnType<typeof validateUpload>> }> = [];
  let secretRef: string | undefined;
  let fieldsRef: string | undefined;
  // Set once the job row and its files are committed. Cleanup decisions depend on
  // it: a charge may only be released, and stored inputs may only be deleted, when
  // no job row exists to reference them.
  let committedJobId: string | undefined;
  try {
    for (const item of prepared) { const key = storage.createUploadKey({ userId: input.userId, filename: item.upload.filename }); const object = await storage.put({ key, bytes: item.upload.bytes, contentType: item.validation.mimeType, checksum: item.validation.checksum }); stored.push({ key: object.key, bucket: object.bucket, upload: item.upload, validation: item.validation }); }
    const jobId = randomUUID();
    if (input.secrets) secretRef = await putPhase1Secret({ tenantId: input.userId, jobId, purpose: tool.toolId as Phase1SecretPurpose, payload: input.secrets });
    // FF-03: submitted values are encrypted under a tenant+job-bound reference.
    // `Job.params` receives the opaque reference, never the values, so no
    // terminal state (SUCCEEDED/FAILED/CANCELLED/EXPIRED) can leave them in a
    // durable JSON column. The reference is created after the job id exists so
    // it can be bound into the envelope's AAD.
    if (fields) fieldsRef = await putFormFields({ tenantId: input.userId, jobId, fields });
    const job = await withTenantScope(executionScope, async (tx) => {
      const document = await tx.document.create({ data: { userId: input.userId, organizationId: input.organizationId, title: `${tool.name} input` } });
      const files = await Promise.all(stored.map(async (item) => { const file = await tx.file.create({ data: { document: { connect: { id: document.id } }, originalName: item.upload.filename.slice(0, 255), mimeType: item.validation.mimeType, size: BigInt(item.upload.bytes.byteLength), storageKey: item.key, checksum: item.validation.checksum, pageCount: item.validation.pageCount, storageObject: buildStorageObjectConnectOrCreate(executionScope, { provider: "s3", bucket: item.bucket, objectKey: item.key, size: BigInt(item.upload.bytes.byteLength), checksum: item.validation.checksum }) } }); await tx.fileVersion.create({ data: { fileId: file.id, ownerId: input.userId, version: 1, storageKey: item.key, checksum: item.validation.checksum } }); return file; }));
      return tx.job.create({ data: { id: jobId, toolId: tool.toolId, idempotencyKey: input.idempotencyKey, requesterId: input.userId, organizationId: input.organizationId, apiClientId: input.apiClientId, inputFileId: files[0].id, status: "QUEUED", params: { inputFileIds: files.map((file) => file.id), options, ...(fieldsRef ? { fieldsRef } : {}), ...(secretRef ? { secretRef } : {}) }, correlationId, steps: { create: { name: tool.toolId, idempotencyKey: `${input.idempotencyKey}:${tool.toolId}`, status: "QUEUED", correlationId } } }, select: { id: true, status: true } });
    });
    committedJobId = job.id;
    const queuedJob = { jobId: job.id, toolId: tool.toolId, idempotencyKey: input.idempotencyKey, correlationId, userId: input.userId };
    const queueOptions = { priority: monetization.plan.entitlements.processingPriority === "high" ? 1 : 5, ...(secretRef ? { attempts: 1 } : {}) };
    if (tool.aiFlag) await enqueueAiJob(queuedJob, queueOptions); else await enqueueJob(queuedJob, queueOptions);
    logger.info("job.queued", { job_id: job.id, correlation_id: correlationId, tool_id: tool.toolId });
    recordMetric("api_job_creation_latency_ms", performance.now() - apiStarted, "ms", { tool_id: tool.toolId });
    recordMetric("jobs_total", 1, "count", { tool_id: tool.toolId });
    return { ...job, reused: false };
  } catch (error) {
    // Cleanup must depend on whether a job row actually committed, because the
    // two failure classes have opposite correct answers:
    //
    //   - **before the commit** (storage, secret/payload write, transaction): no
    //     job exists, nothing will ever read the inputs, and the credit that
    //     authorization already took has no work to pay for. Release everything.
    //   - **after the commit** (enqueue failed, or the acknowledgement was lost):
    //     the job row exists and is discoverable. A caught exception does *not*
    //     prove the queue rejected it — an ambiguous acknowledgement means the job
    //     may be queued and about to run. Releasing the charge would give the work
    //     away, and deleting the inputs would leave a QUEUED job pointing at
    //     objects that no longer exist.
    if (committedJobId) {
      // Keep the charge (the job exists and may still run) and keep every input.
      // The row is left QUEUED: `planStalledJobExpiry` expires anything that is
      // never claimed, and the payload/secret TTL is the backstop, so an enqueue
      // that genuinely never landed is reconciled rather than stranded.
      logger.error("job.enqueue_failed_after_commit", { job_id: committedJobId, correlation_id: correlationId, tool_id: tool.toolId, status: "queued_unconfirmed" });
      recordMetric("jobs_enqueue_unconfirmed", 1, "count", { tool_id: tool.toolId });
      throw error;
    }
    // No job row: release the charge and remove every artifact this attempt wrote.
    await Promise.all([deletePhase1Secret(secretRef).catch(() => undefined), purgeFormFields(fieldsRef).catch(() => undefined), ...stored.map((object) => storage.deleteObject(object.key).catch(() => undefined)), monetization.charge?.release().catch(() => undefined)]);
    throw error;
  }
}

export function createMergePdfJob(input: { userId: string; uploads: Upload[]; idempotencyKey: string; correlationId?: string }) {
  return createToolJob({ ...input, toolId: "merge-pdf" });
}

/** Trusted internal-file boundary used by workflows. Browser-provided storage keys are never accepted. */
export async function createToolJobFromFiles(input: { userId: string; toolId: string; fileIds: string[]; options?: Record<string, string | number | boolean>; idempotencyKey: string; correlationId: string; workflowRunId: string; workflowNodeId: string }) {
  const tool = getToolDefinition(input.toolId);
  if (phase1SecretToolIds.has(tool.toolId)) throw Object.assign(new Error("Secret-bearing tools are not available in persisted workflows."), { code: "WORKFLOW_SECRET_INPUT_UNSUPPORTED" });
  if (requiresDedicatedJobParameters(tool.toolId)) throw Object.assign(new Error("This tool requires typed per-field input that persisted workflows cannot carry."), { code: "WORKFLOW_TYPED_INPUT_UNSUPPORTED" });
  const options = validateToolOptions(tool.toolId, input.options ?? {});
  const existing = await withTenant({ userId: input.userId }, (tx) => tx.job.findUnique({ where: { toolId_idempotencyKey: { toolId: tool.toolId, idempotencyKey: input.idempotencyKey } }, select: { id: true, status: true } }));
  if (existing) return { ...existing, reused: true };
  const files = await withTenant(
    { userId: input.userId },
    (tx) =>
      tx.file.findMany({
        where: {
          id: { in: input.fileIds },
          document: { userId: input.userId, organizationId: null, status: "ACTIVE" },
          storageObjectId: { not: null },
          NOT: { storageKey: { startsWith: "ephemeral/" } },
          storageObject: {
            ownerUserId: input.userId,
            organizationId: null,
            apiClientId: null,
            deletedAt: null,
          },
        },
        select: {
          id: true,
          size: true,
          pageCount: true,
          mimeType: true,
          storageKey: true,
          storageObjectId: true,
          storageObject: {
            select: {
              ownerUserId: true,
              organizationId: true,
              apiClientId: true,
              provider: true,
              bucket: true,
              objectKey: true,
              deletedAt: true,
            },
          },
        },
      }),
  );
  if (files.length !== input.fileIds.length || files.some((file) => !isAuthorizedFileStorageAccess(file, { userId: input.userId }))) {
    throw Object.assign(new Error("WORKFLOW_ARTIFACT_UNAUTHORIZED"), { code: "WORKFLOW_ARTIFACT_UNAUTHORIZED" });
  }
  if (input.fileIds.length < minimumFilesFor(input.toolId) || input.fileIds.length > tool.limits.maxFiles) throw new Error("INPUT_FILE_COUNT_INVALID");
  if (files.some((file) => !tool.mime.input.includes(file.mimeType))) throw Object.assign(new Error("WORKFLOW_MIME_INCOMPATIBLE"), { code: "WORKFLOW_MIME_INCOMPATIBLE" });
  const monetization = await enforceJobCreation({ userId: input.userId, toolId: tool.toolId, idempotencyKey: input.idempotencyKey, correlationId: input.correlationId, options, files: files.map((file) => ({ size: Number(file.size), pageCount: file.pageCount ?? undefined })) });
  const job = await withTenant({ userId: input.userId }, (tx) => tx.job.create({ data: { toolId: tool.toolId, idempotencyKey: input.idempotencyKey, requesterId: input.userId, inputFileId: input.fileIds[0], status: "QUEUED", params: { inputFileIds: input.fileIds, options }, correlationId: input.correlationId, workflowRunId: input.workflowRunId, workflowNodeId: input.workflowNodeId, steps: { create: { name: tool.toolId, idempotencyKey: `${input.idempotencyKey}:${tool.toolId}`, status: "QUEUED", correlationId: input.correlationId } } }, select: { id: true, status: true } }));
  const queued = { jobId: job.id, toolId: tool.toolId, idempotencyKey: input.idempotencyKey, correlationId: input.correlationId, userId: input.userId, workflowRunId: input.workflowRunId };
  const queueOptions = { priority: monetization.plan.entitlements.processingPriority === "high" ? 1 : 5 };
  if (tool.aiFlag) await enqueueAiJob(queued, queueOptions); else await enqueueJob(queued, queueOptions);
  logger.info("workflow.node.queued", { workflow_run_id: input.workflowRunId, workflow_node_id: input.workflowNodeId, job_id: job.id, correlation_id: input.correlationId, tool_id: tool.toolId });
  return { ...job, reused: false };
}
