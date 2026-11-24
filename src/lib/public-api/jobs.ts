import type { PrismaClient } from "@prisma/client";
import { createHash } from "node:crypto";
import type { ApiPrincipal } from "@/lib/api-platform/auth";
import { bindIdempotencyResource, claimApiIdempotency } from "@/lib/api-platform/idempotency";
import { creditCost } from "@/lib/billing/credit-policy";
import { writeBusinessAudit } from "@/lib/business/audit";
import { db } from "@/lib/db";
import { withApiTenant, withTenantScope } from "@/lib/db/tenant";
import { createToolJob } from "@/lib/jobs/orchestrator";
import { getStorage, type ObjectStorage } from "@/lib/storage";
import { isAuthorizedFileStorageAccess } from "@/lib/storage/metadata";
import { getPublicTool } from "./tools";
import { PublicApiError } from "./errors";
import { deletePhase1Secret, phase1SecretsFromForm, type Phase1SecretPayload } from "@/lib/secrets/phase1";
import { purgeFormFields } from "@/lib/pdf/form-payload";
import { requiresDedicatedJobParameters } from "@/lib/tools/options";
import { FormFillError, assertFieldsPayloadSize, assertNoDuplicateJsonKeys, parseFieldsPayload } from "@/lib/pdf/form-validation";
import { BodyTooLargeError, UploadDeadlineError, boundedMultipartRequest, multipartBudget } from "@/lib/http/bounded-body";
import { getToolDefinition } from "@/lib/tools/registry";

type PublicUpload = { filename: string; mimeType: string; bytes: Uint8Array };
/**
 * Fallback body budget for the Public API when the tool is not declared ahead of
 * the body. It is the largest per-tool file limit the registry allows plus framing
 * overhead, so a legitimate single-file request is never refused here; the exact
 * per-tool limit still applies once `toolId` is known.
 */
const MAX_PUBLIC_BODY_BYTES = Math.max(...["fill-forms"].map((id) => getToolDefinition(id).limits.maxBytes));

/** Wall-clock ceiling for the client to finish the multipart body. */
const PUBLIC_UPLOAD_DEADLINE_MS = 120_000;

export type PublicJobInput = { toolId: string; uploads: PublicUpload[]; options: Record<string, string | number | boolean>; fields?: Record<string, unknown>; secrets?: Phase1SecretPayload; idempotencyKey: string };

export async function parsePublicJobRequest(request: Request): Promise<PublicJobInput & { bytesIn: number; requestHash: string }> {
  const contentType = request.headers.get("content-type") ?? ""; if (!contentType.toLowerCase().includes("multipart/form-data")) throw new PublicApiError("VALIDATION_ERROR", "multipart/form-data is required.", 400);
  const key = request.headers.get("idempotency-key")?.trim(); if (!key) throw new PublicApiError("VALIDATION_ERROR", "Idempotency-Key is required.", 400);
  // FF-04: bound the body against actual bytes as the multipart parser pulls
  // them. The Public API is machine-callable, so a header-only check is especially
  // weak here: `Content-Length` may be absent (chunked) or false. The derived
  // request carries a bounded stream, so the limit applies whether or not a
  // declaration is present or truthful.
  const declaredTool = String(request.headers.get("x-dip-tool") ?? "").trim();
  const bodyBudget = multipartBudget(declaredTool ? getToolDefinition(declaredTool).limits.maxBytes : MAX_PUBLIC_BODY_BYTES);
  let form: FormData;
  try {
    const bounded = boundedMultipartRequest(request, { limitBytes: bodyBudget, deadlineMs: PUBLIC_UPLOAD_DEADLINE_MS });
    form = await bounded.formData();
  } catch (error) {
    if (error instanceof BodyTooLargeError) throw new PublicApiError("SIZE_LIMIT_EXCEEDED", "The request body exceeds the size limit.", 413);
    if (error instanceof UploadDeadlineError) throw new PublicApiError("TIMEOUT", "The upload did not complete in time.", 408);
    throw error;
  }
  const toolId = String(form.get("toolId") ?? "").trim(); if (!toolId) throw new PublicApiError("VALIDATION_ERROR", "toolId is required.", 400);
  let options: Record<string, string | number | boolean> = {}; const rawOptions = form.get("options");
  if (typeof rawOptions === "string" && rawOptions) { try { const parsed = JSON.parse(rawOptions) as unknown; if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || Object.values(parsed).some((value) => !["string", "number", "boolean"].includes(typeof value))) throw new Error(); options = parsed as Record<string, string | number | boolean>; } catch { throw new PublicApiError("VALIDATION_ERROR", "options must be a flat JSON object.", 400); } }
  // `fields` is the typed per-field payload used by tools that cannot express
  // their input as flat options (Stage 2 `fill-forms`). It is bounded and
  // shape-checked here so a malformed request never reaches an upload read.
  const rawFields = form.get("fields"); let fields: Record<string, unknown> | undefined;
  if (rawFields !== null) {
    // FF-10: exactly one `fields` part. `form.get()` returns the first of
    // several parts without saying so, which made a repeated part first-wins.
    if (form.getAll("fields").length !== 1 || typeof rawFields !== "string") throw new PublicApiError("VALIDATION_ERROR", "fields must be sent exactly once, as a JSON string.", 400);
    if (rawFields) {
    // `assertFieldsPayloadSize` measures UTF-8 bytes (FF-10), so 35,121 Arabic
    // characters are correctly rejected as 70,121 bytes.
    try { assertFieldsPayloadSize(rawFields); } catch { throw new PublicApiError("VALIDATION_ERROR", "fields exceeds the 64 KB limit.", 400); }
    let parsed: unknown;
    // Duplicate object keys are rejected before `JSON.parse` can keep only the
    // last one and silently reinterpret the request (FF-10).
    try { assertNoDuplicateJsonKeys(rawFields); parsed = JSON.parse(rawFields) as unknown; }
    catch (error) {
      const duplicate = error instanceof FormFillError;
      throw new PublicApiError("VALIDATION_ERROR", duplicate ? "fields must not repeat a field name." : "fields must be a JSON object.", 400);
    }
    // The rejection message is the allowlisted, content-free one (FF-08); the
    // structured detail stays server-side.
    try { fields = parseFieldsPayload(parsed); } catch (error) { throw new PublicApiError("VALIDATION_ERROR", error instanceof FormFillError ? error.message : "fields is invalid.", 400); }
    }
  }
  if (requiresDedicatedJobParameters(toolId) && !fields) throw new PublicApiError("VALIDATION_ERROR", "This tool requires a fields payload.", 400);
  if (!requiresDedicatedJobParameters(toolId) && fields) throw new PublicApiError("VALIDATION_ERROR", "This tool does not accept a fields payload.", 400);
  const files = form.getAll("files"); if (!files.length || files.some((file) => !(file instanceof File))) throw new PublicApiError("VALIDATION_ERROR", "At least one file is required.", 400);
  const uploads = await Promise.all((files as File[]).map(async (file) => ({ filename: file.name, mimeType: file.type, bytes: new Uint8Array(await file.arrayBuffer()) })));
  const bytesIn = uploads.reduce((sum, file) => sum + file.bytes.byteLength, 0); // The request hash covers the field map too: an idempotency replay of the same
// key must not be served for a different set of values.
  const hash = createHash("sha256").update("POST\0/v1/jobs\0").update(toolId).update("\0").update(JSON.stringify(Object.entries(options).sort())).update("\0").update(JSON.stringify(fields ? Object.entries(fields).sort(([a], [b]) => a.localeCompare(b)) : []));
  for (const upload of uploads) hash.update("\0").update(upload.filename).update("\0").update(upload.mimeType).update("\0").update(upload.bytes);
  return { toolId, uploads, options, ...(fields ? { fields } : {}), secrets: phase1SecretsFromForm(toolId, form), idempotencyKey: key, bytesIn, requestHash: hash.digest("hex") };
}

function jobDto(job: { id: string; toolId: string; status: string; errorCode: string | null; correlationId: string | null; createdAt: Date; updatedAt: Date; startedAt: Date | null; completedAt: Date | null }) { return { id: job.id, toolId: job.toolId, status: job.status.toLowerCase(), errorCode: job.errorCode, requestId: job.correlationId, createdAt: job.createdAt, updatedAt: job.updatedAt, startedAt: job.startedAt, completedAt: job.completedAt, resultUrl: job.status === "SUCCEEDED" ? `/v1/jobs/${job.id}/result` : null }; }

export async function submitPublicJob(principal: ApiPrincipal, input: PublicJobInput & { requestHash: string }) {
  await getPublicTool(principal, input.toolId);
  const claim = await claimApiIdempotency(principal, { key: input.idempotencyKey, requestHash: input.requestHash });
  if (claim.record.resourceId) { const existing = await getPublicJob(principal, claim.record.resourceId); if (!existing) throw new PublicApiError("CONFLICT", "The idempotent resource is no longer available.", 409); return { job: existing, replayed: true, chargedCredits: 0 }; }
  const engineKey = `api:${principal.apiClientId}:${input.idempotencyKey}`;
  const created = await createToolJob({ userId: principal.executionUserId, organizationId: principal.organizationId, apiClientId: principal.apiClientId, toolId: input.toolId, uploads: input.uploads, options: input.options, ...(input.fields ? { fields: input.fields } : {}), secrets: input.secrets, idempotencyKey: engineKey });
  await bindIdempotencyResource(principal, claim.record.id, "job", created.id);
  await withApiTenant(principal, (tx) => writeBusinessAudit(tx, { organizationId: principal.organizationId, action: "api_job.submitted", resource: "job", resourceId: created.id, details: { apiClientId: principal.apiClientId, toolId: input.toolId, idempotentReplay: created.reused } }));
  const job = await getPublicJob(principal, created.id); if (!job) throw new Error("JOB_NOT_FOUND"); return { job, replayed: created.reused, chargedCredits: created.reused ? 0 : creditCost(input.toolId) };
}

export async function getPublicJob(principal: ApiPrincipal, jobId: string) { return withApiTenant(principal, async (tx) => { const job = await tx.job.findFirst({ where: { id: jobId, organizationId: principal.organizationId, apiClientId: principal.apiClientId }, select: { id: true, toolId: true, status: true, errorCode: true, correlationId: true, createdAt: true, updatedAt: true, startedAt: true, completedAt: true } }); return job ? jobDto(job) : null; }); }

export async function cancelPublicJob(principal: ApiPrincipal, jobId: string) {
  const cancelled = await withApiTenant(principal, async (tx) => {
    const job = await tx.job.findFirst({ where: { id: jobId, organizationId: principal.organizationId, apiClientId: principal.apiClientId }, select: { id: true, status: true, params: true } }); if (!job) throw new PublicApiError("NOT_FOUND", "The requested job was not found.", 404);
    if (["SUCCEEDED", "FAILED", "CANCELLED", "EXPIRED"].includes(job.status)) return { result: { id: job.id, status: job.status.toLowerCase() }, secretRef: undefined, fieldsRef: undefined };
    if (job.status === "RUNNING") throw new PublicApiError("CONFLICT", "A running job can no longer be cancelled safely.", 409);
    // Cancel-vs-claim: a guarded write, not an unconditional one. The status was
    // read a moment ago, but a worker may have claimed the job in between; an
    // `update()` here would overwrite a row that had just become RUNNING (or even
    // SUCCEEDED) and then this path would purge the inputs of a live attempt.
    const cancelledWrite = await tx.job.updateMany({
      where: { id: job.id, status: { in: ["QUEUED", "RETRYING"] } },
      data: { status: "CANCELLED", completedAt: new Date(), errorCode: "API_CANCELLED" },
    });
    if (cancelledWrite.count !== 1) {
      // Someone else moved it first. Report what actually happened instead of
      // claiming a cancellation that did not take effect; nothing is purged.
      const latest = await tx.job.findUnique({ where: { id: job.id }, select: { status: true } });
      if (latest?.status === "RUNNING") throw new PublicApiError("CONFLICT", "A running job can no longer be cancelled safely.", 409);
      return { result: { id: job.id, status: String(latest?.status ?? "unknown").toLowerCase() }, secretRef: undefined, fieldsRef: undefined };
    } await tx.jobStep.updateMany({ where: { jobId: job.id, status: { in: ["QUEUED", "RETRYING"] } }, data: { status: "CANCELLED", completedAt: new Date(), errorCode: "API_CANCELLED" } }); await writeBusinessAudit(tx, { organizationId: principal.organizationId, action: "api_job.cancelled", resource: "job", resourceId: job.id, details: { apiClientId: principal.apiClientId } }); return { result: { id: job.id, status: "cancelled" }, secretRef: (job.params as { secretRef?: string }).secretRef, fieldsRef: (job.params as { fieldsRef?: string }).fieldsRef };
  });
  // FF-03: cancellation is terminal, so the encrypted values are removed with the
  // rest of the job's sensitive material. The TTL is only the backstop for a
  // cancellation that never reaches this line.
  await Promise.all([deletePhase1Secret(cancelled.secretRef).catch(() => undefined), purgeFormFields(cancelled.fieldsRef).catch(() => undefined)]);
  return cancelled.result;
}

async function scopedResult(principal: ApiPrincipal, jobId: string, client: PrismaClient = db) {
  const job = await withApiTenant(principal, (tx) => tx.job.findFirst({ where: { id: jobId, organizationId: principal.organizationId, apiClientId: principal.apiClientId, status: "SUCCEEDED" }, select: { id: true, toolId: true, result: true } }), client); if (!job) throw new PublicApiError("NOT_FOUND", "A completed result was not found.", 404); return job;
}
export async function getPublicJobResult(principal: ApiPrincipal, jobId: string, client: PrismaClient = db) {
  const job = await scopedResult(principal, jobId, client);
  const result = job.result as { outputFileIds?: string[] } | null;
  if (!result?.outputFileIds) return { kind: "json" as const, data: job.result };
  const scope = { userId: principal.executionUserId, organizationId: principal.organizationId, apiClientId: principal.apiClientId };
  const files = await withTenantScope(
    scope,
    (tx) =>
      tx.file.findMany({
        where: {
          id: { in: result.outputFileIds },
          document: { userId: principal.executionUserId, organizationId: principal.organizationId, status: "ACTIVE" },
          storageObjectId: { not: null },
          NOT: { storageKey: { startsWith: "ephemeral/" } },
          storageObject: {
            ownerUserId: principal.executionUserId,
            organizationId: principal.organizationId,
            apiClientId: principal.apiClientId,
            deletedAt: null,
          },
        },
        select: {
          id: true,
          originalName: true,
          mimeType: true,
          size: true,
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
    client,
  );
  const authorizedFiles = files.filter((file) => isAuthorizedFileStorageAccess(file, scope));
  return { kind: "files" as const, files: authorizedFiles.map((file) => ({ id: file.id, name: file.originalName, mimeType: file.mimeType, bytes: Number(file.size), downloadUrl: `/v1/jobs/${jobId}/result/${file.id}` })) };
}
export async function downloadPublicJobResult(principal: ApiPrincipal, jobId: string, fileId: string, deps: { client?: PrismaClient; storage?: ObjectStorage } = {}) {
  const client = deps.client ?? db;
  const storage = deps.storage ?? getStorage();
  const job = await scopedResult(principal, jobId, client);
  const ids = ((job.result as { outputFileIds?: string[] } | null)?.outputFileIds ?? []);
  if (!ids.includes(fileId)) throw new PublicApiError("NOT_FOUND", "The result file was not found.", 404);
  const scope = { userId: principal.executionUserId, organizationId: principal.organizationId, apiClientId: principal.apiClientId };
  const file = await withTenantScope(
    scope,
    (tx) =>
      tx.file.findFirst({
        where: {
          id: fileId,
          document: { userId: principal.executionUserId, organizationId: principal.organizationId, status: "ACTIVE" },
          storageObjectId: { not: null },
          NOT: { storageKey: { startsWith: "ephemeral/" } },
          storageObject: {
            ownerUserId: principal.executionUserId,
            organizationId: principal.organizationId,
            apiClientId: principal.apiClientId,
            deletedAt: null,
          },
        },
        select: {
          originalName: true,
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
    client,
  );
  if (!isAuthorizedFileStorageAccess(file, scope)) throw new PublicApiError("NOT_FOUND", "The result file was not found.", 404);
  return {
    originalName: file!.originalName,
    mimeType: file!.mimeType,
    storageKey: file!.storageKey,
    bytes: await storage.get(file!.storageKey),
  };
}
