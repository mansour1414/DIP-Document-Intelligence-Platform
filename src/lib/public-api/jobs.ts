import { createHash } from "node:crypto";
import type { ApiPrincipal } from "@/lib/api-platform/auth";
import { bindIdempotencyResource, claimApiIdempotency } from "@/lib/api-platform/idempotency";
import { creditCost } from "@/lib/billing/credit-policy";
import { writeBusinessAudit } from "@/lib/business/audit";
import { withApiTenant, withTenant } from "@/lib/db/tenant";
import { createToolJob } from "@/lib/jobs/orchestrator";
import { getStorage } from "@/lib/storage";
import { getPublicTool } from "./tools";
import { PublicApiError } from "./errors";
import { deletePhase1Secret, phase1SecretsFromForm, type Phase1SecretPayload } from "@/lib/secrets/phase1";

type PublicUpload = { filename: string; mimeType: string; bytes: Uint8Array };
export type PublicJobInput = { toolId: string; uploads: PublicUpload[]; options: Record<string, string | number | boolean>; secrets?: Phase1SecretPayload; idempotencyKey: string };

export async function parsePublicJobRequest(request: Request): Promise<PublicJobInput & { bytesIn: number; requestHash: string }> {
  const contentType = request.headers.get("content-type") ?? ""; if (!contentType.toLowerCase().includes("multipart/form-data")) throw new PublicApiError("VALIDATION_ERROR", "multipart/form-data is required.", 400);
  const key = request.headers.get("idempotency-key")?.trim(); if (!key) throw new PublicApiError("VALIDATION_ERROR", "Idempotency-Key is required.", 400);
  const form = await request.formData(); const toolId = String(form.get("toolId") ?? "").trim(); if (!toolId) throw new PublicApiError("VALIDATION_ERROR", "toolId is required.", 400);
  let options: Record<string, string | number | boolean> = {}; const rawOptions = form.get("options");
  if (typeof rawOptions === "string" && rawOptions) { try { const parsed = JSON.parse(rawOptions) as unknown; if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || Object.values(parsed).some((value) => !["string", "number", "boolean"].includes(typeof value))) throw new Error(); options = parsed as Record<string, string | number | boolean>; } catch { throw new PublicApiError("VALIDATION_ERROR", "options must be a flat JSON object.", 400); } }
  const files = form.getAll("files"); if (!files.length || files.some((file) => !(file instanceof File))) throw new PublicApiError("VALIDATION_ERROR", "At least one file is required.", 400);
  const uploads = await Promise.all((files as File[]).map(async (file) => ({ filename: file.name, mimeType: file.type, bytes: new Uint8Array(await file.arrayBuffer()) })));
  const bytesIn = uploads.reduce((sum, file) => sum + file.bytes.byteLength, 0); const hash = createHash("sha256").update("POST\0/v1/jobs\0").update(toolId).update("\0").update(JSON.stringify(Object.entries(options).sort()));
  for (const upload of uploads) hash.update("\0").update(upload.filename).update("\0").update(upload.mimeType).update("\0").update(upload.bytes);
  return { toolId, uploads, options, secrets: phase1SecretsFromForm(toolId, form), idempotencyKey: key, bytesIn, requestHash: hash.digest("hex") };
}

function jobDto(job: { id: string; toolId: string; status: string; errorCode: string | null; correlationId: string | null; createdAt: Date; updatedAt: Date; startedAt: Date | null; completedAt: Date | null }) { return { id: job.id, toolId: job.toolId, status: job.status.toLowerCase(), errorCode: job.errorCode, requestId: job.correlationId, createdAt: job.createdAt, updatedAt: job.updatedAt, startedAt: job.startedAt, completedAt: job.completedAt, resultUrl: job.status === "SUCCEEDED" ? `/v1/jobs/${job.id}/result` : null }; }

export async function submitPublicJob(principal: ApiPrincipal, input: PublicJobInput & { requestHash: string }) {
  await getPublicTool(principal, input.toolId);
  const claim = await claimApiIdempotency(principal, { key: input.idempotencyKey, requestHash: input.requestHash });
  if (claim.record.resourceId) { const existing = await getPublicJob(principal, claim.record.resourceId); if (!existing) throw new PublicApiError("CONFLICT", "The idempotent resource is no longer available.", 409); return { job: existing, replayed: true, chargedCredits: 0 }; }
  const engineKey = `api:${principal.apiClientId}:${input.idempotencyKey}`;
  const created = await createToolJob({ userId: principal.executionUserId, organizationId: principal.organizationId, apiClientId: principal.apiClientId, toolId: input.toolId, uploads: input.uploads, options: input.options, secrets: input.secrets, idempotencyKey: engineKey });
  await bindIdempotencyResource(principal, claim.record.id, "job", created.id);
  await withApiTenant(principal, (tx) => writeBusinessAudit(tx, { organizationId: principal.organizationId, action: "api_job.submitted", resource: "job", resourceId: created.id, details: { apiClientId: principal.apiClientId, toolId: input.toolId, idempotentReplay: created.reused } }));
  const job = await getPublicJob(principal, created.id); if (!job) throw new Error("JOB_NOT_FOUND"); return { job, replayed: created.reused, chargedCredits: created.reused ? 0 : creditCost(input.toolId) };
}

export async function getPublicJob(principal: ApiPrincipal, jobId: string) { return withApiTenant(principal, async (tx) => { const job = await tx.job.findFirst({ where: { id: jobId, organizationId: principal.organizationId, apiClientId: principal.apiClientId }, select: { id: true, toolId: true, status: true, errorCode: true, correlationId: true, createdAt: true, updatedAt: true, startedAt: true, completedAt: true } }); return job ? jobDto(job) : null; }); }

export async function cancelPublicJob(principal: ApiPrincipal, jobId: string) {
  const cancelled = await withApiTenant(principal, async (tx) => {
    const job = await tx.job.findFirst({ where: { id: jobId, organizationId: principal.organizationId, apiClientId: principal.apiClientId }, select: { id: true, status: true, params: true } }); if (!job) throw new PublicApiError("NOT_FOUND", "The requested job was not found.", 404);
    if (["SUCCEEDED", "FAILED", "CANCELLED", "EXPIRED"].includes(job.status)) return { result: { id: job.id, status: job.status.toLowerCase() }, secretRef: undefined };
    if (job.status === "RUNNING") throw new PublicApiError("CONFLICT", "A running job can no longer be cancelled safely.", 409);
    await tx.job.update({ where: { id: job.id }, data: { status: "CANCELLED", completedAt: new Date(), errorCode: "API_CANCELLED" } }); await tx.jobStep.updateMany({ where: { jobId: job.id, status: { in: ["QUEUED", "RETRYING"] } }, data: { status: "CANCELLED", completedAt: new Date(), errorCode: "API_CANCELLED" } }); await writeBusinessAudit(tx, { organizationId: principal.organizationId, action: "api_job.cancelled", resource: "job", resourceId: job.id, details: { apiClientId: principal.apiClientId } }); return { result: { id: job.id, status: "cancelled" }, secretRef: (job.params as { secretRef?: string }).secretRef };
  });
  await deletePhase1Secret(cancelled.secretRef).catch(() => undefined); return cancelled.result;
}

async function scopedResult(principal: ApiPrincipal, jobId: string) {
  const job = await withApiTenant(principal, (tx) => tx.job.findFirst({ where: { id: jobId, organizationId: principal.organizationId, apiClientId: principal.apiClientId, status: "SUCCEEDED" }, select: { id: true, toolId: true, result: true } })); if (!job) throw new PublicApiError("NOT_FOUND", "A completed result was not found.", 404); return job;
}
export async function getPublicJobResult(principal: ApiPrincipal, jobId: string) { const job = await scopedResult(principal, jobId); const result = job.result as { outputFileIds?: string[] } | null; if (!result?.outputFileIds) return { kind: "json" as const, data: job.result }; const files = await withTenant({ userId: principal.executionUserId }, (tx) => tx.file.findMany({ where: { id: { in: result.outputFileIds }, document: { organizationId: principal.organizationId } }, select: { id: true, originalName: true, mimeType: true, size: true } })); return { kind: "files" as const, files: files.map((file) => ({ id: file.id, name: file.originalName, mimeType: file.mimeType, bytes: Number(file.size), downloadUrl: `/v1/jobs/${jobId}/result/${file.id}` })) }; }
export async function downloadPublicJobResult(principal: ApiPrincipal, jobId: string, fileId: string) { const job = await scopedResult(principal, jobId); const ids = ((job.result as { outputFileIds?: string[] } | null)?.outputFileIds ?? []); if (!ids.includes(fileId)) throw new PublicApiError("NOT_FOUND", "The result file was not found.", 404); const file = await withTenant({ userId: principal.executionUserId }, (tx) => tx.file.findFirst({ where: { id: fileId, document: { organizationId: principal.organizationId } }, select: { originalName: true, mimeType: true, storageKey: true } })); if (!file) throw new PublicApiError("NOT_FOUND", "The result file was not found.", 404); return { ...file, bytes: await getStorage().get(file.storageKey) }; }
