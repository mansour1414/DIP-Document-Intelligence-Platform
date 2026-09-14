import { createHash } from "node:crypto";
import { Prisma } from "@prisma/client";
import type { ApiPrincipal } from "./auth";
import { withApiTenant } from "@/lib/db/tenant";

export class IdempotencyConflictError extends Error { readonly code = "IDEMPOTENCY_KEY_REUSED"; }
export function apiRequestHash(method: string, route: string, body: string | Uint8Array) { return createHash("sha256").update(method.toUpperCase()).update("\0").update(route).update("\0").update(body).digest("hex"); }

export async function claimApiIdempotency(principal: ApiPrincipal, input: { key: string; requestHash: string; expiresAt?: Date }) {
  const key = input.key.trim(); if (!key || key.length > 255 || !/^[\x21-\x7e]+$/.test(key)) throw new Error("INVALID_IDEMPOTENCY_KEY");
  return withApiTenant(principal, async (tx) => {
    const existing = await tx.apiIdempotencyRecord.findUnique({ where: { apiClientId_idempotencyKey: { apiClientId: principal.apiClientId, idempotencyKey: key } } });
    if (existing) { if (existing.requestHash !== input.requestHash) throw new IdempotencyConflictError(); return { record: existing, reused: true }; }
    try { const record = await tx.apiIdempotencyRecord.create({ data: { organizationId: principal.organizationId, apiClientId: principal.apiClientId, idempotencyKey: key, requestHash: input.requestHash, expiresAt: input.expiresAt ?? new Date(Date.now() + 24 * 60 * 60 * 1000) } }); return { record, reused: false }; }
    catch (error) { if (!(error instanceof Prisma.PrismaClientKnownRequestError) || error.code !== "P2002") throw error; const raced = await tx.apiIdempotencyRecord.findUniqueOrThrow({ where: { apiClientId_idempotencyKey: { apiClientId: principal.apiClientId, idempotencyKey: key } } }); if (raced.requestHash !== input.requestHash) throw new IdempotencyConflictError(); return { record: raced, reused: true }; }
  });
}

export async function bindIdempotencyResource(principal: ApiPrincipal, recordId: string, resourceType: "job" | "workflow_run", resourceId: string) {
  return withApiTenant(principal, (tx) => tx.apiIdempotencyRecord.update({ where: { id: recordId }, data: { resourceType, resourceId } }));
}
