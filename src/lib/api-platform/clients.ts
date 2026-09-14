import type { Prisma } from "@prisma/client";
import { withOrganization } from "@/lib/db/tenant";
import { writeBusinessAudit } from "@/lib/business/audit";
import { assertCanManageApi, BusinessAuthorizationError, type OrganizationRole } from "@/lib/business/policy";
import { generateApiKeyMaterial } from "./keys";

async function requireManager(tx: Prisma.TransactionClient, organizationId: string, actorUserId: string) {
  const membership = await tx.membership.findUnique({ where: { userId_organizationId: { userId: actorUserId, organizationId } }, select: { role: true } });
  if (!membership) throw new BusinessAuthorizationError("FORBIDDEN"); assertCanManageApi(membership.role as OrganizationRole);
}
const name = (value: string) => { const result = value.trim(); if (!result || result.length > 100) throw new Error("INVALID_INPUT"); return result; };
const scopes = (value: readonly string[]) => [...new Set(value)].filter((item) => /^[a-z][a-z0-9:_-]{0,63}$|^\*$/.test(item)).slice(0, 50);

export async function createApiClient(actorUserId: string, organizationId: string, clientName: string) {
  return withOrganization({ userId: actorUserId, organizationId }, async (tx) => { await requireManager(tx, organizationId, actorUserId); const client = await tx.apiClient.create({ data: { organizationId, name: name(clientName) } }); await writeBusinessAudit(tx, { organizationId, actorUserId, action: "api_client.created", resource: "api_client", resourceId: client.id, details: { name: client.name } }); return client; });
}

export async function setApiClientStatus(actorUserId: string, organizationId: string, clientId: string, status: "ACTIVE" | "INACTIVE") {
  return withOrganization({ userId: actorUserId, organizationId }, async (tx) => { await requireManager(tx, organizationId, actorUserId); const result = await tx.apiClient.updateMany({ where: { id: clientId, organizationId }, data: { status } }); if (!result.count) throw new BusinessAuthorizationError("NOT_FOUND"); await writeBusinessAudit(tx, { organizationId, actorUserId, action: "api_client.status_changed", resource: "api_client", resourceId: clientId, details: { status } }); return { id: clientId, status }; });
}

export async function listApiKeys(actorUserId: string, organizationId: string, clientId: string) {
  return withOrganization({ userId: actorUserId, organizationId }, async (tx) => { await requireManager(tx, organizationId, actorUserId); return tx.apiKey.findMany({ where: { organizationId, apiClientId: clientId }, select: { id: true, name: true, keyPrefix: true, status: true, scopes: true, expiresAt: true, lastUsedAt: true, revokedAt: true, createdAt: true, updatedAt: true }, orderBy: { createdAt: "desc" } }); });
}

export async function createApiKey(actorUserId: string, organizationId: string, clientId: string, keyName: string, requestedScopes: readonly string[] = []) {
  const material = generateApiKeyMaterial();
  const metadata = await withOrganization({ userId: actorUserId, organizationId }, async (tx) => { await requireManager(tx, organizationId, actorUserId); const client = await tx.apiClient.findFirst({ where: { id: clientId, organizationId } }); if (!client) throw new BusinessAuthorizationError("NOT_FOUND"); const key = await tx.apiKey.create({ data: { organizationId, apiClientId: clientId, name: name(keyName), keyPrefix: material.prefix, keyHash: material.verifier, scopes: scopes(requestedScopes) } }); await writeBusinessAudit(tx, { organizationId, actorUserId, action: "api_key.created", resource: "api_key", resourceId: key.id, details: { apiClientId: clientId, name: key.name, keyPrefix: material.prefix } }); return { id: key.id, name: key.name, keyPrefix: key.keyPrefix, status: key.status, createdAt: key.createdAt }; });
  return { ...metadata, key: material.plaintext };
}

export async function revokeApiKey(actorUserId: string, organizationId: string, keyId: string) {
  return withOrganization({ userId: actorUserId, organizationId }, async (tx) => { await requireManager(tx, organizationId, actorUserId); const result = await tx.apiKey.updateMany({ where: { id: keyId, organizationId, status: "ACTIVE" }, data: { status: "REVOKED", revokedAt: new Date() } }); if (!result.count) throw new BusinessAuthorizationError("NOT_FOUND"); await writeBusinessAudit(tx, { organizationId, actorUserId, action: "api_key.revoked", resource: "api_key", resourceId: keyId }); return { id: keyId, status: "REVOKED" as const }; });
}

export async function rotateApiKey(actorUserId: string, organizationId: string, keyId: string) {
  const material = generateApiKeyMaterial();
  const metadata = await withOrganization({ userId: actorUserId, organizationId }, async (tx) => { await requireManager(tx, organizationId, actorUserId); const old = await tx.apiKey.findFirst({ where: { id: keyId, organizationId, status: "ACTIVE" } }); if (!old?.apiClientId) throw new BusinessAuthorizationError("NOT_FOUND"); await tx.apiKey.update({ where: { id: old.id }, data: { status: "REVOKED", revokedAt: new Date() } }); const next = await tx.apiKey.create({ data: { organizationId, apiClientId: old.apiClientId, name: old.name, scopes: old.scopes ?? [], keyPrefix: material.prefix, keyHash: material.verifier, expiresAt: old.expiresAt, rotatedFromId: old.id } }); await writeBusinessAudit(tx, { organizationId, actorUserId, action: "api_key.rotated", resource: "api_key", resourceId: next.id, details: { apiClientId: old.apiClientId, rotatedFromId: old.id, keyPrefix: material.prefix } }); return { id: next.id, name: next.name, keyPrefix: next.keyPrefix, status: next.status, createdAt: next.createdAt }; });
  return { ...metadata, key: material.plaintext };
}
