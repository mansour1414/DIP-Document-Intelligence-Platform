import { db } from "@/lib/db";
import { withApiTenant } from "@/lib/db/tenant";
import { bearerApiKey, parseApiKey, verifyApiKeySecret } from "./keys";

export type ApiPrincipal = Readonly<{ kind: "api_key"; apiKeyId: string; apiClientId: string; organizationId: string; scopes: readonly string[] }>;
export class ApiAuthenticationError extends Error { readonly code = "API_AUTHENTICATION_FAILED"; constructor() { super("API_AUTHENTICATION_FAILED"); } }

export type ApiKeyCandidate = { key_id: string; key_hash: string; key_status: string; expires_at: Date | null; api_client_id: string; client_status: string; organization_id: string; organization_status: string; scopes: unknown };

export function principalFromApiKeyCandidate(secret: string, candidate: ApiKeyCandidate | undefined, now = new Date()): ApiPrincipal {
  if (!candidate || !verifyApiKeySecret(secret, candidate.key_hash) || candidate.key_status !== "ACTIVE" || candidate.client_status !== "ACTIVE" || candidate.organization_status !== "ACTIVE" || candidate.expires_at && candidate.expires_at <= now) throw new ApiAuthenticationError();
  const scopes = Array.isArray(candidate.scopes) ? candidate.scopes.filter((scope): scope is string => typeof scope === "string") : [];
  return { kind: "api_key", apiKeyId: candidate.key_id, apiClientId: candidate.api_client_id, organizationId: candidate.organization_id, scopes };
}

export async function authenticateApiRequest(request: Request): Promise<ApiPrincipal> {
  const parsed = parseApiKey(bearerApiKey(request.headers.get("authorization")));
  if (!parsed) throw new ApiAuthenticationError();
  const rows = await db.$queryRaw<ApiKeyCandidate[]>`SELECT * FROM api_key_auth_candidate(${parsed.prefix})`;
  const candidate = rows[0];
  const principal = principalFromApiKeyCandidate(parsed.secret, candidate);
  await withApiTenant(principal, (tx) => tx.apiKey.update({ where: { id: principal.apiKeyId }, data: { lastUsedAt: new Date() }, select: { id: true } }));
  return principal;
}

export function authorizeApiPrincipal(principal: ApiPrincipal, requiredScope: string) {
  if (!principal.scopes.includes(requiredScope) && !principal.scopes.includes("*")) throw Object.assign(new Error("API_FORBIDDEN"), { code: "API_FORBIDDEN" });
}
