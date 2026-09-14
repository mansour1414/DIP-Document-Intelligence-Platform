import { randomUUID } from "node:crypto";
import { authenticateApiRequest, authorizeApiPrincipal, type ApiPrincipal } from "@/lib/api-platform/auth";
import { consumeApiRateLimit } from "@/lib/api-platform/rate-limit";
import { withApiTenant } from "@/lib/db/tenant";
import { logger } from "@/lib/logging";
import { recordMetric } from "@/lib/observability/metrics";
import { captureOperationalError } from "@/lib/observability/errors";
import { PublicApiError, publicErrorResponse } from "./errors";

export type PublicRequestContext = { principal: ApiPrincipal; requestId: string; route: string; bytesIn: number; creditsUsed: number; toolId?: string };
function safeInternalDiagnostic(error: unknown) { return (error instanceof Error ? error.stack ?? `${error.name}: ${error.message}` : String(error)).replace(/Bearer\s+\S+/gi, "Bearer [REDACTED]").replace(/postgres(?:ql)?:\/\/[^@\s]+@/gi, "postgresql://[REDACTED]@").replace(/dip_v1_[A-Za-z0-9_-]+/g, "[REDACTED_API_KEY]").slice(0, 4_000); }
function positive(value: string | undefined, fallback: number) { const parsed = Number(value); return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback; }
export function rateLimitDecision(result: { allowed: boolean; retryAfterMs: number }) { if (!result.allowed) throw new PublicApiError("RATE_LIMITED", "The API rate limit was exceeded.", 429, { retryAfterSeconds: Math.max(1, Math.ceil(result.retryAfterMs / 1000)) }); return result; }

async function recordUsage(context: PublicRequestContext, request: Request, response: Response) {
  const bytesOut = (await response.clone().arrayBuffer()).byteLength;
  await withApiTenant(context.principal, (tx) => tx.apiUsage.create({ data: { organizationId: context.principal.organizationId, apiClientId: context.principal.apiClientId, requestId: context.requestId, route: context.route, method: request.method, toolId: context.toolId, statusCode: response.status, bytesIn: BigInt(context.bytesIn), bytesOut: BigInt(bytesOut), creditsUsed: context.creditsUsed } })).catch((error) => logger.error("public_api.usage_failed", { request_id: context.requestId, api_client_id: context.principal.apiClientId, organization_id: context.principal.organizationId, error_code: typeof error === "object" && error && "code" in error ? String(error.code) : "UNKNOWN" }));
  recordMetric("public_api_requests_total", 1, "count", { route: context.route, status: response.status }); recordMetric("public_api_bytes_in", context.bytesIn, "bytes", { route: context.route }); recordMetric("public_api_bytes_out", bytesOut, "bytes", { route: context.route });
}

export async function handlePublicApi(request: Request, route: string, scope: string, handler: (context: PublicRequestContext) => Promise<Response>) {
  const requestId = randomUUID(); const started = performance.now(); let context: PublicRequestContext | undefined; let response: Response;
  try {
    const principal = await authenticateApiRequest(request); authorizeApiPrincipal(principal, scope); context = { principal, requestId, route, bytesIn: 0, creditsUsed: 0 };
    const rateResult = await consumeApiRateLimit(principal, { client: positive(process.env.API_RATE_LIMIT_CLIENT_PER_MINUTE, 120), organization: positive(process.env.API_RATE_LIMIT_ORGANIZATION_PER_MINUTE, 1000), windowMs: 60_000 });
    logger.info("public_api.rate_limit", { request_id: requestId, api_client_id: principal.apiClientId, organization_id: principal.organizationId, route, allowed: rateResult.allowed });
    rateLimitDecision(rateResult);
    response = await handler(context);
  } catch (error) { response = publicErrorResponse(error, requestId); if (response.status === 500) { captureOperationalError(error, { request_id: requestId, route, method: request.method, subsystem: "public_api" }); logger.error("public_api.internal_error", { request_id: requestId, route, method: request.method, error_stack: safeInternalDiagnostic(error) }); } }
  if (context) await recordUsage(context, request, response);
  logger.info("public_api.request", { request_id: requestId, api_client_id: context?.principal.apiClientId, organization_id: context?.principal.organizationId, route, status: response.status, latency_ms: Math.round(performance.now() - started), tool_id: context?.toolId });
  response.headers.set("x-request-id", requestId); response.headers.set("cache-control", "no-store"); return response;
}
