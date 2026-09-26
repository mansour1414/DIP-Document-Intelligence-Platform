import { ApiAuthenticationError } from "@/lib/api-platform/auth";
import { IdempotencyConflictError } from "@/lib/api-platform/idempotency";
import { MonetizationError } from "@/lib/usage/errors";
import { UploadValidationError } from "@/lib/uploads/validation";
import { MalwareScanError } from "@/lib/malware";
import { ToolOptionsValidationError } from "@/lib/tools/options";

export type PublicErrorCode = "VALIDATION_ERROR" | "UNSUPPORTED_FORMAT" | "SIZE_LIMIT_EXCEEDED" | "PAGE_LIMIT_EXCEEDED" | "MALWARE_DETECTED" | "TIMEOUT" | "PROVIDER_ERROR" | "CREDIT_EXHAUSTED" | "RATE_LIMITED" | "UNAUTHORIZED" | "FORBIDDEN" | "NOT_FOUND" | "CONFLICT" | "INTERNAL_ERROR";
export class PublicApiError extends Error { constructor(readonly code: PublicErrorCode, message: string, readonly status: number, readonly details?: Record<string, string | number | boolean>) { super(message); } }

export function mapPublicError(error: unknown): PublicApiError {
  if (error instanceof PublicApiError) return error;
  if (error instanceof ApiAuthenticationError) return new PublicApiError("UNAUTHORIZED", "A valid API key is required.", 401);
  if (error instanceof IdempotencyConflictError) return new PublicApiError("CONFLICT", "The idempotency key was already used with a different request.", 409);
  if (error instanceof ToolOptionsValidationError) return new PublicApiError("VALIDATION_ERROR", error.message, 422);
  if (error instanceof UploadValidationError) {
    if (error.code === "PAGE_LIMIT_EXCEEDED") return new PublicApiError("PAGE_LIMIT_EXCEEDED", "A file exceeds the allowed page limit.", 422);
    if (error.code === "SIZE_LIMIT_EXCEEDED") return new PublicApiError("SIZE_LIMIT_EXCEEDED", "A file exceeds the allowed size limit.", 413);
    return new PublicApiError("UNSUPPORTED_FORMAT", "A file format or signature is unsupported.", 415);
  }
  if (error instanceof MalwareScanError) {
    if (error.code === "INFECTED") return new PublicApiError("MALWARE_DETECTED", "The uploaded file was rejected by security scanning.", 422);
    if (error.code === "SCAN_TIMEOUT") return new PublicApiError("TIMEOUT", "Security scanning timed out.", 504);
    return new PublicApiError("PROVIDER_ERROR", "Security scanning is temporarily unavailable.", 503);
  }
  if (error instanceof MonetizationError) {
    if (error.code === "INSUFFICIENT_CREDITS") return new PublicApiError("CREDIT_EXHAUSTED", "The account has insufficient credits.", 402);
    if (error.code === "FILE_SIZE_PLAN_LIMIT_EXCEEDED") return new PublicApiError("SIZE_LIMIT_EXCEEDED", "A file exceeds the account limit.", 413);
    if (error.code === "PAGE_LIMIT_EXCEEDED") return new PublicApiError("PAGE_LIMIT_EXCEEDED", "A file exceeds the account page limit.", 422);
    if (error.code.includes("LIMIT") || error.code === "PRO_FEATURE_REQUIRED") return new PublicApiError("FORBIDDEN", "The account policy does not permit this request.", 403);
  }
  const code = typeof error === "object" && error && "code" in error ? String(error.code) : error instanceof Error ? error.message : "";
  if (["API_FORBIDDEN", "TOOL_NOT_PUBLIC", "PLAN_LIMIT_EXCEEDED"].includes(code)) return new PublicApiError("FORBIDDEN", "The requested operation is not permitted.", 403);
  if (["NOT_FOUND", "JOB_NOT_FOUND"].includes(code)) return new PublicApiError("NOT_FOUND", "The requested resource was not found.", 404);
  if (["INVALID_INPUT", "INVALID_IDEMPOTENCY_KEY", "INPUT_FILE_COUNT_INVALID"].includes(code)) return new PublicApiError("VALIDATION_ERROR", "The request is invalid.", 400);
  if (["SECRET_INPUT_INVALID", "SECRET_HANDOFF_UNAVAILABLE"].includes(code)) return new PublicApiError("VALIDATION_ERROR", "The secure password input is invalid or unavailable.", 422);
  if (code === "UNLOCK_RATE_LIMITED") return new PublicApiError("RATE_LIMITED", "Unlock requests are temporarily rate limited.", 429);
  if (["TOTAL_SIZE_LIMIT_EXCEEDED"].includes(code)) return new PublicApiError("SIZE_LIMIT_EXCEEDED", "The request exceeds the allowed size.", 413);
  if (/TIMEOUT/i.test(code)) return new PublicApiError("TIMEOUT", "Processing timed out.", 504);
  if (/PROVIDER/i.test(code)) return new PublicApiError("PROVIDER_ERROR", "An upstream provider failed.", 502);
  return new PublicApiError("INTERNAL_ERROR", "The request could not be completed.", 500);
}

export function publicErrorResponse(error: unknown, requestId: string) { const mapped = mapPublicError(error); return Response.json({ error: { code: mapped.code, message: mapped.message, requestId, ...(mapped.details ? { details: mapped.details } : {}) } }, { status: mapped.status, headers: { "x-request-id": requestId, "cache-control": "no-store" } }); }
