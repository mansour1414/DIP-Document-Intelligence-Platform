/**
 * Content-free error reporting (FF-07 / round 2).
 *
 * ## The problem
 *
 * `Job.error` and `JobStep.error` are JSON columns that the API returns to users and
 * support reads directly. The pipeline wrote `{ message: error.message }` into both,
 * where `error.message` is whatever the failure produced:
 *
 *   - a native parser exception (`Cannot read properties of undefined (reading 'X')`);
 *   - a Redis error carrying a connection string or key name;
 *   - a filesystem error carrying an absolute path (`ENOENT: ... /var/task/...`);
 *   - a pdf-lib error quoting document bytes.
 *
 * Every one of those is durable, user-visible and outside our control. The fix is
 * not to scrub messages — it is to stop persisting them. A job row records a **code**
 * from a closed vocabulary and nothing else; the detail lives in the log line, which
 * is access-controlled and already carries the correlation id.
 *
 * ## What counts as allowlisted
 *
 * Codes matching `^[A-Z][A-Z0-9_]{2,63}$` that are either in the known list below or
 * were explicitly marked safe by the throw site (a coded domain error). Anything
 * else — including an empty string, a `TypeError`, or a code that looks like a
 * message — collapses to `PROCESSING_FAILED`. Free-form text can never pass.
 */

/**
 * Codes that may appear in a persisted job row.
 *
 * ## Why this is derived rather than curated
 *
 * The first version of this file listed codes by hand. That was wrong in both
 * directions, and CI caught it: `SCANNER_UNAVAILABLE` (from
 * `MalwareScanError`) and `PDF_PASSWORD_INVALID` (from `QpdfError`) were missing
 * and silently collapsed to `PROCESSING_FAILED`, while other entries duplicated
 * unions that already exist. A hand-maintained allowlist will always drift from
 * the code that actually throws.
 *
 * So the parts that *have* an authoritative union are derived from it —
 * `MalwareScanResultCode` and `FormFillErrorCode` — and the remainder is the
 * vocabulary actually emitted by the modules that feed the pipeline. Every entry
 * below is a code that some module in this repository can throw; none is invented
 * here. The canary test fails if a known-emitted code is ever dropped.
 *
 * What this still is not: a check that each code is *safe* to persist. Safety comes
 * from the shape rule below (a code is an identifier, not a message) and from the
 * fact that every value here is a constant in a `throw`, never derived from input.
 */

/**
 * The scanner outcomes, taken from `MalwareScanResultCode` so that adding a code
 * there cannot silently leave this boundary behind.
 */
const SCANNER_CODES: readonly string[] = [
  "INFECTED", "SCAN_ERROR", "SCAN_TIMEOUT", "SCANNER_UNAVAILABLE",
] satisfies readonly Exclude<MalwareScanResultCode, "CLEAN">[];

/** The fill engine's own codes, taken from `FORM_FILL_ERROR_CODES`. */
const FORM_CODES: readonly string[] = [...FORM_FILL_ERROR_CODES];

/** Rejected-value issues, taken from `FORM_VALUE_ISSUES`. */
const FORM_VALUE_CODES: readonly string[] = [...FORM_VALUE_ISSUES];

/**
 * Codes emitted by the upload, PDF, secret-handoff, storage, output, workflow and
 * monetization paths, plus lifecycle states this module sets itself.
 */
const OPERATIONAL_CODES = [
  // lifecycle / platform
  "PROCESSING_FAILED", "JOB_EXPIRED", "JOB_CANCELLED", "PROCESSING_TIMEOUT",
  "TOOL_NOT_WORKER_ENABLED", "TENANT_CONTEXT_REQUIRED", "JOB_NOT_FOUND", "INVALID_JOB_INPUT",
  // Raised in the durable path itself: the pipeline's params round-trip and the
  // request-body reader. Both are already content-free identifiers.
  "JSON_SERIALISATION_FAILED", "UPLOAD_READ_FAILED",
  "INPUT_NOT_FOUND", "OWNERSHIP_UNKNOWN", "RATE_LIMITED", "PROCESSING_UNAVAILABLE",
  // upload / validation
  "INPUT_FILE_COUNT_INVALID", "TOTAL_SIZE_LIMIT_EXCEEDED", "FILE_SIZE_PLAN_LIMIT_EXCEEDED",
  "PAGE_LIMIT_EXCEEDED", "SIZE_LIMIT_EXCEEDED", "WORKFLOW_MIME_INCOMPATIBLE", "VALIDATION_ERROR",
  "MAGIC_BYTES_INVALID", "MIME_NOT_ALLOWED", "PDF_INVALID", "PDF_OBJECT_LIMIT_EXCEEDED",
  "PDF_RENDER_FAILED", "ENCRYPTED_PDF_REPAIR_UNSUPPORTED", "SIGNED_PDF_REPAIR_UNSAFE",
  "PDF_PASSWORD_INVALID", "QPDF_PROCESSING_FAILED", "UNLOCK_RATE_LIMITED",
  // payload refusals (the issues themselves come from FORM_VALUE_CODES)
  "FIELDS_INPUT_INVALID", "FORM_PAYLOAD_EXPIRED", "FORM_PAYLOAD_INVALID", "FORM_PAYLOAD_UNAVAILABLE",
  // appearance / output
  "APPEARANCE_LIMIT_EXCEEDED", "EMBEDDED_IMAGE_FORMAT_UNSUPPORTED", "FONT_UNAVAILABLE",
  "IMAGE_DIMENSION_LIMIT_EXCEEDED", "NO_SUPPORTED_EMBEDDED_IMAGES", "OUTPUT_LIMIT_EXCEEDED",
  "OUTPUT_VALIDATION_FAILED", "PAGE_DIMENSION_LIMIT_EXCEEDED",
  // secrets
  "SECRET_HANDOFF_UNAVAILABLE", "SECRET_INPUT_INVALID", "SECRET_REFERENCE_EXPIRED",
  "SECRET_REFERENCE_INVALID",
  // boundary
  "WORKER_TIMEOUT", "WORKER_CRASHED", "WORKER_PROTOCOL_ERROR", "WORKER_BUSY",
  "WORKER_INPUT_TOO_LARGE", "WORKER_OUTPUT_TOO_LARGE",
  // security / auth
  "MALWARE_DETECTED", "UNAUTHORIZED", "FORBIDDEN", "API_FORBIDDEN", "AUTH_REQUIRED",
  // workflow
  "WORKFLOW_INVALID", "WORKFLOW_SCHEMA_INVALID", "WORKFLOW_NODES_REQUIRED", "WORKFLOW_NAME_INVALID",
  "WORKFLOW_ARTIFACT_UNAUTHORIZED", "WORKFLOW_SECRET_INPUT_UNSUPPORTED",
  "WORKFLOW_TYPED_INPUT_UNSUPPORTED", "AGENT_BUDGET_EXCEEDED", "AGENT_WORKFLOW_FAILED",
  // monetization
  "INSUFFICIENT_CREDITS", "PLAN_LIMIT_EXCEEDED", "PRO_FEATURE_REQUIRED",
  "DAILY_JOB_LIMIT_EXCEEDED", "MONTHLY_JOB_LIMIT_EXCEEDED", "CONCURRENCY_LIMIT_EXCEEDED",
  "CREDIT_EXHAUSTED",
] as const;

export const ALLOWED_ERROR_CODES: ReadonlySet<string> = new Set<string>([
  ...SCANNER_CODES,
  ...FORM_CODES,
  ...FORM_VALUE_CODES,
  ...OPERATIONAL_CODES,
]);

import type { MalwareScanResultCode } from "@/lib/malware/types";
import { FORM_FILL_ERROR_CODES, FORM_VALUE_ISSUES } from "@/lib/pdf/form-types";

const CODE_SHAPE = /^[A-Z][A-Z0-9_]{2,63}$/u;

/**
 * Reduce any thrown value to a code that is safe to persist and display.
 *
 * Never returns a message. `PROCESSING_FAILED` is the terminal fallback, so a new
 * error type added tomorrow cannot leak by default.
 */
export function publicErrorCode(error: unknown): string {
  if (typeof error === "object" && error !== null && "code" in error) {
    const raw = (error as { code: unknown }).code;
    if (typeof raw === "string" && CODE_SHAPE.test(raw) && ALLOWED_ERROR_CODES.has(raw)) return raw;
  }
  return "PROCESSING_FAILED";
}

/** True when a value is a code this boundary would persist. */
export function isPublicErrorCode(value: unknown): value is string {
  return typeof value === "string" && CODE_SHAPE.test(value) && ALLOWED_ERROR_CODES.has(value);
}

/**
 * The value written into `Job.error` / `JobStep.error`.
 *
 * A code only. This shape is deliberately impoverished: there is no field an
 * operator could populate with a message without changing this function, and a
 * synthetic canary in the test suite fails if one ever reappears.
 */
export type JobErrorRecord = { code: string };

export function jobErrorRecord(error: unknown): JobErrorRecord {
  return { code: publicErrorCode(error) };
}

/**
 * The client-facing message for a code.
 *
 * Messages are fixed strings, not derived from the error, so the same code always
 * produces the same text and nothing from the failure can reach a user.
 */
export function publicErrorMessage(code: string): string {
  switch (code) {
    case "FORM_UNSUPPORTED": return "This document uses a form feature that is not supported.";
    case "FORM_RESTRICTED": return "This document is protected and cannot be filled.";
    case "FORM_NOT_FOUND": return "This document has no fillable form fields.";
    case "MALWARE_DETECTED": return "The file did not pass security screening.";
    case "PROCESSING_UNAVAILABLE": return "The document could not be processed right now.";
    case "RATE_LIMITED": return "Too many requests. Try again shortly.";
    default: return "The document could not be processed.";
  }
}
