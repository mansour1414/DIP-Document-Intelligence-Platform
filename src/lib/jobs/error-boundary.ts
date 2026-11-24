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

/** Codes that may appear in a persisted job row. */
export const ALLOWED_ERROR_CODES = new Set([
  // lifecycle / platform
  "PROCESSING_FAILED", "JOB_EXPIRED", "JOB_CANCELLED", "JOB_TIMEOUT", "TOOL_NOT_WORKER_ENABLED",
  // upload / validation
  "INPUT_FILE_COUNT_INVALID", "TOTAL_SIZE_LIMIT_EXCEEDED", "FILE_SIZE_PLAN_LIMIT_EXCEEDED",
  "PAGE_LIMIT_EXCEEDED", "SIZE_LIMIT_EXCEEDED", "WORKFLOW_MIME_INCOMPATIBLE", "VALIDATION_ERROR",
  "FIELDS_INPUT_INVALID", "FIELD_VALUE_INVALID", "OPTION_NOT_OFFERED", "UNKNOWN_FIELD",
  "TYPE_MISMATCH", "READ_ONLY_FIELD", "DUPLICATE_SELECTION", "LENGTH_EXCEEDED",
  "LINE_BREAK_IN_SINGLE_LINE", "CONTROL_CHARACTER", "UNRENDERABLE_SCRIPT",
  // pdf / form (the `FormFillErrorCode` union is the authority for these)
  "FORM_UNSUPPORTED", "FORM_RESTRICTED", "FORM_NOT_FOUND", "FORM_VALUE_INVALID",
  "FORM_FILL_FAILED", "FORM_OUTPUT_UNVERIFIED",
  "FORM_STRUCTURE_UNSAFE", "WIDGET_TOO_SMALL", "VALUE_OVERFLOWS_WIDGET", "VALUE_NEEDS_MORE_LINES",
  // boundary
  "WORKER_TIMEOUT", "WORKER_CRASHED", "WORKER_PROTOCOL_ERROR", "WORKER_BUSY",
  "WORKER_INPUT_TOO_LARGE", "WORKER_OUTPUT_TOO_LARGE", "PROCESSING_UNAVAILABLE", "RATE_LIMITED",
  // security
  "MALWARE_DETECTED", "OUTPUT_REJECTED", "UNAUTHORIZED", "FORBIDDEN", "AUTH_REQUIRED",
  // monetization
  "INSUFFICIENT_CREDITS", "PLAN_LIMIT_EXCEEDED", "PRO_FEATURE_REQUIRED",
  "DAILY_JOB_LIMIT_EXCEEDED", "MONTHLY_JOB_LIMIT_EXCEEDED", "CONCURRENCY_LIMIT_EXCEEDED",
  // --- operational codes already emitted by the processing paths -----------------
  // Added after reviewing the boundary for regressions: before it existed, *any*
  // `error.code` was persisted, so these reached users and support runbooks. A
  // closed vocabulary must not silently collapse codes other tools already depend
  // on — that would trade a leak for a blind spot. Each is a real, content-free
  // condition raised by the upload, PDF, secret-handoff, storage or output paths.
  "UPLOAD_DECODE_FAILED", "PDF_INVALID", "MAGIC_BYTES_INVALID", "MIME_NOT_ALLOWED",
  "APPEARANCE_LIMIT_EXCEEDED", "EMBEDDED_IMAGE_FORMAT_UNSUPPORTED", "FONT_UNAVAILABLE",
  "FORM_PAYLOAD_EXPIRED", "FORM_PAYLOAD_INVALID", "FORM_PAYLOAD_UNAVAILABLE",
  "IMAGE_DIMENSION_LIMIT_EXCEEDED", "NO_SUPPORTED_EMBEDDED_IMAGES", "OUTPUT_LIMIT_EXCEEDED",
  "PAGE_DIMENSION_LIMIT_EXCEEDED", "PDF_RENDER_FAILED",
  "SECRET_HANDOFF_UNAVAILABLE", "SECRET_INPUT_INVALID", "SECRET_REFERENCE_EXPIRED",
  "SECRET_REFERENCE_INVALID", "UNLOCK_RATE_LIMITED",
  // Pipeline-internal refusals that are safe to name.
  "TENANT_CONTEXT_REQUIRED", "JOB_NOT_FOUND", "OUTPUT_SCAN_FAILED",
]);

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
