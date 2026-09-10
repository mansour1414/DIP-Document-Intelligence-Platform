import { logger, type LogContext } from "@/lib/logging";

/** Vendor-neutral boundary. Sentry can be attached here after its Product/DSN gate. */
export function captureOperationalError(error: unknown, context: LogContext = {}) {
  logger.error("operational.error", { ...context, error_name: error instanceof Error ? error.name : "UnknownError", error_code: typeof error === "object" && error && "code" in error ? String(error.code) : "INTERNAL_ERROR" });
}

