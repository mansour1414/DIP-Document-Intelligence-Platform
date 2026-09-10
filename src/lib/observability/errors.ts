import { logger, type LogContext } from "@/lib/logging";
import * as Sentry from "@sentry/nextjs";

/** Vendor-neutral boundary. Sentry can be attached here after its Product/DSN gate. */
export function captureOperationalError(error: unknown, context: LogContext = {}) {
  logger.error("operational.error", { ...context, error_name: error instanceof Error ? error.name : "UnknownError", error_code: typeof error === "object" && error && "code" in error ? String(error.code) : "INTERNAL_ERROR" });
  if (process.env.SENTRY_DSN) Sentry.withScope((scope) => {
    for (const [key, value] of Object.entries(context)) if (value !== undefined && !/(user_id|content|text|prompt|secret|token|url)/i.test(key)) scope.setTag(key, String(value));
    Sentry.captureException(error);
  });
}
