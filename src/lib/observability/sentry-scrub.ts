import type { ErrorEvent } from "@sentry/nextjs";

const sensitive = /(authorization|cookie|password|secret|token|api.?key|prompt|document.?text|signed.?url|file.?content)/i;
function scrub(value: unknown, depth = 0): unknown {
  if (depth > 5 || value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((item) => scrub(item, depth + 1));
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sensitive.test(key) ? "[REDACTED]" : scrub(item, depth + 1)]));
}

export function scrubSentryEvent(event: ErrorEvent) {
  const cleaned = scrub(event) as ErrorEvent;
  delete cleaned.user;
  delete cleaned.message;
  for (const value of cleaned.exception?.values ?? []) if (value.value) value.value = "[REDACTED_ERROR_MESSAGE]";
  if (cleaned.request) { delete cleaned.request.data; delete cleaned.request.cookies; if (cleaned.request.url) cleaned.request.url = cleaned.request.url.split("?")[0]; }
  return cleaned;
}
