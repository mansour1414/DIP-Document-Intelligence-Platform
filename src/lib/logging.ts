export type LogContext = Record<string, string | number | boolean | undefined>;

const sensitiveKey = /(authorization|cookie|content|text|prompt|credential|secret|token(?!s?$)|signed.?url|api.?key|password)/i;
export function redactLogContext(context: LogContext) {
  return Object.fromEntries(Object.entries(context).map(([key, value]) => sensitiveKey.test(key) ? [key, "[REDACTED]"] : [key, value])) as LogContext;
}

function write(level: "info" | "warn" | "error", event: string, context: LogContext = {}) {
  const payload = JSON.stringify({ timestamp: new Date().toISOString(), level, event, ...redactLogContext(context) });
  console[level](payload);
}

export const logger = {
  info: (event: string, context?: LogContext) => write("info", event, context),
  warn: (event: string, context?: LogContext) => write("warn", event, context),
  error: (event: string, context?: LogContext) => write("error", event, context),
};
