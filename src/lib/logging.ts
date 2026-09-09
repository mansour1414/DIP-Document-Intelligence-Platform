export type LogContext = Record<string, string | number | boolean | undefined>;

function write(level: "info" | "warn" | "error", event: string, context: LogContext = {}) {
  const payload = JSON.stringify({ timestamp: new Date().toISOString(), level, event, ...context });
  console[level](payload);
}

export const logger = {
  info: (event: string, context?: LogContext) => write("info", event, context),
  warn: (event: string, context?: LogContext) => write("warn", event, context),
  error: (event: string, context?: LogContext) => write("error", event, context),
};
