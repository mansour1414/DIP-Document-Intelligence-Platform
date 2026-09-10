import * as Sentry from "@sentry/nextjs";
import { scrubSentryEvent } from "./src/lib/observability/sentry-scrub";

Sentry.init({
  dsn: process.env.SENTRY_DSN || undefined,
  enabled: Boolean(process.env.SENTRY_DSN),
  environment: process.env.NODE_ENV,
  tracesSampleRate: Number(process.env.SENTRY_TRACES_SAMPLE_RATE ?? "0.05"),
  sendDefaultPii: false,
  beforeSend: scrubSentryEvent,
});

