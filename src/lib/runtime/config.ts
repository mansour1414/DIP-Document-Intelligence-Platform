function boundedInteger(name: string, fallback: number, minimum: number, maximum: number) {
  const parsed = Number(process.env[name]);
  return Number.isInteger(parsed) && parsed >= minimum ? Math.min(parsed, maximum) : fallback;
}

export const runtimeLimits = {
  maxInputBytes: boundedInteger("MAX_INPUT_BYTES", 100 * 1024 * 1024, 1024, 500 * 1024 * 1024),
  maxPages: boundedInteger("MAX_PDF_PAGES", 500, 1, 2_000),
  maxPdfObjects: boundedInteger("MAX_PDF_OBJECTS", 100_000, 100, 1_000_000),
  maxRenderedPixelsPerPage: boundedInteger("MAX_RENDERED_PIXELS_PER_PAGE", 40_000_000, 1_000_000, 100_000_000),
  maxOutputFiles: boundedInteger("MAX_OUTPUT_FILES", 500, 1, 2_000),
  maxOutputBytes: boundedInteger("MAX_OUTPUT_BYTES", 250 * 1024 * 1024, 1024, 1024 * 1024 * 1024),
  maxExtractedTextChars: boundedInteger("MAX_EXTRACTED_TEXT_CHARS", 2_000_000, 1_000, 10_000_000),
  maxAiOutputTokens: boundedInteger("MAX_AI_OUTPUT_TOKENS", 8_192, 128, 32_768),
  documentConcurrency: boundedInteger("DOCUMENT_WORKER_CONCURRENCY", 2, 1, 8),
  aiConcurrency: boundedInteger("AI_WORKER_CONCURRENCY", 2, 1, 8),
  aiRatePerMinute: boundedInteger("AI_RATE_LIMIT_PER_MINUTE", 10, 1, 1_000),
  stalledIntervalMs: boundedInteger("QUEUE_STALLED_INTERVAL_MS", 30_000, 5_000, 300_000),
  maxStalledCount: boundedInteger("QUEUE_MAX_STALLED_COUNT", 1, 0, 5),
  jobTimeoutMs: boundedInteger("JOB_TIMEOUT_MS", 180_000, 5_000, 30 * 60_000),
  officeTimeoutMs: boundedInteger("LIBREOFFICE_TIMEOUT_MS", 120_000, 5_000, 15 * 60_000),
  ocrTimeoutMs: boundedInteger("OCR_TIMEOUT_MS", 300_000, 5_000, 30 * 60_000),
  storageTimeoutMs: boundedInteger("STORAGE_TIMEOUT_MS", 30_000, 1_000, 5 * 60_000),
  aiTimeoutMs: boundedInteger("AI_PROVIDER_TIMEOUT_MS", 60_000, 1_000, 10 * 60_000),
} as const;

export type TimeoutClass = "pdf" | "office" | "ocr" | "ai";
export function timeoutFor(resource: TimeoutClass) {
  if (resource === "office") return runtimeLimits.officeTimeoutMs;
  if (resource === "ocr") return runtimeLimits.ocrTimeoutMs;
  if (resource === "ai") return runtimeLimits.aiTimeoutMs;
  return runtimeLimits.jobTimeoutMs;
}

