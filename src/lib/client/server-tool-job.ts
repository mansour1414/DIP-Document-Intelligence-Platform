/**
 * Client contract for the async Office/OCR job pipeline (PR-0).
 *
 * The browser never talks to a document engine: it enqueues work through
 * `POST /api/jobs/[tool]` (multipart `files` + JSON `options`), polls
 * `GET /api/jobs/status/[jobId]` and downloads the authorized output from
 * `GET /api/files/[fileId]`.
 *
 * Every collaborator (fetch, clock, sleep) is injectable so the contract can be
 * exercised behaviourally in tests without a browser or a running worker.
 */

export type JobFailureCode =
  | "AUTH_REQUIRED"
  | "JOB_NOT_FOUND"
  | "JOB_REJECTED"
  | "JOB_STATUS_UNAVAILABLE"
  | "JOB_FAILED"
  | "JOB_CANCELLED"
  | "JOB_EXPIRED"
  | "OUTPUT_MISSING"
  | "OUTPUT_UNAUTHORIZED"
  | "OUTPUT_DOWNLOAD_FAILED"
  | "STILL_PROCESSING"
  | "ABORTED";

export class ServerToolJobError extends Error {
  readonly code: JobFailureCode;
  readonly jobId?: string;
  /** Machine-readable code returned by the API (for example `INFECTED`). */
  readonly serverCode?: string;
  readonly status?: number;

  constructor(code: JobFailureCode, message: string, options: { jobId?: string; serverCode?: string; status?: number } = {}) {
    super(message);
    this.name = "ServerToolJobError";
    this.code = code;
    this.jobId = options.jobId;
    this.serverCode = options.serverCode;
    this.status = options.status;
  }
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

/** 1s cadence matches the previous implementation and keeps load predictable. */
export const JOB_POLL_INTERVAL_MS = 1_000;
/** Never poll for less than 30s, or longer than 30min, regardless of server hints. */
export const JOB_POLL_MIN_BUDGET_MS = 30_000;
export const JOB_POLL_MAX_BUDGET_MS = 30 * 60_000;
/**
 * Fallbacks that mirror `jobPollBudgetMs()` on the server: configurable engine
 * timeout + object-storage persist + queue/retry grace
 * (OCR 300s + 120s, Office 120s + 120s by default). The server sends its own
 * `pollBudgetMs` per job and that value always wins.
 */
export const DEFAULT_POLL_BUDGET_MS = { ocr: 420_000, office: 240_000 } as const;

/** Clamp the polling window to a bounded, maintainable range. */
export function resolvePollBudgetMs(isOcr: boolean, serverBudgetMs?: number | null) {
  const hint = typeof serverBudgetMs === "number" && Number.isFinite(serverBudgetMs) && serverBudgetMs > 0 ? serverBudgetMs : undefined;
  const candidate = hint ?? (isOcr ? DEFAULT_POLL_BUDGET_MS.ocr : DEFAULT_POLL_BUDGET_MS.office);
  return Math.min(Math.max(candidate, JOB_POLL_MIN_BUDGET_MS), JOB_POLL_MAX_BUDGET_MS);
}

export type JobState = "pending" | "succeeded" | "failed" | "cancelled" | "expired";
export type JobStatusView = { state: JobState; outputFileIds: string[]; code?: string; message?: string; pollBudgetMs?: number };

const TERMINAL_STATES = new Set<JobState>(["succeeded", "failed", "cancelled", "expired"]);

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function messageOf(value: unknown): string | undefined {
  if (typeof value === "string") return value.trim() || undefined;
  const record = asRecord(value);
  const message = record && typeof record.message === "string" ? record.message.trim() : "";
  return message || undefined;
}

/** Normalise a `GET /api/jobs/status/[jobId]` payload. Pure and failure-safe. */
export function readJobStatus(payload: unknown): JobStatusView {
  const record = asRecord(payload) ?? {};
  const raw = typeof record.status === "string" ? record.status.toLowerCase() : "";
  const state: JobState = raw === "succeeded" || raw === "failed" || raw === "cancelled" || raw === "expired" ? raw : "pending";
  const result = asRecord(record.result);
  const outputFileIds = Array.isArray(result?.outputFileIds) ? result!.outputFileIds.filter((id): id is string => typeof id === "string" && id.length > 0) : [];
  const code = typeof record.errorCode === "string" && record.errorCode ? record.errorCode : undefined;
  const pollBudgetMs = typeof record.pollBudgetMs === "number" && Number.isFinite(record.pollBudgetMs) && record.pollBudgetMs > 0 ? record.pollBudgetMs : undefined;
  return { state, outputFileIds, ...(code ? { code } : {}), ...(messageOf(record.error) ? { message: messageOf(record.error) } : {}), ...(pollBudgetMs ? { pollBudgetMs } : {}) };
}

async function readJson(response: Response): Promise<Record<string, unknown>> {
  try { return asRecord(await response.json()) ?? {}; } catch { return {}; }
}

export type SubmitInput = {
  toolId: string;
  file: Blob & { name?: string };
  options?: Record<string, string | number | boolean>;
  /** Stable per selected file so a retried submit cannot create a second job. */
  idempotencyKey: string;
  correlationId?: string;
  fetchImpl?: FetchLike;
};

export type SubmitResult = { jobId: string; correlationId: string; reused: boolean; status: string };

/** Enqueue a document job with the exact multipart/header contract of `POST /api/jobs/[tool]`. */
export async function submitServerToolJob(input: SubmitInput): Promise<SubmitResult> {
  const fetchImpl = input.fetchImpl ?? fetch;
  const correlationId = input.correlationId ?? globalThis.crypto.randomUUID();
  const form = new FormData();
  form.append("files", input.file, input.file.name ?? "document");
  form.set("options", JSON.stringify(input.options ?? {}));
  const response = await fetchImpl(`/api/jobs/${input.toolId}`, {
    method: "POST",
    headers: { "Idempotency-Key": input.idempotencyKey, "X-Correlation-Id": correlationId },
    body: form,
  });
  const payload = await readJson(response);
  const serverCode = typeof payload.code === "string" ? payload.code : undefined;
  const serverMessage = typeof payload.message === "string" ? payload.message : undefined;
  if (response.status === 401) throw new ServerToolJobError("AUTH_REQUIRED", serverMessage ?? "Sign in to process documents.", { serverCode, status: 401 });
  if (!response.ok) throw new ServerToolJobError("JOB_REJECTED", serverMessage ?? "The job could not be queued.", { serverCode, status: response.status });
  const jobId = typeof payload.jobId === "string" ? payload.jobId : "";
  if (!jobId) throw new ServerToolJobError("JOB_REJECTED", serverMessage ?? "The job was accepted without an identifier.", { serverCode, status: response.status });
  return { jobId, correlationId: typeof payload.correlationId === "string" ? payload.correlationId : correlationId, reused: payload.reused === true, status: typeof payload.status === "string" ? payload.status : "queued" };
}

export type PollInput = {
  jobId: string;
  isOcr: boolean;
  /** Server-provided budget from the submit/status response, when available. */
  budgetMs?: number;
  fetchImpl?: FetchLike;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  signal?: AbortSignal;
};

export type PollResult = { jobId: string; fileId: string; outputFileIds: string[] };

/**
 * Poll a job until it reaches a terminal state.
 *
 * The loop is bounded by the job's own polling budget. When the budget expires
 * while the worker is still running the call throws `STILL_PROCESSING` — never
 * `JOB_FAILED` — so the UI can say "still processing" and resume with the same
 * job id instead of submitting a duplicate job.
 */
export async function pollJobOutput(input: PollInput): Promise<PollResult> {
  const fetchImpl = input.fetchImpl ?? fetch;
  const sleep = input.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const now = input.now ?? (() => Date.now());
  const startedAt = now();
  const hardAttemptCap = Math.ceil(JOB_POLL_MAX_BUDGET_MS / JOB_POLL_INTERVAL_MS) + 1;
  // An explicit budget (tests, callers with a known deadline) is honoured up to
  // the hard ceiling; a server hint is additionally clamped to the sane window.
  let budgetMs = typeof input.budgetMs === "number" && Number.isFinite(input.budgetMs) && input.budgetMs > 0
    ? Math.min(input.budgetMs, JOB_POLL_MAX_BUDGET_MS)
    : resolvePollBudgetMs(input.isOcr);
  for (let attempt = 0; ; attempt += 1) {
    if (input.signal?.aborted) throw new ServerToolJobError("ABORTED", "Job polling was cancelled.", { jobId: input.jobId });
    if (attempt >= hardAttemptCap) throw new ServerToolJobError("STILL_PROCESSING", "The job is still running.", { jobId: input.jobId });
    const response = await fetchImpl(`/api/jobs/status/${input.jobId}`, { cache: "no-store", ...(input.signal ? { signal: input.signal } : {}) });
    if (response.status === 401) throw new ServerToolJobError("AUTH_REQUIRED", "Sign in to check this job.", { jobId: input.jobId, status: 401 });
    if (response.status === 404) throw new ServerToolJobError("JOB_NOT_FOUND", "This job is no longer available.", { jobId: input.jobId, status: 404 });
    if (!response.ok) throw new ServerToolJobError("JOB_STATUS_UNAVAILABLE", "The job status could not be read.", { jobId: input.jobId, status: response.status });
    const view = readJobStatus(await readJson(response));
    if (view.pollBudgetMs) budgetMs = resolvePollBudgetMs(input.isOcr, view.pollBudgetMs);
    if (view.state === "succeeded") {
      if (!view.outputFileIds.length) throw new ServerToolJobError("OUTPUT_MISSING", view.message ?? "The worker finished without an output file.", { jobId: input.jobId });
      return { jobId: input.jobId, fileId: view.outputFileIds[0], outputFileIds: view.outputFileIds };
    }
    if (TERMINAL_STATES.has(view.state)) {
      const code: JobFailureCode = view.state === "failed" ? "JOB_FAILED" : view.state === "cancelled" ? "JOB_CANCELLED" : "JOB_EXPIRED";
      throw new ServerToolJobError(code, view.message ?? "The worker could not process this document.", { jobId: input.jobId, serverCode: view.code });
    }
    if (now() - startedAt >= budgetMs) throw new ServerToolJobError("STILL_PROCESSING", "The worker is still processing this document.", { jobId: input.jobId });
    await sleep(JOB_POLL_INTERVAL_MS);
  }
}

/** Strip path separators, quotes and control characters from a download name. */
export function filenameFromDisposition(disposition: string | null): string | undefined {
  if (!disposition) return undefined;
  const match = /filename\*=UTF-8''([^;]+)|filename="?([^";]+)"?/i.exec(disposition);
  const raw = (match?.[1] ?? match?.[2] ?? "").trim();
  if (!raw) return undefined;
  let decoded = raw;
  try { decoded = decodeURIComponent(raw); } catch { decoded = raw; }
  const clean = decoded.replace(/[\u0000-\u001f"'\\/]/g, "_").replace(/\s+/g, " ").trim();
  return clean || undefined;
}

export type DownloadInput = { fileId: string; fallbackName?: string; fetchImpl?: FetchLike; signal?: AbortSignal };
export type DownloadResult = { blob: Blob; filename: string };

/** Fetch an authorized output; 401/403/404 are reported as `OUTPUT_UNAUTHORIZED` without a body. */
export async function downloadServerToolOutput(input: DownloadInput): Promise<DownloadResult> {
  const fetchImpl = input.fetchImpl ?? fetch;
  const response = await fetchImpl(`/api/files/${input.fileId}`, { cache: "no-store", ...(input.signal ? { signal: input.signal } : {}) });
  if (response.status === 401 || response.status === 403 || response.status === 404) throw new ServerToolJobError("OUTPUT_UNAUTHORIZED", "This output is not available for your account.", { status: response.status });
  if (!response.ok) throw new ServerToolJobError("OUTPUT_DOWNLOAD_FAILED", "The output file could not be downloaded.", { status: response.status });
  const blob = await response.blob();
  return { blob, filename: filenameFromDisposition(response.headers.get("content-disposition")) ?? input.fallbackName ?? `${input.fileId}.bin` };
}

export type SubmissionRequest = {
  toolId: string;
  options?: Record<string, string | number | boolean>;
  file: { name?: string; size?: number; lastModified?: number };
};

export type PendingSubmission = { key: string; fingerprint: string };

/**
 * Stable description of exactly what was submitted. Two submissions with the
 * same fingerprint are the same operation; any change to the tool, the file or
 * the options (for example the OCR language) is a different operation and must
 * not silently reuse the previous job.
 */
export function submissionFingerprint(request: SubmissionRequest) {
  const options = Object.keys(request.options ?? {}).sort().map((name) => [name, request.options?.[name]]);
  return JSON.stringify({
    toolId: request.toolId,
    options,
    file: { name: request.file.name ?? "", size: request.file.size ?? 0, lastModified: request.file.lastModified ?? 0 },
  });
}

/**
 * Resolve the idempotency key for a submission.
 *
 * A retained key is reused only when the new request is byte-for-byte the same
 * operation (same fingerprint) — that is what makes an ambiguous retry safe.
 * Changing the OCR language, the file or the tool therefore starts a genuinely
 * new operation under a new key instead of attaching to the original job.
 */
export function idempotencyFor(
  pending: PendingSubmission | null,
  request: SubmissionRequest,
  createKey: () => string = () => globalThis.crypto.randomUUID(),
): PendingSubmission {
  const fingerprint = submissionFingerprint(request);
  if (pending && pending.fingerprint === fingerprint) return pending;
  return { key: createKey(), fingerprint };
}

/**
 * Keep the submitted idempotency key only when the outcome is unknown
 * (timeout, aborted poll, unreadable status, transport error). Re-submitting
 * with the same key lets the API reuse the existing job instead of creating a
 * duplicate; terminal outcomes always release the key.
 */
export function retainsIdempotencyKey(error: unknown) {
  if (!(error instanceof ServerToolJobError)) return true;
  return error.code === "STILL_PROCESSING" || error.code === "ABORTED" || error.code === "JOB_STATUS_UNAVAILABLE";
}

/** Bounded retry schedule for retrieving an already-produced output. */
export const DOWNLOAD_RETRY_ATTEMPTS = 3;
export const DOWNLOAD_RETRY_DELAY_MS = 500;

/**
 * Download an output that the worker already produced, retrying transient
 * transport/5xx failures only.
 *
 * This never submits work: a failed download must not turn into a second
 * processing execution. Authorization failures (401/403/404) are returned
 * immediately because retrying them cannot succeed.
 */
export async function downloadServerToolOutputWithRetry(
  input: DownloadInput & { attempts?: number; sleep?: (ms: number) => Promise<void> },
): Promise<DownloadResult> {
  const attempts = Math.min(Math.max(input.attempts ?? DOWNLOAD_RETRY_ATTEMPTS, 1), DOWNLOAD_RETRY_ATTEMPTS);
  const sleep = input.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  let lastError: unknown;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await downloadServerToolOutput(input);
    } catch (error) {
      lastError = error;
      const retryable = error instanceof ServerToolJobError && error.code === "OUTPUT_DOWNLOAD_FAILED";
      if (!retryable || attempt === attempts - 1) throw error;
      await sleep(DOWNLOAD_RETRY_DELAY_MS * (attempt + 1));
    }
  }
  throw lastError;
}

/** Human-readable, locale-neutral rendering of a pipeline failure. */
export function formatJobError(error: unknown): string {
  if (error instanceof ServerToolJobError) return error.serverCode ? `${error.serverCode}: ${error.message}` : `${error.code}: ${error.message}`;
  return error instanceof Error ? error.message : "PROCESSING_FAILED: The document could not be processed.";
}

/**
 * Guards a single component run: blocks duplicate submissions and invalidates
 * in-flight responses when the user clears the selection or the component
 * unmounts, so a stale response can never repopulate a cleared output.
 */
export type RunGuard = {
  start(): number;
  current(): number;
  isCurrent(run: number): boolean;
  finish(run: number): void;
  cancel(): void;
  busy(): boolean;
};

export function createRunGuard(): RunGuard {
  let token = 0;
  let inFlight = false;
  return {
    start() { if (inFlight) return -1; inFlight = true; token += 1; return token; },
    current() { return token; },
    isCurrent(run: number) { return run >= 0 && run === token; },
    finish(run: number) { if (run === token) inFlight = false; },
    cancel() { token += 1; inFlight = false; },
    busy() { return inFlight; },
  };
}
