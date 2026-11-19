/**
 * PR-0 behavioural tests.
 *
 * Every test in this file executes real code: the legacy route handler is
 * invoked, and the async pipeline client contract is driven with a fake fetch,
 * fake clock and fake sleep. No source-string assertions live here (those are
 * in pr0-server-tools-pipeline.test.ts).
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  DEFAULT_POLL_BUDGET_MS,
  DOWNLOAD_RETRY_ATTEMPTS,
  downloadServerToolOutputWithRetry,
  idempotencyFor,
  submissionFingerprint,
  JOB_POLL_INTERVAL_MS,
  JOB_POLL_MAX_BUDGET_MS,
  JOB_POLL_MIN_BUDGET_MS,
  ServerToolJobError,
  createRunGuard,
  downloadServerToolOutput,
  filenameFromDisposition,
  formatJobError,
  pollJobOutput,
  readJobStatus,
  retainsIdempotencyKey,
  resolvePollBudgetMs,
  submitServerToolJob,
} from "../src/lib/client/server-tool-job";
import { jobPollBudgetMs, runtimeLimits } from "../src/lib/runtime/config";
import { MalwareScanError, requireCleanUpload, type MalwareScanner, type MalwareScanResultCode } from "../src/lib/malware";
import { POST as legacyPost } from "../src/app/api/tools/[tool]/route";

const serverTools = ["word-to-pdf", "pdf-to-word", "excel-to-pdf", "powerpoint-to-pdf", "ocr-pdf"] as const;

type Call = { url: string; init?: RequestInit };
function jsonFetch(responses: Array<{ status?: number; body: unknown; headers?: Record<string, string> }>) {
  const calls: Call[] = [];
  let index = 0;
  const fetchImpl = async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    const next = responses[Math.min(index, responses.length - 1)];
    index += 1;
    return new Response(JSON.stringify(next.body), { status: next.status ?? 200, headers: { "content-type": "application/json", ...(next.headers ?? {}) } });
  };
  return { fetchImpl, calls, count: () => index };
}

// ---------------------------------------------------------------- legacy route

test("PR-0 (behaviour): legacy route returns 409 SYNC_PROCESSING_DISABLED for all five tools", async () => {
  for (const tool of serverTools) {
    const response = await legacyPost(new Request(`http://localhost/api/tools/${tool}`, { method: "POST" }), { params: Promise.resolve({ tool }) });
    assert.equal(response.status, 409, tool);
    assert.match(response.headers.get("content-type") ?? "", /application\/json/);
    const body = await response.json() as { code?: string; message?: string; jobId?: string };
    assert.equal(body.code, "SYNC_PROCESSING_DISABLED", tool);
    assert.match(body.message ?? "", new RegExp(`/api/jobs/${tool}`), tool);
    assert.equal(body.jobId, undefined, "the legacy route must never return a job");
  }
});

test("PR-0 (behaviour): legacy route rejects unknown tool ids without processing", async () => {
  for (const tool of ["merge-pdf", "summarize-pdf", "not-a-tool"]) {
    const response = await legacyPost(new Request(`http://localhost/api/tools/${tool}`, { method: "POST" }), { params: Promise.resolve({ tool }) });
    assert.equal(response.status, 404, tool);
    assert.equal((await response.json() as { code?: string }).code, "NOT_FOUND", tool);
  }
});

// ------------------------------------------------------------ submit contract

test("PR-0 (behaviour): submit posts multipart files + JSON options with idempotency and correlation headers", async () => {
  const { fetchImpl, calls } = jsonFetch([{ status: 202, body: { jobId: "job-1", status: "queued", correlationId: "corr-1", reused: false } }]);
  const file = new File([new Uint8Array([1, 2, 3])], "scan.png", { type: "image/png" });
  const result = await submitServerToolJob({ toolId: "ocr-pdf", file, options: { language: "ara" }, idempotencyKey: "idem-1", correlationId: "corr-1", fetchImpl });
  assert.deepEqual(result, { jobId: "job-1", correlationId: "corr-1", reused: false, status: "queued" });
  assert.equal(calls[0].url, "/api/jobs/ocr-pdf");
  assert.equal(calls[0].init?.method, "POST");
  const headers = calls[0].init?.headers as Record<string, string>;
  assert.equal(headers["Idempotency-Key"], "idem-1");
  assert.equal(headers["X-Correlation-Id"], "corr-1");
  const form = calls[0].init?.body as FormData;
  assert.ok(form instanceof FormData);
  const sent = form.getAll("files");
  assert.equal(sent.length, 1);
  assert.equal((sent[0] as File).name, "scan.png");
  assert.equal(form.get("options"), JSON.stringify({ language: "ara" }));
  assert.equal(form.get("file"), null, "the legacy single-file field must not be used");
});

test("PR-0 (behaviour): submit for Office tools sends an empty options object", async () => {
  const { fetchImpl, calls } = jsonFetch([{ status: 202, body: { jobId: "job-2" } }]);
  const file = new File([new Uint8Array([1])], "report.docx", { type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document" });
  await submitServerToolJob({ toolId: "word-to-pdf", file, idempotencyKey: "idem-2", fetchImpl });
  assert.equal((calls[0].init?.body as FormData).get("options"), "{}");
});

test("PR-0 (behaviour): submit surfaces scanner and malware rejections without a job id", async () => {
  const cases: Array<[number, string, string]> = [
    [400, "INFECTED", "This file was rejected by the malware scanner."],
    [400, "SCANNER_UNAVAILABLE", "The malware scanner is unavailable."],
    [409, "TOOL_NOT_WORKER_ENABLED", "This tool has not moved to the worker pipeline yet."],
  ];
  for (const [status, code, message] of cases) {
    const { fetchImpl } = jsonFetch([{ status, body: { code, message } }]);
    const file = new File([new Uint8Array([1])], "doc.pdf", { type: "application/pdf" });
    await assert.rejects(
      () => submitServerToolJob({ toolId: "pdf-to-word", file, idempotencyKey: "idem-x", fetchImpl }),
      (error: unknown) => error instanceof ServerToolJobError && error.code === "JOB_REJECTED" && error.serverCode === code && error.status === status && error.message === message,
      code,
    );
  }
});

test("PR-0 (behaviour): submit maps 401 to AUTH_REQUIRED and an id-less 202 to JOB_REJECTED", async () => {
  const unauthorized = jsonFetch([{ status: 401, body: { code: "AUTH_REQUIRED", message: "Sign in to process documents." } }]);
  await assert.rejects(
    () => submitServerToolJob({ toolId: "ocr-pdf", file: new File([new Uint8Array([1])], "a.pdf"), idempotencyKey: "k", fetchImpl: unauthorized.fetchImpl }),
    (error: unknown) => error instanceof ServerToolJobError && error.code === "AUTH_REQUIRED" && error.status === 401,
  );
  const empty = jsonFetch([{ status: 202, body: {} }]);
  await assert.rejects(
    () => submitServerToolJob({ toolId: "ocr-pdf", file: new File([new Uint8Array([1])], "a.pdf"), idempotencyKey: "k", fetchImpl: empty.fetchImpl }),
    (error: unknown) => error instanceof ServerToolJobError && error.code === "JOB_REJECTED",
  );
});

// -------------------------------------------------------------- poll contract

function clock(start = 0, step = JOB_POLL_INTERVAL_MS) {
  let value = start;
  return { now: () => value, sleep: async (ms: number) => { value += Math.max(ms, step); }, elapsed: () => value };
}

test("PR-0 (behaviour): polling waits through queued/running and returns the authorized output id", async () => {
  const { fetchImpl, calls } = jsonFetch([
    { body: { status: "queued" } },
    { body: { status: "running" } },
    { body: { status: "retrying" } },
    { body: { status: "succeeded", result: { outputFileIds: ["file-1"] } } },
  ]);
  const time = clock();
  const result = await pollJobOutput({ jobId: "job-1", isOcr: true, fetchImpl, now: time.now, sleep: time.sleep });
  assert.deepEqual(result, { jobId: "job-1", fileId: "file-1", outputFileIds: ["file-1"] });
  assert.equal(calls.length, 4);
  assert.equal(calls[0].url, "/api/jobs/status/job-1");
});

test("PR-0 (behaviour): failed, cancelled and expired jobs surface distinct localized-safe errors", async () => {
  const expectations: Array<[string, string, string]> = [
    ["failed", "JOB_FAILED", "LibreOffice could not convert this document."],
    ["cancelled", "JOB_CANCELLED", "The job was cancelled."],
    ["expired", "JOB_EXPIRED", "The job expired before it completed."],
  ];
  for (const [state, code, message] of expectations) {
    const { fetchImpl } = jsonFetch([{ body: { status: state, errorCode: `${state.toUpperCase()}_CODE`, error: { message } } }]);
    const time = clock();
    await assert.rejects(
      () => pollJobOutput({ jobId: "job-2", isOcr: false, fetchImpl, now: time.now, sleep: time.sleep }),
      (error: unknown) => error instanceof ServerToolJobError && error.code === code && error.message === message && error.serverCode === `${state.toUpperCase()}_CODE`,
      state,
    );
  }
});

test("PR-0 (behaviour): a succeeded job without output files is an error, not a silent success", async () => {
  const { fetchImpl } = jsonFetch([{ body: { status: "succeeded", result: {} } }, { body: { status: "succeeded", result: { outputFileIds: [] } } }]);
  const time = clock();
  for (let attempt = 0; attempt < 2; attempt += 1) {
    await assert.rejects(
      () => pollJobOutput({ jobId: "job-3", isOcr: false, fetchImpl, now: time.now, sleep: time.sleep }),
      (error: unknown) => error instanceof ServerToolJobError && error.code === "OUTPUT_MISSING",
    );
  }
});

test("PR-0 (behaviour): status authorization failures are reported without inventing a job failure", async () => {
  for (const [status, code] of [[401, "AUTH_REQUIRED"], [404, "JOB_NOT_FOUND"], [500, "JOB_STATUS_UNAVAILABLE"]] as const) {
    const { fetchImpl } = jsonFetch([{ status, body: { code: "NOT_FOUND" } }]);
    const time = clock();
    await assert.rejects(
      () => pollJobOutput({ jobId: "job-4", isOcr: true, fetchImpl, now: time.now, sleep: time.sleep }),
      (error: unknown) => error instanceof ServerToolJobError && error.code === code,
      String(status),
    );
  }
});

test("PR-0 (behaviour): a still-running job reports STILL_PROCESSING, never a failure, when the budget ends", async () => {
  const { fetchImpl, count } = jsonFetch([{ body: { status: "running" } }]);
  const time = clock();
  await assert.rejects(
    () => pollJobOutput({ jobId: "job-5", isOcr: false, fetchImpl, now: time.now, sleep: time.sleep, budgetMs: 5_000 }),
    (error: unknown) => error instanceof ServerToolJobError && error.code === "STILL_PROCESSING" && error.jobId === "job-5",
  );
  // Bounded: 5s budget / 1s interval plus the terminal-exit check.
  assert.equal(count(), 6);
  assert.ok(count() <= Math.ceil(5_000 / JOB_POLL_INTERVAL_MS) + 1);
});

test("PR-0 (behaviour): the server-provided budget wins and is clamped to a bounded window", async () => {
  const hint = 40_000;
  const hinted = jsonFetch([{ body: { status: "running", pollBudgetMs: hint } }]);
  const time = clock();
  await assert.rejects(
    () => pollJobOutput({ jobId: "job-6", isOcr: true, fetchImpl: hinted.fetchImpl, now: time.now, sleep: time.sleep }),
    (error: unknown) => error instanceof ServerToolJobError && error.code === "STILL_PROCESSING",
  );
  assert.equal(hinted.count(), Math.ceil(hint / JOB_POLL_INTERVAL_MS) + 1, "the server hint, not the client default, must bound polling");

  assert.equal(resolvePollBudgetMs(true, 1_000), JOB_POLL_MIN_BUDGET_MS);
  assert.equal(resolvePollBudgetMs(false, 10 * 60 * 60_000), JOB_POLL_MAX_BUDGET_MS);
  assert.equal(resolvePollBudgetMs(true, 123_456), 123_456);
  assert.equal(resolvePollBudgetMs(true, Number.NaN), DEFAULT_POLL_BUDGET_MS.ocr);
  assert.equal(resolvePollBudgetMs(false, undefined), DEFAULT_POLL_BUDGET_MS.office);
});

test("PR-0 (behaviour): aborted polling stops without touching job state", async () => {
  const controller = new AbortController();
  controller.abort();
  const { fetchImpl, count } = jsonFetch([{ body: { status: "running" } }]);
  await assert.rejects(
    () => pollJobOutput({ jobId: "job-7", isOcr: false, fetchImpl, signal: controller.signal }),
    (error: unknown) => error instanceof ServerToolJobError && error.code === "ABORTED",
  );
  assert.equal(count(), 0);
});

test("PR-0 (behaviour): status payloads are normalised defensively", () => {
  assert.deepEqual(readJobStatus({ status: "SUCCEEDED", result: { outputFileIds: ["a", 7, "", "b"] } }), { state: "succeeded", outputFileIds: ["a", "b"] });
  assert.deepEqual(readJobStatus({ status: "RUNNING" }), { state: "pending", outputFileIds: [] });
  assert.equal(readJobStatus({ status: "mystery" }).state, "pending");
  assert.deepEqual(readJobStatus(null), { state: "pending", outputFileIds: [] });
  assert.equal(readJobStatus({ status: "failed", error: "boom" }).message, "boom");
});

// ------------------------------------------------------------ download access

test("PR-0 (behaviour): authorized download returns the blob and a sanitized filename", async () => {
  const body = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
  const fetchImpl = async (url: string) => { assert.equal(url, "/api/files/file-1"); return new Response(body, { status: 200, headers: { "content-disposition": "attachment; filename=\"converted output.pdf\"" } }); };
  const result = await downloadServerToolOutput({ fileId: "file-1", fetchImpl });
  assert.equal(result.filename, "converted output.pdf");
  assert.deepEqual(new Uint8Array(await result.blob.arrayBuffer()), body);
});

test("PR-0 (behaviour): unauthorized output access never yields a file", async () => {
  for (const status of [401, 403, 404]) {
    const fetchImpl = async () => new Response(JSON.stringify({ code: "NOT_FOUND" }), { status, headers: { "content-type": "application/json" } });
    await assert.rejects(
      () => downloadServerToolOutput({ fileId: "someone-elses-file", fetchImpl }),
      (error: unknown) => error instanceof ServerToolJobError && error.code === "OUTPUT_UNAUTHORIZED" && error.status === status,
      String(status),
    );
  }
  await assert.rejects(
    () => downloadServerToolOutput({ fileId: "file", fetchImpl: async () => new Response("nope", { status: 500 }) }),
    (error: unknown) => error instanceof ServerToolJobError && error.code === "OUTPUT_DOWNLOAD_FAILED",
  );
});

test("PR-0 (behaviour): download filenames cannot escape the attachment directory", () => {
  assert.equal(filenameFromDisposition('attachment; filename="../../etc/passwd"'), ".._.._etc_passwd");
  assert.equal(filenameFromDisposition("attachment; filename*=UTF-8''%D8%AA%D9%82%D8%B1%D9%8A%D8%B1.pdf"), "تقرير.pdf");
  assert.equal(filenameFromDisposition(null), undefined);
  assert.equal(filenameFromDisposition('attachment; filename=""'), undefined);
});

// ------------------------------------------------------------------ UI guards

test("PR-0 (behaviour): the run guard blocks duplicate submissions and invalidates stale responses", () => {
  const guard = createRunGuard();
  const first = guard.start();
  assert.equal(first, 1);
  assert.equal(guard.busy(), true);
  assert.equal(guard.start(), -1, "a second submit while one is in flight must be refused");
  assert.equal(guard.isCurrent(first), true);

  guard.cancel();
  assert.equal(guard.busy(), false);
  assert.equal(guard.isCurrent(first), false, "a response from a cleared run must not restore output");

  const second = guard.start();
  assert.ok(second > first);
  assert.equal(guard.isCurrent(second), true);
  guard.finish(second);
  assert.equal(guard.busy(), false);
  assert.equal(guard.isCurrent(second), true, "finishing keeps the token so the success render is not lost");

  // A stale run finishing must not unlock the current run.
  const third = guard.start();
  guard.finish(second);
  assert.equal(guard.busy(), true);
  guard.finish(third);
  assert.equal(guard.busy(), false);
});

test("PR-0 (behaviour): a retry after an unknown outcome reuses the idempotency key", () => {
  for (const code of ["STILL_PROCESSING", "ABORTED", "JOB_STATUS_UNAVAILABLE"] as const) {
    assert.equal(retainsIdempotencyKey(new ServerToolJobError(code, "unknown outcome")), true, code);
  }
  assert.equal(retainsIdempotencyKey(new TypeError("network down")), true, "a transport failure must not release the key");
  for (const code of ["JOB_FAILED", "JOB_CANCELLED", "JOB_EXPIRED", "JOB_REJECTED", "AUTH_REQUIRED", "OUTPUT_MISSING", "OUTPUT_UNAUTHORIZED"] as const) {
    assert.equal(retainsIdempotencyKey(new ServerToolJobError(code, "terminal")), false, code);
  }
});

test("PR-0 (behaviour): an ambiguous OCR submission followed by a language change starts a new operation", async () => {
  const file = new File([new Uint8Array([1, 2, 3])], "scan.pdf", { type: "application/pdf" });
  const original = { toolId: "ocr-pdf", options: { language: "ara" }, file };
  const first = idempotencyFor(null, original, () => "key-original");

  // Ambiguous outcome: the job may or may not exist, so the key is retained.
  const ambiguous = new ServerToolJobError("JOB_STATUS_UNAVAILABLE", "status unreadable", { jobId: "job-1", status: 500 });
  assert.equal(retainsIdempotencyKey(ambiguous), true);

  // Retrying the identical request reuses the key (the API would reuse job-1).
  assert.equal(idempotencyFor(first, { ...original, options: { language: "ara" } }, () => "key-retry").key, "key-original");
  // Option key order must not change the identity of the request.
  assert.equal(submissionFingerprint({ ...original, options: { language: "ara" } }), submissionFingerprint(original));

  // Changing the OCR language is a different operation and must not attach to job-1.
  const changedLanguage = idempotencyFor(first, { ...original, options: { language: "eng" } }, () => "key-new-language");
  assert.equal(changedLanguage.key, "key-new-language");
  assert.notEqual(submissionFingerprint({ ...original, options: { language: "eng" } }), first.fingerprint);

  // Prove that the changed request really is submitted under the new key.
  const { fetchImpl, calls } = jsonFetch([{ status: 202, body: { jobId: "job-2" } }]);
  await submitServerToolJob({ ...original, options: { language: "eng" }, idempotencyKey: changedLanguage.key, fetchImpl });
  assert.equal((calls[0].init?.headers as Record<string, string>)["Idempotency-Key"], "key-new-language");
  assert.equal((calls[0].init?.body as FormData).get("options"), JSON.stringify({ language: "eng" }));

  // A different file or tool is likewise a new operation.
  const otherFile = new File([new Uint8Array([9])], "scan.pdf", { type: "application/pdf" });
  assert.notEqual(idempotencyFor(first, { ...original, file: otherFile }, () => "key-other-file").key, "key-original");
  assert.notEqual(idempotencyFor(first, { ...original, toolId: "pdf-to-word" }, () => "key-other-tool").key, "key-original");
});

test("PR-0 (behaviour): a transient output download failure retries without a second job", async () => {
  const calls: string[] = [];
  let statusReads = 0;
  let downloadAttempts = 0;
  const fetchImpl = async (url: string, init?: RequestInit) => {
    calls.push(`${init?.method ?? "GET"} ${url}`);
    if (url === "/api/jobs/ocr-pdf") return new Response(JSON.stringify({ jobId: "job-download", status: "queued" }), { status: 202, headers: { "content-type": "application/json" } });
    if (url.startsWith("/api/jobs/status/")) { statusReads += 1; return new Response(JSON.stringify({ status: "succeeded", result: { outputFileIds: ["file-download"] } }), { status: 200 }); }
    if (url === "/api/files/file-download") {
      downloadAttempts += 1;
      if (downloadAttempts < 3) return new Response("upstream unavailable", { status: 500 });
      return new Response(new Uint8Array([0x25, 0x50, 0x44, 0x46]), { status: 200, headers: { "content-disposition": 'attachment; filename="out.pdf"' } });
    }
    throw new Error(`unexpected request ${url}`);
  };

  const file = new File([new Uint8Array([1])], "scan.pdf", { type: "application/pdf" });
  const submission = await submitServerToolJob({ toolId: "ocr-pdf", file, options: { language: "ara" }, idempotencyKey: "idem-download", fetchImpl });
  const time = clock();
  const poll = await pollJobOutput({ jobId: submission.jobId, isOcr: true, fetchImpl, now: time.now, sleep: time.sleep });
  const download = await downloadServerToolOutputWithRetry({ fileId: poll.fileId, fetchImpl, sleep: async () => {} });

  assert.equal(download.filename, "out.pdf");
  assert.equal(statusReads, 1, "one status read for one finished job");
  assert.equal(downloadAttempts, 3, "the download is retried up to three times");
  assert.equal(calls.filter((call) => call.startsWith("POST /api/jobs")).length, 1, "exactly one processing job is created");
  assert.equal(calls.filter((call) => call.startsWith("POST ")).length, 1, "no retry may submit work");
});

test("PR-0 (behaviour): a persistent download failure keeps the produced output addressable for another attempt", async () => {
  const posts: string[] = [];
  let failDownload = true;
  const fetchImpl = async (url: string, init?: RequestInit) => {
    if (init?.method === "POST") { posts.push(url); return new Response(JSON.stringify({ jobId: "job-x" }), { status: 202 }); }
    if (url === "/api/files/file-keep") {
      if (failDownload) return new Response("still failing", { status: 503 });
      return new Response(new Uint8Array([1, 2]), { status: 200, headers: { "content-disposition": 'attachment; filename="kept.pdf"' } });
    }
    throw new Error(`unexpected ${url}`);
  };

  await assert.rejects(
    () => downloadServerToolOutputWithRetry({ fileId: "file-keep", fetchImpl, sleep: async () => {} }),
    (error: unknown) => error instanceof ServerToolJobError && error.code === "OUTPUT_DOWNLOAD_FAILED",
  );
  assert.equal(posts.length, 0, "a failed download must never enqueue processing work");

  // The retained file id still resolves once the transient fault clears.
  failDownload = false;
  const retried = await downloadServerToolOutputWithRetry({ fileId: "file-keep", fetchImpl, sleep: async () => {} });
  assert.equal(retried.filename, "kept.pdf");
  assert.equal(posts.length, 0, "the retry is a download only, not a new job");
});

test("PR-0 (behaviour): authorization failures are not retried", async () => {
  let attempts = 0;
  const fetchImpl = async () => { attempts += 1; return new Response(JSON.stringify({ code: "NOT_FOUND" }), { status: 404 }); };
  await assert.rejects(
    () => downloadServerToolOutputWithRetry({ fileId: "not-mine", fetchImpl, sleep: async () => { throw new Error("must not sleep"); } }),
    (error: unknown) => error instanceof ServerToolJobError && error.code === "OUTPUT_UNAUTHORIZED",
  );
  assert.equal(attempts, 1, "401/403/404 must not be retried");
  assert.equal(DOWNLOAD_RETRY_ATTEMPTS, 3);
});

test("PR-0 (behaviour): failures render a machine code with a readable message", () => {
  assert.equal(formatJobError(new ServerToolJobError("JOB_FAILED", "boom", { serverCode: "ENGINE_UNAVAILABLE" })), "ENGINE_UNAVAILABLE: boom");
  assert.equal(formatJobError(new ServerToolJobError("STILL_PROCESSING", "still running")), "STILL_PROCESSING: still running");
  assert.equal(formatJobError(new Error("network down")), "network down");
  assert.match(formatJobError(undefined), /PROCESSING_FAILED/);
});

// ------------------------------------------------- server-side budget contract

test("PR-0 (behaviour): the server polling budget follows the configurable worker timeouts", () => {
  assert.equal(jobPollBudgetMs("ocr-pdf"), runtimeLimits.ocrTimeoutMs + runtimeLimits.storageTimeoutMs + 90_000);
  for (const tool of ["word-to-pdf", "pdf-to-word", "excel-to-pdf", "powerpoint-to-pdf"]) {
    assert.equal(jobPollBudgetMs(tool), runtimeLimits.officeTimeoutMs + runtimeLimits.storageTimeoutMs + 90_000, tool);
  }
  assert.ok(jobPollBudgetMs("ocr-pdf") > jobPollBudgetMs("word-to-pdf"), "OCR must be allowed longer than Office");
  assert.ok(jobPollBudgetMs("ocr-pdf") > runtimeLimits.ocrTimeoutMs, "the budget must exceed the engine timeout");
  assert.ok(jobPollBudgetMs("ocr-pdf") <= JOB_POLL_MAX_BUDGET_MS);
});

// ------------------------------------------------------- malware gate (real)

const scanner = (result: MalwareScanResultCode): MalwareScanner => ({
  async scan() { return { result, engine: "test-scanner", engineVersion: "1", signatureVersion: "safe-test", scannedAt: new Date(0) }; },
});
const malwareBytes = new TextEncoder().encode("PR0 harmless fixture, never a real payload");

test("PR-0 (behaviour): a rejected upload never reaches a clean result (malware gate fails closed)", async () => {
  for (const code of ["INFECTED", "SCAN_ERROR", "SCAN_TIMEOUT", "SCANNER_UNAVAILABLE"] as const) {
    const recorded: string[] = [];
    await assert.rejects(
      () => requireCleanUpload(malwareBytes, scanner(code), async (verdict) => { recorded.push(verdict); }),
      (error: unknown) => error instanceof MalwareScanError && error.code === code,
      code,
    );
    assert.deepEqual(recorded, [code], `${code} must be recorded exactly once`);
  }
});

test("PR-0 (behaviour): scanner unavailability is a rejection, not a bypass", async () => {
  await assert.rejects(
    () => requireCleanUpload(malwareBytes, { async scan() { throw new Error("socket closed"); } }, async () => {}),
    (error: unknown) => error instanceof MalwareScanError && error.code === "SCAN_ERROR",
  );
  // Without CLAMD_HOST the default scanner must refuse rather than accept.
  const previous = process.env.CLAMD_HOST;
  delete process.env.CLAMD_HOST;
  try {
    await assert.rejects(() => requireCleanUpload(malwareBytes), (error: unknown) => error instanceof MalwareScanError && error.code === "SCANNER_UNAVAILABLE");
  } finally {
    if (previous !== undefined) process.env.CLAMD_HOST = previous;
  }
});

test("PR-0 (behaviour): a clean upload returns checksum metadata only", async () => {
  const clean = await requireCleanUpload(malwareBytes, scanner("CLEAN"), async () => { throw new Error("must not record"); });
  assert.match(clean.checksumSha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(Object.keys(clean).sort(), ["checksumSha256", "engine", "engineVersion", "scannedAt", "signatureVersion"]);
});
