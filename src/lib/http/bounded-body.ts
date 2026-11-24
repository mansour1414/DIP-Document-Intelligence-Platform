/**
 * Bound a request body to a byte ceiling **before** it is buffered (FF-04).
 *
 * ## What this replaces, and why the previous version was a regression
 *
 * The first attempt substituted `request.body` in place with
 * `Object.defineProperty` and left the original `Request` object in use. Routing
 * code calls `request.formData()`, and `formData()` does not read `.body` through
 * the property — it reads the body *state* the request was constructed with. The
 * counting stream had therefore already consumed the source, and the real consumer
 * failed with:
 *
 *     TypeError: Body is unusable: Body has already been read
 *
 * That broke every multipart endpoint, not just the ones under test. The unit tests
 * missed it because they called `.body.getReader()` directly on the stream that had
 * just been substituted — they exercised the substitute, never the consumer.
 *
 * The correct mechanism is a **new `Request`** whose body is the bounded stream.
 * `formData()` then parses the bounded stream like any other body, so the limit and
 * the real consumer are the same path.
 *
 * ## What this can and cannot enforce
 *
 * - **Bytes:** counted as they are pulled, so a missing (`Transfer-Encoding:
 *   chunked`), false or absent `Content-Length` changes only *when* the rejection
 *   happens, never whether it can. The declared length is used solely as a cheap
 *   early exit before any byte is read.
 * - **Backpressure:** the stream is pull-based. It hands one chunk to the consumer
 *   at a time and does not drain ahead of it, so a slow multipart parser does not
 *   cause the whole body to be buffered in this layer.
 * - **Deadline:** enforced *inside* the stream. An `AbortSignal` passed to
 *   `formData()` was measured not to interrupt parsing — a slow body simply kept
 *   reading past the abort — so the deadline is a timer that errors the stream.
 *
 * A `content-length` header is deliberately **removed** from the derived request:
 * the derived body is a different stream and its length is not the declared one.
 * Keeping a false length would also re-introduce the very header this module exists
 * to stop trusting.
 */

export class BodyTooLargeError extends Error {
  readonly code = "SIZE_LIMIT_EXCEEDED";
  constructor(readonly limitBytes: number) {
    super("The request body exceeds the size limit.");
    this.name = "BodyTooLargeError";
  }
}

export class UploadDeadlineError extends Error {
  readonly code = "UPLOAD_TIMEOUT";
  constructor(readonly deadlineMs: number) {
    super("The upload did not complete in time.");
    this.name = "UploadDeadlineError";
  }
}

export type BoundableRequest = {
  headers: { forEach(callback: (value: string, key: string) => void): void; get(name: string): string | null };
  body?: ReadableStream<Uint8Array> | null;
  url: string;
};

/**
 * Multipart framing allowance.
 *
 * A `multipart/form-data` body is larger than the files it carries: boundary
 * lines, part headers and the terminating delimiter. This covers any realistic
 * filename, boundary and several small text parts without letting the overhead
 * itself become a way to smuggle more bytes past a file limit. It is *additive* to
 * the documented per-field payload allowance, never a substitute for it.
 */
export const MULTIPART_OVERHEAD_BYTES = 16 * 1024;

/** Total body budget for a request expected to carry `fileBudget` bytes of files. */
export function multipartBudget(fileBudget: number) {
  return fileBudget + MULTIPART_OVERHEAD_BYTES;
}

export type BuildBoundedOptions = {
  /** Hard ceiling on total body bytes, including multipart framing. */
  limitBytes: number;
  /** Wall-clock ceiling for the consumer to finish pulling the body. */
  deadlineMs?: number;
};

/**
 * Re-issue `request` with a body that cannot exceed `limitBytes`.
 *
 * The returned `Request` is what the caller must use for `formData()` (or any
 * other body read). Its headers are a copy of the original's with `content-length`
 * removed.
 */
export function boundedMultipartRequest<T extends BoundableRequest>(request: T, options: BuildBoundedOptions): Request {
  const { limitBytes, deadlineMs = 120_000 } = options;

  // Cheap early exit only. Never the enforcement.
  const declared = request.headers.get("content-length");
  if (declared) {
    const parsed = Number(declared);
    if (Number.isFinite(parsed) && parsed > limitBytes) throw new BodyTooLargeError(limitBytes);
  }

  const source = request.body;
  // A body-less request (or one already consumed upstream) has nothing to bound;
  // the caller's own validation rejects it.
  if (!source) return new Request(request.url, { method: "POST", headers: cloneHeaders(request), duplex: "half" } as RequestInit);

  let seen = 0;
  let settled = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const reader = source.getReader();

  const finish = (controller: ReadableStreamDefaultController<Uint8Array>, error?: Error) => {
    if (settled) return;
    settled = true;
    if (timer) clearTimeout(timer);
    if (error) controller.error(error);
    else controller.close();
  };

  const bounded = new ReadableStream<Uint8Array>({
    start(controller) {
      // Deadline enforced here rather than through `AbortSignal`: an abort signal
      // was measured not to interrupt `formData()` parsing, which kept reading a
      // slow body indefinitely.
      timer = setTimeout(() => {
        void reader.cancel().catch(() => undefined);
        finish(controller, new UploadDeadlineError(deadlineMs));
      }, deadlineMs);
      // Do not unref in environments without it (browsers/edge).
      (timer as unknown as { unref?: () => void }).unref?.();
    },
    async pull(controller) {
      if (settled) return;
      let result: ReadableStreamReadResult<Uint8Array>;
      try { result = await reader.read(); }
      catch (error) { finish(controller, error instanceof Error ? error : new Error("UPLOAD_READ_FAILED")); return; }
      if (result.done) { finish(controller); return; }
      const chunk = result.value;
      seen += chunk.byteLength;
      if (seen > limitBytes) {
        // The over-limit chunk is never enqueued, so the consumer cannot buffer
        // more than the ceiling.
        await reader.cancel().catch(() => undefined);
        finish(controller, new BodyTooLargeError(limitBytes));
        return;
      }
      try { controller.enqueue(chunk); }
      catch { /* consumer went away; `cancel` cleans up */ }
    },
    cancel(reason) {
      if (timer) clearTimeout(timer);
      settled = true;
      return reader.cancel(reason).catch(() => undefined);
    },
  });

  return new Request(request.url, {
    method: "POST",
    headers: cloneHeaders(request),
    body: bounded,
    duplex: "half",
  } as RequestInit);
}

/** Copy headers, dropping the ones that describe the *original* body. */
function cloneHeaders(request: BoundableRequest) {
  const headers = new Headers();
  request.headers.forEach((value, key) => {
    const name = key.toLowerCase();
    // `content-length` describes a body this request no longer has. `transfer-encoding`
    // is a hop-by-hop claim about framing that the platform already decoded.
    if (name === "content-length" || name === "transfer-encoding") return;
    headers.set(key, value);
  });
  return headers;
}
