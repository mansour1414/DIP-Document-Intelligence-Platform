/**
 * Bound a request body to a byte ceiling **before** it is buffered (FF-04).
 *
 * ## What the previous check could not do
 *
 * The inspect route read `Content-Length` and rejected oversized declarations. That
 * is a useful early exit, but it is not an enforcement point: the header is
 * attacker-supplied, may be absent, and — most importantly — does not have to be
 * true. Three shapes defeated it:
 *
 *   - **missing header** (chunked transfer encoding): `declared === undefined`, so
 *     the guard is skipped and `formData()` buffers whatever arrives;
 *   - **wrong header** (declares 1 KiB, sends 900 MiB): the declaration passes and
 *     `formData()` buffers everything;
 *   - **duplicate parts / overhead**: only the *file's* size was checked after
 *     parsing, so N copies of a file plus unbounded part headers were all buffered
 *     before anything was rejected.
 *
 * The only honest enforcement is to count the bytes as they arrive and abort the
 * read the moment the budget is exceeded. That is what this module does.
 *
 * ## Why a stream re-wrap and not a new parser
 *
 * `Request` is a `ReadableStream`. Re-wrapping the body in a counting stream means
 * every consumer — `formData()`, `arrayBuffer()`, anything — pulls through the
 * counter, and crossing the limit errors the stream, which aborts the read. No
 * multipart parser is reimplemented and no dependency is added; the framework's own
 * parser still does the parsing.
 */

export class BodyTooLargeError extends Error {
  readonly code = "SIZE_LIMIT_EXCEEDED";
  constructor(readonly limitBytes: number) {
    super("The request body exceeds the size limit.");
    this.name = "BodyTooLargeError";
  }
}

export type BoundableRequest = {
  headers: { get(name: string): string | null };
  body?: ReadableStream<Uint8Array> | null;
};

/**
 * Re-wrap a request so its body cannot exceed `limitBytes`.
 *
 * The declared `Content-Length`, when present and truthful, is rejected up front so
 * the bytes are never read at all. It is then *ignored* for enforcement purposes:
 * the counting stream is what actually stops the read, so a missing or lying header
 * changes only when the rejection happens, never whether it can.
 *
 * Returns the same kind of object; use it exactly as you would the original.
 */
export function withBodyLimit<T extends BoundableRequest>(request: T, limitBytes: number): T {
  // Early exit only: a truthful oversized declaration is rejected without reading.
  const declared = request.headers.get("content-length");
  if (declared) {
    const parsed = Number(declared);
    if (Number.isFinite(parsed) && parsed > limitBytes) throw new BodyTooLargeError(limitBytes);
  }
  const body = request.body;
  // No stream (already consumed, or a body-less request): nothing to bound.
  if (!body) return request;

  let seen = 0;
  const counter = new ReadableStream<Uint8Array>({
    async start(controller) {
      const reader = body.getReader();
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          seen += value.byteLength;
          // Checked *before* enqueueing, so the over-limit chunk never reaches the
          // consumer and the total buffered stays within budget plus one chunk.
          if (seen > limitBytes) {
            controller.error(new BodyTooLargeError(limitBytes));
            await reader.cancel().catch(() => undefined);
            return;
          }
          controller.enqueue(value);
        }
        controller.close();
      } catch (error) {
        controller.error(error);
      }
    },
  });

  return Object.defineProperty(request, "body", { value: counter, configurable: true, enumerable: true }) as T;
}

/**
 * Multipart framing allowance.
 *
 * A `multipart/form-data` body is larger than the file it carries: boundary lines,
 * part headers and the terminating delimiter. This covers any realistic filename,
 * boundary and a handful of small text parts without letting the overhead itself
 * become a way to smuggle more bytes past a file limit.
 */
export const MULTIPART_OVERHEAD_BYTES = 16 * 1024;

/** Total body budget for a request expected to carry `fileBudget` bytes of files. */
export function multipartBudget(fileBudget: number) {
  return fileBudget + MULTIPART_OVERHEAD_BYTES;
}
