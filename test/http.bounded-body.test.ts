/**
 * FF-04 — request-byte enforcement, behaviourally.
 *
 * Each case is one of the bypasses the architect identified. They are driven
 * through real `Request` objects and a real `ReadableStream`, so this tests the
 * enforcement mechanism rather than the presence of a header check.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { BodyTooLargeError, MULTIPART_OVERHEAD_BYTES, multipartBudget, withBodyLimit } from "../src/lib/http/bounded-body";

/** A request whose body streams `chunks` of `size` bytes, optionally lying about its length. */
function streamingRequest(chunks: number, size: number, declared?: number) {
  let emitted = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (emitted >= chunks) { controller.close(); return; }
      emitted += 1;
      controller.enqueue(new Uint8Array(size));
    },
  });
  const headers = new Headers();
  if (declared !== undefined) headers.set("content-length", String(declared));
  return new Request("https://example.test/upload", { method: "POST", body, headers, duplex: "half" } as RequestInit);
}

/** Read a bounded request to completion; returns total bytes seen or throws. */
async function drain(request: Request) {
  let total = 0;
  const reader = request.body!.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return total;
    total += value.byteLength;
  }
}

test("a truthful oversized Content-Length is rejected without reading the body", () => {
  const request = streamingRequest(100, 1024, 100 * 1024);
  assert.throws(() => withBodyLimit(request, 50 * 1024), BodyTooLargeError);
});

test("the declared length is an early exit only, never the enforcement", async () => {
  // Declares 1 KiB, streams 100 KiB. The old implementation passed this.
  const request = streamingRequest(100, 1024, 1024);
  const bounded = withBodyLimit(request, 10 * 1024);
  await assert.rejects(() => drain(bounded), BodyTooLargeError);
});

test("a missing Content-Length (chunked) is still bounded", async () => {
  // No header at all: the previous guard was skipped entirely.
  const request = streamingRequest(100, 1024, undefined);
  const bounded = withBodyLimit(request, 10 * 1024);
  await assert.rejects(() => drain(bounded), BodyTooLargeError);
});

test("a body exactly at the limit is accepted", async () => {
  const request = streamingRequest(10, 1024, 10 * 1024);
  const bounded = withBodyLimit(request, 10 * 1024);
  assert.equal(await drain(bounded), 10 * 1024, "a body at the ceiling must pass unchanged");
});

test("one byte over the limit is rejected, and the over-limit chunk is never delivered", async () => {
  const request = streamingRequest(11, 1024, undefined);
  const bounded = withBodyLimit(request, 10 * 1024);
  let delivered = 0;
  const reader = bounded.body!.getReader();
  await assert.rejects(async () => {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      delivered += value.byteLength;
    }
  }, BodyTooLargeError);
  assert.ok(delivered <= 10 * 1024, `consumers must never buffer more than the budget (got ${delivered})`);
});

test("the multipart overhead allowance is explicit and separate from the file budget", () => {
  assert.equal(multipartBudget(100), 100 + MULTIPART_OVERHEAD_BYTES);
  assert.ok(MULTIPART_OVERHEAD_BYTES > 0 && MULTIPART_OVERHEAD_BYTES <= 64 * 1024);
});

test("a request without a body passes through untouched", () => {
  const request = new Request("https://example.test/inspect", { method: "POST" });
  assert.equal(withBodyLimit(request, 10), request);
});

test("a caller cannot smuggle extra bytes with duplicate parts", async () => {
  // Two parts of 8 KiB each under a 10 KiB budget: the budget is on the *body*,
  // so the second part is what crosses the line.
  const request = streamingRequest(2, 8 * 1024, undefined);
  const bounded = withBodyLimit(request, 10 * 1024);
  await assert.rejects(() => drain(bounded), BodyTooLargeError);
});
