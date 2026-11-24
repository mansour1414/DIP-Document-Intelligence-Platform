/**
 * FF-04 — bounded request consumption, tested through the *real* consumer.
 *
 * ## Why this file was rewritten
 *
 * The first version called `.body.getReader()` directly on the stream the wrapper
 * had substituted. That passes even when the application's actual consumer is
 * broken, and it was: `Object.defineProperty(request, "body", …)` left the original
 * `Request` in place, whose body state had already been consumed. Routing code calls
 * `request.formData()`, which threw
 *
 *     TypeError: Body is unusable: Body has already been read
 *
 * on every multipart endpoint. Every case below therefore goes through
 * `formData()` — the same call the routes make — and a "valid multipart request
 * must still parse" case exists specifically so that breaking the consumer can never
 * again be mistaken for a passing test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { FORM_FIELDS_JSON_LIMIT } from "../src/lib/pdf/form-types";
import {
  MULTIPART_OVERHEAD_BYTES,
  BodyTooLargeError,
  UploadDeadlineError,
  boundedMultipartRequest,
  multipartBudget,
} from "../src/lib/http/bounded-body";

/** A real multipart request, as a browser or proxy would send it. */
function multipartRequest(fields: Record<string, string | { bytes: number; name: string }>, headers: Record<string, string> = {}) {
  const form = new FormData();
  for (const [key, value] of Object.entries(fields)) {
    if (typeof value === "string") form.set(key, value);
    else form.set(key, new File([new Uint8Array(value.bytes)], value.name, { type: "application/pdf" }));
  }
  return new Request("https://example.test/api/jobs/fill-forms", { method: "POST", body: form, headers });
}

/** A multipart body of known size delivered as a stream, with no Content-Length. */
function streamedRequest(totalBytes: number, chunk = 1024) {
  const boundary = "----dipstream";
  const head = `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="a.pdf"\r\nContent-Type: application/pdf\r\n\r\n`;
  const tail = `\r\n--${boundary}--\r\n`;
  const prefix = new TextEncoder().encode(head);
  const suffix = new TextEncoder().encode(tail);
  let sent = 0;
  return new Request("https://example.test/api/fill-forms/inspect", {
    method: "POST",
    headers: { "content-type": `multipart/form-data; boundary=${boundary}` },
    body: new ReadableStream({
      pull(controller) {
        if (sent === 0) { sent += prefix.length; controller.enqueue(prefix); return; }
        if (sent - prefix.length < totalBytes) {
          const remaining = totalBytes - (sent - prefix.length);
          const size = Math.min(chunk, remaining);
          sent += size;
          controller.enqueue(new Uint8Array(size));
          return;
        }
        controller.enqueue(suffix);
        controller.close();
      },
    }),
    duplex: "half",
  } as RequestInit);
}

test("a valid multipart request still parses through formData()", async () => {
  // The regression: this is the call every route makes, and it must work.
  const bounded = boundedMultipartRequest(multipartRequest({ file: { bytes: 2048, name: "a.pdf" }, options: "{}" }), { limitBytes: 1024 * 1024 });
  const form = await bounded.formData();
  const file = form.get("file");
  assert.ok(file instanceof File, "the file part must survive bounding");
  assert.equal(file.size, 2048);
  assert.equal(form.get("options"), "{}", "text parts must survive bounding too");
});

test("the derived request does not carry a stale Content-Length", async () => {
  // A declaration *within* budget is used only as an early exit and then dropped:
  // the derived body is a different stream, so its length is not the declared one.
  const bounded = boundedMultipartRequest(multipartRequest({ file: { bytes: 64, name: "a.pdf" } }, { "content-length": "5000" }), { limitBytes: multipartBudget(1024) });
  assert.equal(bounded.headers.get("content-length"), null, "a stale declaration must not be forwarded");
  assert.ok((await bounded.formData()).get("file") instanceof File);
});

test("an oversized declaration is rejected before any byte is read", () => {
  assert.throws(
    () => boundedMultipartRequest(multipartRequest({ file: { bytes: 64, name: "a.pdf" } }, { "content-length": "999999" }), { limitBytes: multipartBudget(1024) }),
    BodyTooLargeError,
  );
});

test("an oversized body is rejected while the consumer reads actual bytes", async () => {
  const bounded = boundedMultipartRequest(multipartRequest({ file: { bytes: 20_000, name: "a.pdf" } }), { limitBytes: 4_000 });
  await assert.rejects(() => bounded.formData(), BodyTooLargeError);
});

test("a false Content-Length cannot bypass the limit", async () => {
  const bounded = boundedMultipartRequest(
    multipartRequest({ file: { bytes: 20_000, name: "a.pdf" } }, { "content-length": "10" }),
    { limitBytes: 4_000 },
  );
  await assert.rejects(() => bounded.formData(), BodyTooLargeError);
});

test("a missing Content-Length (chunked) cannot bypass the limit", async () => {
  const bounded = boundedMultipartRequest(streamedRequest(20_000), { limitBytes: 4_000 });
  await assert.rejects(() => bounded.formData(), BodyTooLargeError);
});

test("a streamed body under the limit parses fully", async () => {
  const bounded = boundedMultipartRequest(streamedRequest(3_000), { limitBytes: 4_000 });
  const form = await bounded.formData();
  assert.equal((form.get("file") as File).size, 3_000);
});

test("an upload that outlives the deadline is aborted during consumption", async () => {
  const slow = new Request("https://example.test/x", {
    method: "POST",
    headers: { "content-type": "multipart/form-data; boundary=b" },
    body: new ReadableStream({
      async pull(controller) { await new Promise((resolve) => setTimeout(resolve, 20)); controller.enqueue(new Uint8Array(256)); },
    }),
    duplex: "half",
  } as RequestInit);
  const started = Date.now();
  await assert.rejects(() => boundedMultipartRequest(slow, { limitBytes: 10 * 1024 * 1024, deadlineMs: 120 }).formData(), UploadDeadlineError);
  // Enforced by the stream's timer, which is the only mechanism measured to work:
  // an AbortSignal passed to formData() did not interrupt parsing.
  assert.ok(Date.now() - started < 3_000, "the deadline must fire promptly, not after the body finishes");
});

test("an accepted body at exactly the ceiling passes", async () => {
  const probe = multipartRequest({ file: { bytes: 1_000, name: "a.pdf" } });
  const measured = (await probe.arrayBuffer()).byteLength;
  const again = multipartRequest({ file: { bytes: 1_000, name: "a.pdf" } });
  const bounded = boundedMultipartRequest(again, { limitBytes: measured });
  assert.ok((await bounded.formData()).get("file") instanceof File);
});

test("the multipart overhead allowance is separate and explicit", () => {
  // Framing is not charged to a caller that sends no fields payload.
  assert.equal(multipartBudget(64 * 1024), 64 * 1024 + MULTIPART_OVERHEAD_BYTES);
  assert.ok(MULTIPART_OVERHEAD_BYTES >= 8 * 1024, "framing overhead must clear realistic boundaries and filenames");
});

test("the file allowance, the fields allowance and framing are budgeted separately", () => {
  // Regression: the budget used to be `fileBudget + 16 KiB` for every endpoint, so a
  // Fill Forms request carrying both a maximum PDF and a maximum `fields` payload was
  // ~64 KiB over budget and rejected by the transport — a *valid* request refused
  // before the form validator ran. Each part is now accounted for on its own.
  const fileBytes = 64 * 1024;
  const fieldsBytes = FORM_FIELDS_JSON_LIMIT;
  const total = multipartBudget(fileBytes, { fieldsBytes });

  assert.equal(total, fileBytes + fieldsBytes + MULTIPART_OVERHEAD_BYTES);
  // The old contract could not have fitted this request at all.
  assert.ok(total > fileBytes + MULTIPART_OVERHEAD_BYTES, "the fields payload must not be paid for out of the file allowance");
  assert.ok(fieldsBytes >= 64 * 1024, "the documented fields contract is 64 KiB");
  // And a tool that takes no fields payload is not handed an allowance it cannot use.
  assert.equal(multipartBudget(fileBytes), fileBytes + MULTIPART_OVERHEAD_BYTES);
});

test("a maximum-size fields payload with realistic framing still parses", async () => {
  // The end-to-end version of the regression above: build a real multipart body whose
  // `fields` part is a genuine JSON document at the limit, plus a separate file part
  // with a long filename, and require the real consumer to accept it. The budget must
  // be computed the way the route computes it — `FORM_FIELDS_JSON_LIMIT` reserved.
  const fields = JSON.stringify(
    Object.fromEntries(Array.from({ length: 400 }, (_, index) => [
      `field_${index}`,
      { value: "x".repeat(120), type: "text" },
    ])),
  );
  const fieldsBytes = new TextEncoder().encode(fields).byteLength;
  assert.ok(fieldsBytes <= FORM_FIELDS_JSON_LIMIT, `fixture must be within the contract (${fieldsBytes} bytes)`);

  const request = multipartRequest({ fields, file: { bytes: 64, name: `${"a".repeat(180)}.pdf` } });
  const actualBytes = (await new Request(request.url, { method: "POST", body: await request.arrayBuffer() }).arrayBuffer()).byteLength;
  // Real framing for two parts with a maximum-length filename, not a guessed constant.
  const framingBytes = actualBytes - fieldsBytes - 64;
  assert.ok(framingBytes > 0 && framingBytes < MULTIPART_OVERHEAD_BYTES,
    `framing must be real (${framingBytes}) and must fit the allowance (${MULTIPART_OVERHEAD_BYTES})`);

  const bounded = boundedMultipartRequest(
    multipartRequest({ fields, file: { bytes: 64, name: `${"a".repeat(180)}.pdf` } }),
    { limitBytes: multipartBudget(64, { fieldsBytes: FORM_FIELDS_JSON_LIMIT }) },
  );
  const parsed = await bounded.formData();
  assert.equal(typeof parsed.get("fields"), "string");
  assert.equal((parsed.get("fields") as string).length, fields.length);
  assert.ok(parsed.get("file") instanceof File);
});

test("a body over the combined budget is still refused", async () => {
  // The split must not turn into an unbounded total: the same body minus the fields
  // reservation is still rejected, so the ceiling remains real.
  // 40 KiB of content against a budget of `1 KiB + framing` — comfortably over, so the
  // rejection is about the ceiling and not about framing noise.
  const fields = "x".repeat(4096);
  const request = multipartRequest({ fields, file: { bytes: 40 * 1024, name: "a.pdf" } });
  const bounded = boundedMultipartRequest(request, { limitBytes: multipartBudget(1024) });
  await assert.rejects(() => bounded.formData(), (error: unknown) => error instanceof BodyTooLargeError);
});

test("a body that is already consumed is refused rather than silently empty", async () => {
  const consumed = multipartRequest({ file: { bytes: 32, name: "a.pdf" } });
  await consumed.arrayBuffer();
  // Nothing left to reuse: the derived request must not pretend to be empty and
  // valid, or a caller would see a validation error that misdescribes the cause.
  await assert.rejects(async () => (await boundedMultipartRequest(consumed, { limitBytes: 4096 }).formData()));
});
