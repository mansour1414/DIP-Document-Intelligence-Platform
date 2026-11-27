/**
 * R7D.1 — bounded provisional result streaming.
 *
 * ## Defect 3, asserted directly
 *
 * The abandoned supervisor collected every result chunk and `Buffer.concat`-ed them. The
 * critical test here is `R7D.1-S-2`: a stream far larger than the reader's buffer capacity
 * must be forwarded **without the reader ever holding it**. If someone reintroduces
 * buffering, peak retained bytes rises with document size and that test fails on the
 * measurement, not on an opinion about the code.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { BoundedProvisionalOutput, ProvisionalResultStream, StreamError, sha256Hex } from "../src/lib/execution/provisional-stream";
import { WORKER_LIMITS } from "../src/lib/pdf/worker-protocol";

/** Build one fd3 frame: `[u32 metaLen][meta JSON][output]`. */
function frame(meta: Record<string, unknown>, output?: Uint8Array): Buffer {
  const json = Buffer.from(JSON.stringify(meta), "utf8");
  const header = Buffer.alloc(4);
  header.writeUInt32BE(json.byteLength, 0);
  return output && output.byteLength > 0 ? Buffer.concat([header, json, Buffer.from(output)]) : Buffer.concat([header, json]);
}

const fillMeta = (outputBytes: number) => ({ ok: true, op: "fill", pages: 1, fields: 1, outputBytes });
const verifyMeta = { ok: true, op: "verify", pages: 1, widgets: 0, preserved: 2 };

// ---------------------------------------------------------------------------------------
// The buffering defect.
// ---------------------------------------------------------------------------------------

test("R7D.1-S-1: a fill result is forwarded chunk by chunk as it arrives", () => {
  const seen: number[] = [];
  const stream = new ProvisionalResultStream({ expectedOp: "fill", sink: (chunk) => seen.push(chunk.bytes.byteLength) });
  const output = Buffer.alloc(3000, 7);
  const bytes = frame(fillMeta(output.byteLength), output);
  // Feed in 100-byte slices, as a pipe would deliver them.
  for (let offset = 0; offset < bytes.byteLength; offset += 100) stream.push(bytes.subarray(offset, Math.min(offset + 100, bytes.byteLength)));
  const done = stream.finish();
  assert.equal(done.outputBytes, 3000);
  assert.ok(seen.length > 1, "output must be forwarded incrementally, not as one blob");
  assert.equal(seen.reduce((a, b) => a + b, 0), 3000);
  assert.equal(done.outputSha256, sha256Hex(output));
});

test("R7D.1-S-2: a result much larger than the reader's capacity is never retained", () => {
  // 8 MiB through a 64 KiB nominal backlog. If the reader buffered, peak retained bytes
  // would be ~8 MiB. Measured here by accounting for every byte the reader could hold.
  const CAP = 64 * 1024;
  const total = 8 * 1024 * 1024;
  let forwarded = 0;
  let peakBacklog = 0;
  const stream = new ProvisionalResultStream({
    expectedOp: "fill",
    maxBufferedBytes: CAP,
    sink: (chunk) => {
      forwarded += chunk.bytes.byteLength;
      peakBacklog = Math.max(peakBacklog, stream.backlogBytes);
      // The caller consumes immediately, as a pipe to the client would.
      stream.acknowledge(chunk.bytes.byteLength);
    },
  });
  const output = Buffer.alloc(total, 3);
  const bytes = frame(fillMeta(total), output);
  for (let offset = 0; offset < bytes.byteLength; offset += CAP) {
    stream.push(bytes.subarray(offset, Math.min(offset + CAP, bytes.byteLength)));
  }
  const done = stream.finish();
  assert.equal(forwarded, total);
  assert.equal(done.outputBytes, total);
  assert.equal(done.outputSha256, sha256Hex(output));
  assert.ok(peakBacklog <= CAP, `peak backlog ${peakBacklog} must stay within ${CAP}`);
});

test("R7D.1-S-3: a consumer that stops reading is refused rather than buffered without bound", () => {
  const stream = new ProvisionalResultStream({ expectedOp: "fill", maxBufferedBytes: 1024, sink: () => { /* never acknowledges */ } });
  const output = Buffer.alloc(64 * 1024, 1);
  const bytes = frame(fillMeta(output.byteLength), output);
  assert.throws(() => stream.push(bytes), (error: unknown) => error instanceof StreamError && error.fault === "BUFFER_EXCEEDED");
});

// ---------------------------------------------------------------------------------------
// Header-first rejection.
// ---------------------------------------------------------------------------------------

test("R7D.1-S-4: an operation mismatch is rejected before any output is forwarded", () => {
  // A container asked for `verify` that answers with a `fill` payload must not get to
  // stream megabytes before anyone notices.
  const seen: number[] = [];
  const stream = new ProvisionalResultStream({ expectedOp: "verify", sink: (chunk) => seen.push(chunk.bytes.byteLength) });
  const bytes = frame(fillMeta(5000), Buffer.alloc(5000));
  assert.throws(() => stream.push(bytes), (error: unknown) => error instanceof StreamError && error.fault === "OP_MISMATCH");
  assert.deepEqual(seen, [], "no output may be forwarded after an operation mismatch");
});

test("R7D.1-S-5: metadata-only operations reject output bytes", () => {
  const stream = new ProvisionalResultStream({ expectedOp: "verify", sink: () => {} });
  stream.push(frame(verifyMeta, Buffer.alloc(10)));
  assert.throws(() => stream.finish(), (error: unknown) => error instanceof StreamError && error.fault === "UNEXPECTED_OUTPUT");
});

test("R7D.1-S-6: a declared output length that disagrees with the frame is refused", () => {
  const stream = new ProvisionalResultStream({ expectedOp: "fill", sink: () => {} });
  stream.push(frame(fillMeta(100), Buffer.alloc(50)));
  assert.throws(() => stream.finish(), (error: unknown) => error instanceof StreamError && error.fault === "TRUNCATED");
});

// ---------------------------------------------------------------------------------------
// Malformed and hostile frames.
// ---------------------------------------------------------------------------------------

test("R7D.1-S-7: a truncated header is refused, not treated as an empty result", () => {
  const stream = new ProvisionalResultStream({ expectedOp: "fill", sink: () => {} });
  stream.push(Buffer.from([0, 0]));
  assert.throws(() => stream.finish(), (error: unknown) => error instanceof StreamError && error.fault === "TRUNCATED");
});

test("R7D.1-S-8: oversized metadata is refused on the declared length alone", () => {
  const stream = new ProvisionalResultStream({ expectedOp: "fill", sink: () => {} });
  const header = Buffer.alloc(4);
  header.writeUInt32BE(WORKER_LIMITS.metaBytes + 1, 0);
  assert.throws(() => stream.push(header), (error: unknown) => error instanceof StreamError && error.fault === "META_TOO_LARGE");
});

test("R7D.1-S-9: invalid JSON metadata is refused", () => {
  const stream = new ProvisionalResultStream({ expectedOp: "fill", sink: () => {} });
  const json = Buffer.from("{not json", "utf8");
  const header = Buffer.alloc(4);
  header.writeUInt32BE(json.byteLength, 0);
  assert.throws(() => stream.push(Buffer.concat([header, json])), (error: unknown) => error instanceof StreamError && error.fault === "META_INVALID_JSON");
});

test("R7D.1-S-10: an unknown operation in the metadata is refused", () => {
  const stream = new ProvisionalResultStream({ expectedOp: "fill", sink: () => {} });
  assert.throws(() => stream.push(frame({ ok: true, op: "exfiltrate" })), (error: unknown) => error instanceof StreamError && error.fault === "META_INVALID_SHAPE");
});

test("R7D.1-S-11: output beyond the configured ceiling is refused", () => {
  const stream = new ProvisionalResultStream({ expectedOp: "fill", maxOutputBytes: 1024, sink: () => {} });
  assert.throws(() => stream.push(frame(fillMeta(2048), Buffer.alloc(2048))), (error: unknown) => error instanceof StreamError && error.fault === "OUTPUT_TOO_LARGE");
});

test("R7D.1-S-12: the stream is single-use", () => {
  const stream = new ProvisionalResultStream({ expectedOp: "inspect", sink: () => {} });
  stream.push(frame({ ok: true, op: "inspect", pages: 1 }));
  stream.finish();
  assert.throws(() => stream.push(Buffer.alloc(1)), (error: unknown) => error instanceof StreamError && error.fault === "CLOSED");
  assert.throws(() => stream.finish(), (error: unknown) => error instanceof StreamError && error.fault === "CLOSED");
});

// ---------------------------------------------------------------------------------------
// Incremental hashing.
// ---------------------------------------------------------------------------------------

test("R7D.1-S-13: the running digest matches the digest of what has arrived so far", () => {
  const stream = new ProvisionalResultStream({ expectedOp: "fill", sink: () => {} });
  const first = Buffer.alloc(1024, 9);
  const header = Buffer.from(frame(fillMeta(2048), undefined));
  stream.push(Buffer.concat([header, first]));
  assert.equal(stream.digestSoFar(), sha256Hex(first));
  // The checkpoint must not disturb the running hash.
  stream.push(Buffer.alloc(1024, 9));
  assert.equal(stream.finish().outputSha256, sha256Hex(Buffer.alloc(2048, 9)));
});

// ---------------------------------------------------------------------------------------
// Caller-side bounded retention and publication gating.
// ---------------------------------------------------------------------------------------

test("R7D.1-S-14: the caller's provisional output is capped", () => {
  const output = new BoundedProvisionalOutput(1024);
  output.append(Buffer.alloc(512));
  assert.throws(() => output.append(Buffer.alloc(1024)), (error: unknown) => error instanceof StreamError && error.fault === "OUTPUT_TOO_LARGE");
  assert.equal(output.bytes, 512);
});

test("R7D.1-S-15: provisional output cannot be published without a terminal commit", () => {
  const output = new BoundedProvisionalOutput(1024);
  output.append(Buffer.alloc(64, 5));
  assert.throws(() => output.collect(false), (error: unknown) => error instanceof StreamError);
  const published = output.collect(true);
  assert.equal(published.byteLength, 64);
});

test("R7D.1-S-16: discarded output is unreachable even with a commit", () => {
  const output = new BoundedProvisionalOutput(1024);
  output.append(Buffer.alloc(64, 5));
  output.discard();
  assert.equal(output.bytes, 0);
  assert.throws(() => output.collect(true), (error: unknown) => error instanceof StreamError);
  assert.throws(() => output.append(Buffer.alloc(1)), (error: unknown) => error instanceof StreamError);
});

test("R7D.1-S-17: appended chunks are copied, so a reused buffer cannot corrupt them", () => {
  const output = new BoundedProvisionalOutput(1024);
  const reused = Buffer.alloc(4, 1);
  output.append(reused);
  reused.fill(9);
  const collected = output.collect(true);
  assert.deepEqual([...collected], [1, 1, 1, 1]);
});
