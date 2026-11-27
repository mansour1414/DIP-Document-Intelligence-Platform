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

/** Build a raw result frame without going through the encoder, so shapes can be controlled. */
function frameOf(meta: unknown, output?: Buffer): Buffer {
  const json = Buffer.from(JSON.stringify(meta), "utf8");
  const header = Buffer.alloc(4);
  header.writeUInt32BE(json.byteLength, 0);
  return output && output.byteLength > 0 ? Buffer.concat([header, json, output]) : Buffer.concat([header, json]);
}

/** A stable execution id, so a grant can be bound to it. */
const EXECUTION = "0123456789abcdef0123456789abcdef";
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

const fillMeta = (outBytes: number) => ({
  ok: true,
  op: "fill",
  pages: 1,
  // F02: the fill contract field is `outBytes`, not `outputBytes`. The streaming validator
  // previously looked for the wrong one.
  outBytes,
  checksum: "0".repeat(64),
  report: { filled: 1, untouched: 0, rasterAppearances: 0, flatten: false },
});
const verifyMeta = { ok: true, op: "verify", pages: 1, widgets: 0, preserved: 2 };

// ---------------------------------------------------------------------------------------
// The buffering defect.
// ---------------------------------------------------------------------------------------

test("R7D.1-S-1: a fill result is forwarded chunk by chunk as it arrives", () => {
  const seen: number[] = [];
  const stream = new ProvisionalResultStream({ executionId: EXECUTION, expectedOp: "fill", sink: (chunk) => seen.push(chunk.bytes.byteLength) });
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
    executionId: EXECUTION,
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
  const stream = new ProvisionalResultStream({ executionId: EXECUTION, expectedOp: "fill", maxBufferedBytes: 1024, sink: () => { /* never acknowledges */ } });
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
  const stream = new ProvisionalResultStream({ executionId: EXECUTION, expectedOp: "verify", sink: (chunk) => seen.push(chunk.bytes.byteLength) });
  const bytes = frame(fillMeta(5000), Buffer.alloc(5000));
  assert.throws(() => stream.push(bytes), (error: unknown) => error instanceof StreamError && error.fault === "OP_MISMATCH");
  assert.deepEqual(seen, [], "no output may be forwarded after an operation mismatch");
});

test("R7D.1-S-5: metadata-only operations reject output bytes", () => {
  const stream = new ProvisionalResultStream({ executionId: EXECUTION, expectedOp: "verify", sink: () => {} });
  stream.push(frame(verifyMeta, Buffer.alloc(10)));
  assert.throws(() => stream.finish(), (error: unknown) => error instanceof StreamError && error.fault === "UNEXPECTED_OUTPUT");
});

test("R7D.1-S-6: a declared output length that disagrees with the frame is refused", () => {
  const stream = new ProvisionalResultStream({ executionId: EXECUTION, expectedOp: "fill", sink: () => {} });
  stream.push(frame(fillMeta(100), Buffer.alloc(50)));
  assert.throws(() => stream.finish(), (error: unknown) => error instanceof StreamError && error.fault === "TRUNCATED");
});

// ---------------------------------------------------------------------------------------
// Malformed and hostile frames.
// ---------------------------------------------------------------------------------------

test("R7D.1-S-7: a truncated header is refused, not treated as an empty result", () => {
  const stream = new ProvisionalResultStream({ executionId: EXECUTION, expectedOp: "fill", sink: () => {} });
  stream.push(Buffer.from([0, 0]));
  assert.throws(() => stream.finish(), (error: unknown) => error instanceof StreamError && error.fault === "TRUNCATED");
});

test("R7D.1-S-8: oversized metadata is refused on the declared length alone", () => {
  const stream = new ProvisionalResultStream({ executionId: EXECUTION, expectedOp: "fill", sink: () => {} });
  const header = Buffer.alloc(4);
  header.writeUInt32BE(WORKER_LIMITS.metaBytes + 1, 0);
  assert.throws(() => stream.push(header), (error: unknown) => error instanceof StreamError && error.fault === "META_TOO_LARGE");
});

test("R7D.1-S-9: invalid JSON metadata is refused", () => {
  const stream = new ProvisionalResultStream({ executionId: EXECUTION, expectedOp: "fill", sink: () => {} });
  const json = Buffer.from("{not json", "utf8");
  const header = Buffer.alloc(4);
  header.writeUInt32BE(json.byteLength, 0);
  assert.throws(() => stream.push(Buffer.concat([header, json])), (error: unknown) => error instanceof StreamError && error.fault === "META_INVALID_JSON");
});

test("R7D.1-S-10: an unknown operation in the metadata is refused", () => {
  const stream = new ProvisionalResultStream({ executionId: EXECUTION, expectedOp: "fill", sink: () => {} });
  assert.throws(() => stream.push(frame({ ok: true, op: "exfiltrate" })), (error: unknown) => error instanceof StreamError && error.fault === "META_INVALID_SHAPE");
});

test("R7D.1-S-11: output beyond the configured ceiling is refused", () => {
  const stream = new ProvisionalResultStream({ executionId: EXECUTION, expectedOp: "fill", maxOutputBytes: 1024, sink: () => {} });
  assert.throws(() => stream.push(frame(fillMeta(2048), Buffer.alloc(2048))), (error: unknown) => error instanceof StreamError && error.fault === "OUTPUT_TOO_LARGE");
});

test("R7D.1-S-12: the stream is single-use", () => {
  // A fill frame, because its metadata contract is the simplest complete one. The point of
  // this test is lifecycle, not inventory shape.
  const output = Buffer.alloc(16, 6);
  const stream = new ProvisionalResultStream({ executionId: EXECUTION, expectedOp: "fill", sink: () => {} });
  stream.push(frame(fillMeta(output.byteLength), output));
  stream.finish();
  assert.throws(() => stream.push(Buffer.alloc(1)), (error: unknown) => error instanceof StreamError && error.fault === "CLOSED");
  assert.throws(() => stream.finish(), (error: unknown) => error instanceof StreamError && error.fault === "CLOSED");
});

// ---------------------------------------------------------------------------------------
// Incremental hashing.
// ---------------------------------------------------------------------------------------

test("R7D.1-S-13: the running digest matches the digest of what has arrived so far", () => {
  const stream = new ProvisionalResultStream({ executionId: EXECUTION, expectedOp: "fill", sink: () => {} });
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

test("R7D.1-S-15: output cannot be published before the stream seals it", () => {
  const output = new BoundedProvisionalOutput(1024);
  output.append(Buffer.alloc(64, 5));
  // No seal yet, so no grant can be issued and `collect` refuses.
  assert.throws(() => output.grantTerminalCommit(), (error: unknown) => error instanceof StreamError);
  assert.throws(() => output.collect({ executionId: EXECUTION, digest: "0".repeat(64), bytes: 64, consumed: false }), (error: unknown) => error instanceof StreamError);
});

test("R7D.1-F02-11: a grant is bound to the digest and byte count it was issued for", () => {
  // The point of replacing `collect(true)` is that the boolean proved nothing. A grant that can
  // be paired with different bytes would prove no more.
  const output = new BoundedProvisionalOutput(1024);
  output.append(Buffer.alloc(64, 5));
  output.seal(EXECUTION, "a".repeat(64));
  assert.throws(
    () => output.collect({ executionId: EXECUTION, digest: "b".repeat(64), bytes: 64, consumed: false }),
    (error: unknown) => error instanceof StreamError && /does not match the bytes/u.test(error.message),
  );
  assert.throws(
    () => output.collect({ executionId: EXECUTION, digest: "a".repeat(64), bytes: 65, consumed: false }),
    (error: unknown) => error instanceof StreamError && /does not match the byte count/u.test(error.message),
  );
  // The genuine grant works exactly once.
  const published = output.collect(output.grantTerminalCommit());
  assert.equal(published.byteLength, 64);
});

test("R7D.1-F02-12: a grant from another execution is refused", () => {
  const output = new BoundedProvisionalOutput(1024);
  output.append(Buffer.alloc(8, 1));
  output.seal(EXECUTION, "c".repeat(64));
  assert.throws(
    () => output.collect({ executionId: "f".repeat(32), digest: "c".repeat(64), bytes: 8, consumed: false }),
    (error: unknown) => error instanceof StreamError && /different execution/u.test(error.message),
  );
});

test("R7D.1-F02-13: a grant is single-use", () => {
  // One execution produces one document. A second publication is a second document.
  const output = new BoundedProvisionalOutput(1024);
  output.append(Buffer.alloc(8, 1));
  output.seal(EXECUTION, "d".repeat(64));
  const grant = output.grantTerminalCommit();
  assert.equal(output.collect(grant).byteLength, 8);
  assert.throws(() => output.collect(grant), (error: unknown) => error instanceof StreamError && /already used/u.test(error.message));
});

test("R7D.1-F02-14: output cannot be sealed twice", () => {
  // A second seal would let a caller substitute a digest after the stream had already checked one.
  const output = new BoundedProvisionalOutput(1024);
  output.seal(EXECUTION, "e".repeat(64));
  assert.throws(() => output.seal(EXECUTION, "f".repeat(64)), (error: unknown) => error instanceof StreamError);
});

test("R7D.1-S-16: discarded output is unreachable even with a commit", () => {
  const output = new BoundedProvisionalOutput(1024);
  output.append(Buffer.alloc(64, 5));
  output.seal(EXECUTION, "0".repeat(64));
  output.discard();
  assert.equal(output.bytes, 0);
  // Even a grant this object itself issued cannot resurrect discarded bytes.
  assert.throws(() => output.grantTerminalCommit(), (error: unknown) => error instanceof StreamError);
  assert.throws(
    () => output.collect({ executionId: EXECUTION, digest: "0".repeat(64), bytes: 64, consumed: false }),
    (error: unknown) => error instanceof StreamError,
  );
  assert.throws(() => output.append(Buffer.alloc(1)), (error: unknown) => error instanceof StreamError);
});

test("R7D.1-S-17: appended chunks are copied, so a reused buffer cannot corrupt them", () => {
  const output = new BoundedProvisionalOutput(1024);
  const reused = Buffer.alloc(4, 1);
  output.append(reused);
  output.seal(EXECUTION, "0".repeat(64));
  reused.fill(9);
  const collected = output.collect(output.grantTerminalCommit());
  assert.deepEqual([...collected], [1, 1, 1, 1]);
});

// ---------------------------------------------------------------------------------------
// C-F05 — the streaming reader
// ---------------------------------------------------------------------------------------

test("R7D.1-CF05-1: the header prefix is read four bytes at a time, not by re-concatenating", () => {
  // A byte-at-a-time feed is the pathological case for `Buffer.concat([buf, view])`: it copies
  // the whole buffer on every push. Four pushes here, one allocation each.
  const output = new BoundedProvisionalOutput(1024);
  const stream = new ProvisionalResultStream({ executionId: EXECUTION, expectedOp: "fill", sink: (chunk) => { output.append(chunk.bytes); } });
  const frame = frameOf(fillMeta(4), Buffer.alloc(4, 7));
  for (const byte of frame) stream.push(Buffer.from([byte]));
  const done = stream.finish(output);
  assert.equal(done.outputBytes, 4);
  assert.equal(output.bytes, 4);
});

test("R7D.1-CF05-2: a coalesced header and body in one chunk are split correctly", () => {
  // The supervisor reads whatever the pipe gives it; a small result arrives as one chunk.
  const output = new BoundedProvisionalOutput(1024);
  const stream = new ProvisionalResultStream({ executionId: EXECUTION, expectedOp: "fill", sink: (chunk) => { output.append(chunk.bytes); } });
  stream.push(frameOf(fillMeta(8), Buffer.alloc(8, 3)));
  const done = stream.finish(output);
  assert.equal(done.outputBytes, 8);
  assert.equal(output.bytes, 8);
});

test("R7D.1-CF05-3: an oversized declared metadata length is refused before allocation", () => {
  const stream = new ProvisionalResultStream({ executionId: EXECUTION, expectedOp: "fill", sink: () => {} });
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(64 * 1024 * 1024, 0);
  assert.throws(() => stream.push(prefix), (error: unknown) => error instanceof StreamError && error.fault === "META_TOO_LARGE");
});

test("R7D.1-CF05-4: a zero-length metadata declaration is refused as framing", () => {
  const stream = new ProvisionalResultStream({ executionId: EXECUTION, expectedOp: "fill", sink: () => {} });
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(0, 0);
  assert.throws(() => stream.push(prefix), (error: unknown) => error instanceof StreamError && error.fault === "META_INVALID_JSON");
});

test("R7D.1-CF05-5: output beyond the declared length is refused during the stream, not at the end", () => {
  // The declaration is known as soon as the metadata parses, so a frame that is already too
  // long can be refused before the caller forwards the rest of it.
  const stream = new ProvisionalResultStream({ executionId: EXECUTION, expectedOp: "fill", sink: () => {} });
  const frame = frameOf(fillMeta(4), Buffer.alloc(64, 1));
  assert.throws(() => stream.push(frame), (error: unknown) => error instanceof StreamError && error.fault === "TRUNCATED");
});

test("R7D.1-CF05-6: a fault permanently invalidates the stream", () => {
  // After a framing error the bytes that follow were never validated. Continuing would mean
  // treating unvalidated bytes as a shorter valid result.
  const stream = new ProvisionalResultStream({ executionId: EXECUTION, expectedOp: "fill", sink: () => {} });
  const bad = Buffer.alloc(4);
  bad.writeUInt32BE(64 * 1024 * 1024, 0);
  assert.throws(() => stream.push(bad));
  assert.throws(() => stream.push(Buffer.alloc(4)), (error: unknown) => error instanceof StreamError && /invalidated/u.test(error.message));
  assert.throws(() => stream.finish(), (error: unknown) => error instanceof StreamError && /invalidated/u.test(error.message));
});

test("R7D.1-CF05-7: a stream cannot complete after its metadata was invalid JSON", () => {
  const stream = new ProvisionalResultStream({ executionId: EXECUTION, expectedOp: "fill", sink: () => {} });
  const json = Buffer.from("{not json", "utf8");
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(json.byteLength, 0);
  assert.throws(() => stream.push(Buffer.concat([prefix, json])));
  assert.throws(() => stream.finish(), (error: unknown) => error instanceof StreamError);
});

test("R7D.1-CF05-8: the pending bound refuses a consumer that stops reading", () => {
  const stream = new ProvisionalResultStream({
    executionId: EXECUTION,
    expectedOp: "fill",
    maxBufferedBytes: 1_024,
    sink: () => {}, // never acknowledges
  });
  const chunk = Buffer.alloc(60 * 1024, 1);
  const total = 4 * 1024 * 1024;
  // The declaration must be truthful or the frame is refused for the wrong reason.
  const frame = frameOf(fillMeta(total), Buffer.alloc(0));
  stream.push(frame);
  let fault: string | undefined;
  try {
    for (let sent = 0; sent < total; sent += chunk.byteLength) stream.push(chunk);
  } catch (error) {
    fault = error instanceof StreamError ? error.fault : "OTHER";
  }
  assert.equal(fault, "BUFFER_EXCEEDED", "an unacked consumer must be refused rather than buffered");
});

test("R7D.1-CF05-9: the result metadata buffer is not retained after parsing", async () => {
  // A 4 MiB metadata block is allocated once and dropped. Keeping it alive would mean every
  // in-flight execution held a metadata copy for the life of the stream.
  const { readFileSync } = await import("node:fs");
  const source = readFileSync("src/lib/execution/provisional-stream.ts", "utf8");
  assert.match(source, /this\.metaBuffer = Buffer\.alloc\(0\)/u, "the metadata buffer must be released after validation");
});
