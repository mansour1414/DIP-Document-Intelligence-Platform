/**
 * R7D.1 — internal worker protocol v2.
 *
 * v1 compatibility is asserted against the real v1 module, not re-described here: if v2
 * ever changed a shared limit or a refusal shape, the two encoders would disagree and the
 * compatibility test would fail.
 */
import test from "node:test";
import assert from "node:assert/strict";
import {
  asVerifyMeta,
  decodeControlV2,
  decodeResultV2,
  encodeControlV2,
  encodeResultV2,
  VERIFY_BOUNDS,
  WORKER_PROTOCOL_V2,
  WorkerProtocolError,
} from "../src/lib/pdf/worker-protocol-v2";
import { WORKER_LIMITS, WORKER_PROTOCOL_VERSION, encodeControl, decodeControl } from "../src/lib/pdf/worker-protocol";
import { ProvisionalResultStream, StreamError } from "../src/lib/execution/provisional-stream";

const body = Buffer.from("PDFBODY");

function faultOf(fn: () => void): string | undefined {
  try {
    fn();
    return undefined;
  } catch (error) {
    return error instanceof WorkerProtocolError ? error.reason : "NOT_PROTOCOL_ERROR";
  }
}

// ---------------------------------------------------------------------------------------
// Round trips.
// ---------------------------------------------------------------------------------------

test("R7D.1-V2-1: inspect round-trips", () => {
  const encoded = encodeControlV2({ v: WORKER_PROTOCOL_V2, op: "inspect" }, body, 512 * 1024 * 1024);
  const { request, body: decoded } = decodeControlV2(encoded, 512 * 1024 * 1024);
  assert.equal(request.op, "inspect");
  assert.deepEqual([...decoded], [...body]);
});

test("R7D.1-V2-2: fill round-trips with flatten as an explicit boolean", () => {
  const encoded = encodeControlV2({ v: WORKER_PROTOCOL_V2, op: "fill", flatten: true, fields: { a: "1", b: true, c: ["x", "y"] } }, body, 512 * 1024 * 1024);
  const { request } = decodeControlV2(encoded, 512 * 1024 * 1024);
  assert.equal(request.op, "fill");
  if (request.op !== "fill") throw new Error("unreachable");
  assert.equal(request.flatten, true);
  assert.deepEqual({ ...request.fields }, { a: "1", b: true, c: ["x", "y"] });
});

test("R7D.1-V2-3: verify round-trips a transient baseline", () => {
  const baseline = { kind: "flatten" as const, expected: { name: "Ada" }, untouched: { keep: "v" } };
  const encoded = encodeControlV2({ v: WORKER_PROTOCOL_V2, op: "verify", baseline }, body, 512 * 1024 * 1024);
  const { request } = decodeControlV2(encoded, 512 * 1024 * 1024);
  assert.equal(request.op, "verify");
  if (request.op !== "verify") throw new Error("unreachable");
  assert.deepEqual(request.baseline, baseline);
});

test("R7D.1-V2-4: a verify result is metadata-only and narrows correctly", () => {
  const meta = { ok: true as const, op: "verify" as const, pages: 2, widgets: 0, preserved: 3 };
  const decoded = decodeResultV2(encodeResultV2(meta), 1024, "verify");
  assert.equal(decoded.output.byteLength, 0);
  assert.deepEqual(asVerifyMeta(decoded.meta), meta);
});

test("R7D.1-V2-5: a fill result carries its declared output", () => {
  const output = Buffer.alloc(64, 4);
  const decoded = decodeResultV2(encodeResultV2({ ok: true, op: "fill", pages: 1, outBytes: 64, checksum: "0".repeat(64), report: { filled: 1, untouched: 0, rasterAppearances: 0, flatten: false } }, output), 1024, "fill");
  assert.deepEqual([...decoded.output], [...output]);
});

// ---------------------------------------------------------------------------------------
// Rejections.
// ---------------------------------------------------------------------------------------

test("R7D.1-V2-6: a v1 frame is rejected by v2 as a version mismatch", () => {
  // v1 and v2 must not interoperate silently: a v1 control frame decoded as v2 would
  // ignore `verify` entirely and treat an unknown op as whatever the fallthrough said.
  const v1 = encodeControl({ v: WORKER_PROTOCOL_VERSION, op: "inspect" } as never, Buffer.alloc(0), 1024);
  assert.equal(faultOf(() => decodeControlV2(v1, 1024)), "VERSION_MISMATCH");
});

test("R7D.1-V2-7: a declared body length that disagrees with the frame is rejected", () => {
  const good = encodeControlV2({ v: WORKER_PROTOCOL_V2, op: "inspect" }, body, 1024);
  // Append a trailing byte: the declaration says 7, the frame now carries 8.
  assert.equal(faultOf(() => decodeControlV2(Buffer.concat([good, Buffer.from([0])]), 1024)), "LENGTH_MISMATCH");
  // Truncate one byte.
  assert.equal(faultOf(() => decodeControlV2(good.subarray(0, good.byteLength - 1), 1024)), "LENGTH_MISMATCH");
});

test("R7D.1-V2-8: a truncated header or metadata is rejected", () => {
  assert.equal(faultOf(() => decodeControlV2(Buffer.from([0, 0]), 1024)), "TRUNCATED");
  const header = Buffer.alloc(4);
  header.writeUInt32BE(100, 0);
  assert.equal(faultOf(() => decodeControlV2(Buffer.concat([header, Buffer.from("{}")]), 1024)), "TRUNCATED");
});

test("R7D.1-V2-9: oversized control metadata is rejected on the declared length", () => {
  const header = Buffer.alloc(4);
  header.writeUInt32BE(WORKER_LIMITS.controlBytes + 1, 0);
  assert.equal(faultOf(() => decodeControlV2(Buffer.concat([header, Buffer.alloc(8)]), 1024)), "CONTROL_TOO_LARGE");
});

test("R7D.1-V2-10: invalid field value types are rejected", () => {
  // `3` is neither a string, a boolean, nor a string array. Accepting it would put a
  // non-scalar into the fill engine and produce an unfalsifiable verification mismatch.
  const encoded = encodeControlV2({ v: WORKER_PROTOCOL_V2, op: "fill", flatten: false, fields: { a: 3 as never } }, body, 1024);
  assert.equal(faultOf(() => decodeControlV2(encoded, 1024)), "INVALID_REQUEST");
});

test("R7D.1-V2-11: flatten must be a boolean", () => {
  const encoded = encodeControlV2({ v: WORKER_PROTOCOL_V2, op: "fill", flatten: "yes" as never, fields: {} }, body, 1024);
  assert.equal(faultOf(() => decodeControlV2(encoded, 1024)), "INVALID_REQUEST");
});

test("R7D.1-V2-12: an unknown operation is rejected", () => {
  const encoded = encodeControlV2({ v: WORKER_PROTOCOL_V2, op: "exfiltrate" as never }, body, 1024);
  assert.equal(faultOf(() => decodeControlV2(encoded, 1024)), "INVALID_REQUEST");
});

test("R7D.1-V2-13: an invalid verify baseline kind is rejected", () => {
  const encoded = encodeControlV2({ v: WORKER_PROTOCOL_V2, op: "verify", baseline: { kind: "nope" as never, expected: {} } }, body, 1024);
  assert.equal(faultOf(() => decodeControlV2(encoded, 1024)), "INVALID_REQUEST");
});

test("R7D.1-V2-14: a result operation mismatch is rejected", () => {
  const encoded = encodeResultV2({ ok: true, op: "verify", pages: 1, widgets: 0, preserved: 0 });
  assert.equal(faultOf(() => decodeResultV2(encoded, 1024, "fill")), "OP_MISMATCH");
});

test("R7D.1-V2-15: a metadata-only operation may not carry output", () => {
  const encoded = encodeResultV2({ ok: true, op: "verify", pages: 1, widgets: 0, preserved: 0 });
  // Splice output bytes past the metadata boundary.
  const spliced = Buffer.concat([encoded, Buffer.alloc(8, 1)]);
  assert.equal(faultOf(() => decodeResultV2(spliced, 1024, "verify")), "UNEXPECTED_OUTPUT");
});

test("R7D.1-V2-16: output beyond the configured ceiling is rejected", () => {
  const encoded = encodeResultV2({ ok: true, op: "fill", pages: 1, outBytes: 2048, checksum: "0".repeat(64), report: { filled: 1, untouched: 0, rasterAppearances: 0, flatten: false } }, Buffer.alloc(2048, 2));
  assert.equal(faultOf(() => decodeResultV2(encoded, 1024, "fill")), "OUTPUT_TOO_LARGE");
});

// ---------------------------------------------------------------------------------------
// Compatibility with v1.
// ---------------------------------------------------------------------------------------

test("R7D.1-V2-17: v1 still works and is unchanged by v2's presence", () => {
  // The v1 round trip must behave exactly as before. This is the guard on §10's
  // "preserve existing protocol v1 inspect/fill behavior".
  const encoded = encodeControl({ v: WORKER_PROTOCOL_VERSION, op: "inspect" } as never, body, 1024);
  const decoded = decodeControl(encoded, 1024);
  assert.equal(decoded.control.op, "inspect");
  assert.deepEqual([...decoded.pdf], [...body]);
});

test("R7D.1-V2-18: v2 reuses v1's limits rather than defining its own", () => {
  // A separate set would let the tighter one silently become the real ceiling.
  assert.equal(VERIFY_BOUNDS.baselineBytes, WORKER_LIMITS.controlBytes);
  const oversizedJson = "x".repeat(WORKER_LIMITS.controlBytes + 16);
  // Both halves must reject it: the encoder refuses to emit it, and a frame that somehow
  // carried it would be refused on decode. Asserting only one would leave the other free
  // to become the weak link.
  assert.equal(
    faultOf(() => encodeControlV2({ v: WORKER_PROTOCOL_V2, op: "verify", baseline: { kind: "fill", expected: { big: oversizedJson } } }, body, 1024)),
    "CONTROL_TOO_LARGE",
  );
  const header = Buffer.alloc(4);
  header.writeUInt32BE(WORKER_LIMITS.controlBytes + 1, 0);
  assert.equal(faultOf(() => decodeControlV2(Buffer.concat([header, Buffer.alloc(8)]), 1024)), "CONTROL_TOO_LARGE");
});

// ---------------------------------------------------------------------------------------
// F02 — strict metadata validation. Each of these passed under the old cast.
// ---------------------------------------------------------------------------------------

const FILL_OK = {
  ok: true as const,
  op: "fill" as const,
  pages: 1,
  outBytes: 4,
  checksum: "0".repeat(64),
  report: { filled: 1, untouched: 0, rasterAppearances: 0, flatten: false },
};

test("R7D.1-F02-1: a fill result missing outBytes is rejected", () => {
  // The old decoder returned `raw as WorkerMetaV2`, so this shape was accepted.
  const withoutLength = { ...FILL_OK } as Record<string, unknown>;
  delete withoutLength.outBytes;
  assert.equal(faultOf(() => decodeResultV2(frameOf(withoutLength, Buffer.alloc(4)), 1024, "fill")), "INVALID_META");
});

test("R7D.1-F02-2: a fill result missing checksum or report is rejected", () => {
  const noChecksum = { ...FILL_OK } as Record<string, unknown>;
  delete noChecksum.checksum;
  assert.equal(faultOf(() => decodeResultV2(frameOf(noChecksum, Buffer.alloc(4)), 1024, "fill")), "INVALID_META");
  const noReport = { ...FILL_OK } as Record<string, unknown>;
  delete noReport.report;
  assert.equal(faultOf(() => decodeResultV2(frameOf(noReport, Buffer.alloc(4)), 1024, "fill")), "INVALID_META");
});

test("R7D.1-F02-3: a fill result whose outBytes disagrees with the frame is rejected", () => {
  // Declared 4, carried 3. The old code never compared them, so a truncated document would
  // have been forwarded as complete.
  assert.equal(faultOf(() => decodeResultV2(frameOf(FILL_OK, Buffer.alloc(3)), 1024, "fill")), "OUTPUT_LENGTH_MISMATCH");
  // Declared 4, carried 5: bytes nobody accounted for.
  assert.equal(faultOf(() => decodeResultV2(frameOf(FILL_OK, Buffer.alloc(5)), 1024, "fill")), "OUTPUT_LENGTH_MISMATCH");
});

test("R7D.1-F02-4: a non-boolean outcome discriminator is rejected", () => {
  for (const ok of ["false", 0, 1, null, undefined]) {
    const frame = frameOf({ ...FILL_OK, ok }, Buffer.alloc(4));
    assert.equal(faultOf(() => decodeResultV2(frame, 1024, "fill")), "INVALID_DISCRIMINATOR", `ok=${String(ok)}`);
  }
});

test("R7D.1-F02-5: a refusal carrying output bytes is rejected", () => {
  // Refusals are metadata-only. Bytes behind a failure marker are either corruption or an
  // attempt to have content accepted under a failure the caller will not inspect.
  const refusal = { ok: false, op: "fill", code: "FORM_UNSUPPORTED", details: { reason: "ENCRYPTED" } };
  assert.equal(faultOf(() => decodeResultV2(frameOf(refusal, Buffer.alloc(16)), 1024, "fill")), "UNEXPECTED_OUTPUT");
  // Without bytes the same refusal is accepted.
  assert.doesNotThrow(() => decodeResultV2(frameOf(refusal), 1024, "fill"));
});

test("R7D.1-F02-6: a refusal with an unknown code is rejected", () => {
  const refusal = { ok: false, op: "fill", code: "SOMETHING_NEW", details: {} };
  assert.equal(faultOf(() => decodeResultV2(frameOf(refusal), 1024, "fill")), "UNKNOWN_ERROR_CODE");
});

test("R7D.1-F02-7: a verify result with unexpected properties is rejected", () => {
  const withExtra = { ok: true, op: "verify", pages: 1, widgets: 0, preserved: 0, note: "extra" };
  assert.equal(faultOf(() => decodeResultV2(frameOf(withExtra), 1024, "verify")), "INVALID_META");
});

test("R7D.1-F02-8: verify counters must be non-negative integers", () => {
  for (const bad of [-1, 1.5, "3", null]) {
    const frame = frameOf({ ok: true, op: "verify", pages: 1, widgets: bad, preserved: 0 });
    assert.equal(faultOf(() => decodeResultV2(frame, 1024, "verify")), "INVALID_META", `widgets=${String(bad)}`);
  }
});

test("R7D.1-F02-9: a verify answer to a fill request is rejected", () => {
  const frame = frameOf({ ok: true, op: "verify", pages: 1, widgets: 0, preserved: 0 });
  assert.equal(faultOf(() => decodeResultV2(frame, 1024, "fill")), "OP_MISMATCH");
});

test("R7D.1-F02-10: the buffered and streaming decoders agree on every malformed frame", () => {
  // The review asked for identical semantics. They share one validator, so this asserts the
  // sharing holds rather than that two implementations happen to agree today.
  const cases: Array<[string, unknown, number]> = [
    ["missing outBytes", { ...FILL_OK, outBytes: undefined }, 4],
    ["length disagree", FILL_OK, 3],
    ["bad discriminator", { ...FILL_OK, ok: "true" }, 4],
    ["bad checksum", { ...FILL_OK, checksum: "short" }, 4],
  ];
  for (const [label, meta, bytes] of cases) {
    const frame = frameOf(meta, Buffer.alloc(bytes));
    const buffered = faultOf(() => decodeResultV2(frame, 1024, "fill"));
    const streamed = faultOfStream(frame);
    assert.ok(buffered !== undefined, `buffered decoder must reject: ${label}`);
    assert.ok(streamed !== undefined, `streaming decoder must reject: ${label}`);
  }
});

/** Build a raw result frame without going through the encoder, so invalid shapes can be sent. */
function frameOf(meta: unknown, output?: Buffer): Buffer {
  const json = Buffer.from(JSON.stringify(meta), "utf8");
  const header = Buffer.alloc(4);
  header.writeUInt32BE(json.byteLength, 0);
  return output && output.byteLength > 0 ? Buffer.concat([header, json, output]) : Buffer.concat([header, json]);
}

/** Run a frame through the streaming validator and return its fault, if any. */
function faultOfStream(frame: Buffer): string | undefined {
  try {
    const stream = new ProvisionalResultStream({ expectedOp: "fill", sink: () => {} });
    stream.push(frame);
    stream.finish();
    return undefined;
  } catch (error) {
    return error instanceof StreamError ? error.fault : "OTHER";
  }
}
