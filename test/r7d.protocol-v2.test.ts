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
