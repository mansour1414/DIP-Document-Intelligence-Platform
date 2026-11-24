/**
 * R6.1-D — the framed IPC contract, corrected.
 *
 * Each test here corresponds to a defect that was confirmed in the R6 commit by
 * inspecting the code rather than by a failing test, which is why several of them
 * previously had no coverage at all:
 *
 *   D1  a failure `code` was any non-empty string
 *   D2  failure `details` were forwarded without sanitisation
 *   D3  `decodeResult` returned on failure metadata before checking for trailing bytes
 *   D4  operation mismatch was checked for success frames only
 *   D5  JSON decoding accepted invalid UTF-8 by substitution
 *   D9  the wrong limit constants were used for names, options and value lengths
 *
 * D6 (stdout drained), D7 (partial writes) and D8 (bounded accounting, shutdown
 * reaping) are exercised by the subprocess tests in `pdf.form-worker.test.ts`, because
 * they only exist when a process actually runs.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  WORKER_LIMITS,
  WorkerProtocolError,
  decodeResult,
  encodeResult,
  parseMeta,
  setExpectedOp,
  type WorkerMeta,
} from "../src/lib/pdf/worker-protocol";

const inventory = { fields: [], unsupported: [], pages: 1, hasXfa: false, needAppearances: false, duplicates: [] };
const okInspect: WorkerMeta = { ok: true, op: "inspect", pages: 1, inventory };

function framing(payload: Buffer) {
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.byteLength, 0);
  return Buffer.concat([header, payload]);
}

function reason(fn: () => unknown): string {
  try { fn(); }
  catch (error) { return error instanceof WorkerProtocolError ? error.reason : `NOT_PROTOCOL:${String(error)}`; }
  return "DID_NOT_THROW";
}

test("D1: a failure code must be one of the existing error codes", () => {
  // The set is `FORM_FILL_ERROR_CODES`, which already existed as a runtime-checkable
  // allowlist. A child is untrusted, so its `code` is not merely a string.
  for (const code of ["anything", "FORM_NOT_FOUND ", "form_not_found", "__proto__", "constructor", ""]) {
    assert.equal(
      reason(() => parseMeta({ ok: false, op: "inspect", code })),
      "UNKNOWN_ERROR_CODE",
      `code ${JSON.stringify(code)} must be refused`,
    );
  }
  // Every allowlisted code is still accepted, and its identity is preserved so the
  // parent can map it to the established message.
  for (const code of ["FORM_NOT_FOUND", "FORM_UNSUPPORTED", "FORM_RESTRICTED", "FORM_VALUE_INVALID", "FORM_FILL_FAILED", "FORM_OUTPUT_UNVERIFIED"]) {
    const meta = parseMeta({ ok: false, op: "inspect", code });
    assert.equal(meta.ok, false);
    if (!meta.ok) assert.equal(meta.code, code, "the valid code must survive unchanged");
  }
});

test("D2: failure details are rebuilt from an allowlist, never forwarded", () => {
  const parsed = parseMeta({
    ok: false,
    op: "fill",
    code: "FORM_VALUE_INVALID",
    details: {
      issues: ["UNKNOWN_FIELD", "TYPE_MISMATCH", "NOT_A_REAL_ISSUE"],
      shape: "NO_PDF_HEADER",
      reason: "UNEXPECTED",
      limit: 400,
      pageMarkers: 9000,
      // Everything below is content the parent must never see.
      fieldName: "customer_iban",
      value: "DE89 3704 0044 0532 0130 00",
      documentText: "%PDF-1.7 secret",
      nested: { deep: ["x"] },
    },
  });
  assert.equal(parsed.ok, false);
  if (parsed.ok) return;
  const details = parsed.details as Record<string, unknown>;
  assert.deepEqual(details.issues, ["UNKNOWN_FIELD", "TYPE_MISMATCH"], "only existing issue codes survive");
  assert.equal(details.shape, "NO_PDF_HEADER");
  assert.equal(details.reason, "UNEXPECTED");
  assert.equal(details.limit, 400);
  assert.equal(details.pageMarkers, 9000);
  for (const forbidden of ["fieldName", "value", "documentText", "nested"]) {
    assert.equal(forbidden in details, false, `${forbidden} must not be forwarded`);
  }
});

test("D2: a non-code-shaped or non-numeric detail is dropped rather than passed", () => {
  const parsed = parseMeta({ ok: false, op: "inspect", code: "FORM_UNSUPPORTED", details: { shape: "has spaces and lower", limit: -1, pageMarkers: 1.5 } });
  if (parsed.ok) return assert.fail("expected a failure frame");
  assert.equal(parsed.details, undefined, "every value was invalid, so no details are attached");
});

test("D3: a failure frame with trailing bytes is refused", () => {
  // Previously `decodeResult` returned the failure metadata immediately, so anything
  // appended after it was never examined. The parent did not read the bytes, which is
  // not the same as the bytes not being there.
  const meta = Buffer.from(JSON.stringify({ ok: false, op: "inspect", code: "FORM_UNSUPPORTED" }), "utf8");
  const clean = framing(meta);
  const decoded = decodeResult(clean, 1024);
  assert.equal(decoded.meta.ok, false, "a clean failure frame still decodes");

  const withTrailing = Buffer.concat([clean, Buffer.from("extra", "utf8")]);
  assert.equal(reason(() => decodeResult(withTrailing, 1024)), "TRAILING_DATA");
});

test("D4: operation mismatch applies to failure frames too", () => {
  // The parent asked for a fill; the child answered "inspect failed". That is not a
  // fill refusal, it is a frame from a different exchange.
  setExpectedOp("fill");
  try {
    assert.equal(reason(() => parseMeta({ ok: false, op: "inspect", code: "FORM_UNSUPPORTED" })), "OP_MISMATCH");
    // The matching operation is accepted.
    const matching = parseMeta({ ok: false, op: "fill", code: "FORM_FILL_FAILED" });
    assert.equal(matching.ok, false);
  } finally { setExpectedOp(null); }
});

test("D4: success frames are still checked against the requested operation", () => {
  setExpectedOp("fill");
  try {
    assert.equal(reason(() => parseMeta(okInspect)), "OP_MISMATCH");
  } finally { setExpectedOp(null); }
});

test("D5: invalid UTF-8 in the metadata is a protocol error, not a substitution", () => {
  // A lone continuation byte is never valid UTF-8. A default TextDecoder would replace
  // it with U+FFFD and the result could then parse as JSON — silently repairing corrupt
  // transport into a plausible value.
  const invalid = Buffer.concat([Buffer.from('{"ok":true,"op":"inspect","pages":1,"inventory":', "utf8"), Buffer.from([0x80, 0x80]), Buffer.from("}", "utf8")]);
  assert.equal(reason(() => decodeResult(framing(invalid), 1024)), "INVALID_UTF8");

  // And a valid multi-byte sequence must still decode: the strictness must not break
  // the ordinary case, which includes Arabic field names.
  const arabic = Buffer.from(JSON.stringify({ ok: true, op: "inspect", pages: 1, inventory: { ...inventory, duplicates: ["اسم"] } }), "utf8");
  const decoded = decodeResult(framing(arabic), 1024);
  assert.equal(decoded.meta.ok, true);
});

test("D9: field names, options and value lengths use their own limits", () => {
  const at = (length: number) => "n".repeat(length);
  // A field name is bounded by FORM_FIELD_NAME_LIMIT (200), not by the value-count
  // limit. At the boundary it must pass; one over must fail.
  const nameOk = parseMeta({ ok: true, op: "inspect", pages: 1, inventory: { ...inventory, fields: [{ name: at(200), kind: "text", page: 1, required: false, readOnly: false, value: null }] } });
  assert.equal(nameOk.ok, true, "a 200-character name is legal");
  assert.equal(
    reason(() => parseMeta({ ok: true, op: "inspect", pages: 1, inventory: { ...inventory, fields: [{ name: at(201), kind: "text", page: 1, required: false, readOnly: false, value: null }] } })),
    "INVALID_INVENTORY",
    "a 201-character name is not",
  );

  // Option *count* is bounded by FORM_OPTION_LIMIT (200). The old code bounded it by
  // FORM_FIELD_LIMIT (400), so a 300-entry list was accepted.
  const options = (count: number) => Array.from({ length: count }, (_, index) => `option-${index}`);
  assert.equal(
    parseMeta({ ok: true, op: "inspect", pages: 1, inventory: { ...inventory, fields: [{ name: "a", kind: "dropdown", page: 1, required: false, readOnly: false, value: null, options: options(200) }] } }).ok,
    true,
    "200 options is the ceiling and is accepted",
  );
  assert.equal(
    reason(() => parseMeta({ ok: true, op: "inspect", pages: 1, inventory: { ...inventory, fields: [{ name: "a", kind: "dropdown", page: 1, required: false, readOnly: false, value: null, options: options(300) }] } })),
    "INVALID_INVENTORY",
    "300 options exceeds FORM_OPTION_LIMIT even though it is under FORM_FIELD_LIMIT",
  );

  // An optionlist *selection count* uses the option limit, and each selected string
  // uses the character limit.
  const selections = (count: number) => Array.from({ length: count }, (_, index) => `s${index}`);
  assert.equal(
    parseMeta({ ok: true, op: "inspect", pages: 1, inventory: { ...inventory, fields: [{ name: "a", kind: "optionlist", page: 1, required: false, readOnly: false, value: selections(200) }] } }).ok,
    true,
  );
  assert.equal(
    reason(() => parseMeta({ ok: true, op: "inspect", pages: 1, inventory: { ...inventory, fields: [{ name: "a", kind: "optionlist", page: 1, required: false, readOnly: false, value: selections(201) }] } })),
    "INVALID_INVENTORY",
  );
  // A 4,000-character value is legal; 4,001 is not.
  assert.equal(
    parseMeta({ ok: true, op: "inspect", pages: 1, inventory: { ...inventory, fields: [{ name: "a", kind: "text", page: 1, required: false, readOnly: false, value: "v".repeat(4000) }] } }).ok,
    true,
  );
  assert.equal(
    reason(() => parseMeta({ ok: true, op: "inspect", pages: 1, inventory: { ...inventory, fields: [{ name: "a", kind: "text", page: 1, required: false, readOnly: false, value: "v".repeat(4001) }] } })),
    "INVALID_INVENTORY",
  );
});

test("D8: the framing ceilings are bounded before allocation", () => {
  // A declared length beyond the ceiling must be rejected from the header alone, so no
  // buffer of that size is ever reserved.
  const header = Buffer.alloc(4);
  header.writeUInt32BE(WORKER_LIMITS.metaBytes + 1, 0);
  assert.equal(reason(() => decodeResult(Buffer.concat([header, Buffer.from("{}")]), 1024)), "FIELD_TOO_LARGE");
  // A declared length that runs past the buffer is a truncation, not an allocation.
  const short = Buffer.alloc(4);
  short.writeUInt32BE(64, 0);
  assert.equal(reason(() => decodeResult(Buffer.concat([short, Buffer.from("{}")]), 1024)), "TRUNCATED");
});

test("an encoded result round-trips, and a fill frame carries its exact output", () => {
  const output = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 1, 2, 3]);
  const frame = encodeResult(
    { ok: true, op: "fill", pages: 1, outBytes: output.byteLength, checksum: createHash("sha256").update(output).digest("hex"), report: { filled: 1, untouched: 0, rasterAppearances: 0, flatten: false } },
    output,
  );
  const decoded = decodeResult(frame, 1024);
  assert.deepEqual(decoded.output, output);
  assert.equal(decoded.meta.ok, true);
});
