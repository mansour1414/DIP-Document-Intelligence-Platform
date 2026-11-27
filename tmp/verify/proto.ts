import {
  encodeControl, decodeControl, encodeResult, decodeResult,
  WorkerProtocolError, WORKER_PROTOCOL_VERSION, assertPages, parseMeta,
} from "../../src/lib/pdf/worker-protocol";

let pass = 0, fail = 0;
const ok = (name: string) => { pass++; console.log("  ok  ", name); };
const bad = (name: string, e?: unknown) => { fail++; console.log("  FAIL", name, "->", (e as Error)?.message); };
function expects(name: string, fn: () => unknown, reason: string) {
  try { fn(); bad(name + " (no throw)"); }
  catch (e) { (e instanceof WorkerProtocolError && e.reason === reason) ? ok(`${name} -> ${reason}`) : bad(name, `wrong error: ${(e as WorkerProtocolError).reason}`); }
}

const pdf = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x00, 0xff, 0x10]);
// --- control round trip
const c = encodeControl({ v: WORKER_PROTOCOL_VERSION, op: "fill", flatten: true, fields: { a: "x", b: true, c: ["1","2"] } }, pdf);
const back = decodeControl(c, 1024);
console.log("control round-trip:", back.control.op, "| pdf identical:", Buffer.compare(Buffer.from(pdf), Buffer.from(back.pdf)) === 0);
(back.control.op === "fill" && back.control.flatten === true) ? ok("fill control") : bad("fill control", "mismatch");

// --- result round trip
const out = new Uint8Array([0x25, 0x50, 0x44, 0x46, 9, 9]);
const r = encodeResult({ ok: true, op: "fill", pages: 3, outBytes: out.byteLength, checksum: "a".repeat(64), report: { filled: 2, untouched: 1, rasterAppearances: 0, flatten: false } }, out);
const rf = decodeResult(r, 1024);
(rf.output && Buffer.compare(Buffer.from(out), Buffer.from(rf.output)) === 0) ? ok("fill result round-trip (binary)") : bad("fill result", "bytes differ");

const i = decodeResult(encodeResult({ ok: true, op: "inspect", pages: 2, inventory: { fields: [], unsupported: [], pages: 2, hasXfa: false, needAppearances: false, duplicates: [] } }), 1024);
(i.meta.ok && i.meta.op === "inspect" && i.meta.pages === 2) ? ok("inspect result") : bad("inspect", "mismatch");

// --- rejections
expects("truthy string discriminator", () => parseMeta({ ok: "true", op: "inspect", pages: 1, inventory: { fields: [], unsupported: [], pages: 1, hasXfa: false, needAppearances: false, duplicates: [] } }), "INVALID_DISCRIMINATOR");
expects("ok=1 discriminator", () => parseMeta({ ok: 1, op: "inspect", pages: 1, inventory: { fields: [], unsupported: [], pages: 1, hasXfa: false, needAppearances: false, duplicates: [] } }), "INVALID_DISCRIMINATOR");
expects("pages=0", () => parseMeta({ ok: true, op: "inspect", pages: 0, inventory: { fields: [], unsupported: [], pages: 1, hasXfa: false, needAppearances: false, duplicates: [] } }), "INVALID_PAGES");
expects("pages=-1", () => parseMeta({ ok: true, op: "inspect", pages: -1, inventory: { fields: [], unsupported: [], pages: 1, hasXfa: false, needAppearances: false, duplicates: [] } }), "INVALID_PAGES");
expects("pages=1.5", () => parseMeta({ ok: true, op: "inspect", pages: 1.5, inventory: { fields: [], unsupported: [], pages: 1, hasXfa: false, needAppearances: false, duplicates: [] } }), "INVALID_PAGES");
expects("pages=NaN", () => parseMeta({ ok: true, op: "inspect", pages: NaN, inventory: { fields: [], unsupported: [], pages: 1, hasXfa: false, needAppearances: false, duplicates: [] } }), "INVALID_PAGES");
expects("pages=Infinity", () => assertPages(Infinity), "INVALID_PAGES");
expects("pages=unsafe", () => assertPages(Number.MAX_SAFE_INTEGER + 2), "INVALID_PAGES");
expects("unknown op", () => parseMeta({ ok: true, op: "delete", pages: 1, inventory: { fields: [], unsupported: [], pages: 1, hasXfa: false, needAppearances: false, duplicates: [] } }), "UNKNOWN_OP");
expects("bad checksum", () => parseMeta({ ok: true, op: "fill", pages: 1, outBytes: 5, checksum: "zz", report: { filled:0,untouched:0,rasterAppearances:0,flatten:false } }), "INVALID_META");

// --- framing rejections
expects("truncated meta length", () => decodeResult(Buffer.from([0,0]), 1024), "TRUNCATED");
expects("oversized meta", () => { const b = Buffer.alloc(8); b.writeUInt32BE(5*1024*1024, 0); return decodeResult(b, 1024); }, "FIELD_TOO_LARGE");
expects("invalid json", () => { const j = Buffer.from("not json"); const h = Buffer.alloc(4); h.writeUInt32BE(j.length,0); return decodeResult(Buffer.concat([h,j]), 1024); }, "INVALID_JSON");
expects("trailing data after inspect", () => { const f = encodeResult({ ok: true, op: "inspect", pages: 1, inventory: { fields: [], unsupported: [], pages: 1, hasXfa: false, needAppearances: false, duplicates: [] } }); return decodeResult(Buffer.concat([f, Buffer.from("x")]), 1024); }, "TRAILING_DATA");
expects("output shorter than declared", () => { const f = encodeResult({ ok: true, op: "fill", pages: 1, outBytes: 10, checksum: "a".repeat(64), report: { filled:0,untouched:0,rasterAppearances:0,flatten:false } }, new Uint8Array(10)); return decodeResult(f.subarray(0, f.byteLength - 3), 1024); }, "TRUNCATED");
expects("output longer than declared", () => { const f = encodeResult({ ok: true, op: "fill", pages: 1, outBytes: 4, checksum: "a".repeat(64), report: { filled:0,untouched:0,rasterAppearances:0,flatten:false } }, new Uint8Array(4)); return decodeResult(Buffer.concat([f, Buffer.from([1])]), 1024); }, "TRAILING_DATA");
expects("output meta mismatch", () => { const f = encodeResult({ ok: true, op: "fill", pages: 1, outBytes: 4, checksum: "a".repeat(64), report: { filled:0,untouched:0,rasterAppearances:0,flatten:false } }, new Uint8Array(4)); f.writeUInt32BE(99, f.byteLength - 4 - 0); return decodeResult(f, 1024); }, "OUTPUT_LENGTH_MISMATCH");
expects("version mismatch", () => { const j = Buffer.from(JSON.stringify({ v: 99, op: "inspect" })); const h = Buffer.alloc(4); h.writeUInt32BE(j.length,0); return decodeControl(Buffer.concat([h,j]), 1024); }, "VERSION_MISMATCH");
expects("nested field value", () => { const j = Buffer.from(JSON.stringify({ v: WORKER_PROTOCOL_VERSION, op: "fill", flatten: false, fields: { a: { evil: 1 } } })); const h = Buffer.alloc(4); h.writeUInt32BE(j.length,0); return decodeControl(Buffer.concat([h,j]), 1024); }, "INVALID_FIELDS");
expects("pdf over limit", () => decodeControl(encodeControl({ v: WORKER_PROTOCOL_VERSION, op: "inspect" }, new Uint8Array(2048)), 1024), "PDF_TOO_LARGE");

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
