import { encodeResult, decodeResult } from "../../src/lib/pdf/worker-protocol";
const out = new Uint8Array(4);
const f = encodeResult({ ok: true, op: "fill", pages: 1, outBytes: 4, checksum: "a".repeat(64), report: { filled:0,untouched:0,rasterAppearances:0,flatten:false } }, out);
const metaLen = f.readUInt32BE(0);
const outLenOffset = 4 + metaLen;
console.log("declared outBytes:", 4, "| outLen field at", outLenOffset, "=", f.readUInt32BE(outLenOffset));
// Patch the declared output length to disagree with the metadata's outBytes.
f.writeUInt32BE(8, outLenOffset);
try { decodeResult(f, 1024); console.log("FAIL: accepted mismatch"); }
catch (e: any) { console.log("patching declared length to 8 ->", e.reason); }
// And the genuine case: metadata says outBytes=4 but stream carries 4 while meta says 5.
const g = encodeResult({ ok: true, op: "fill", pages: 1, outBytes: 5, checksum: "a".repeat(64), report: { filled:0,untouched:0,rasterAppearances:0,flatten:false } }, out);
try { decodeResult(g, 1024); console.log("FAIL: accepted outBytes mismatch"); }
catch (e: any) { console.log("meta outBytes=5 with 4 bytes ->", e.reason); }
