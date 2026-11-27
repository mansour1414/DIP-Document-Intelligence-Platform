import { readFileSync, writeSync } from "node:fs";
// Read a 4-byte big-endian length, then that many bytes, from fd 0.
const chunks = [];
process.stdin.on("data", (c) => chunks.push(c));
process.stdin.on("end", () => {
  const all = Buffer.concat(chunks);
  const metaLen = all.readUInt32BE(0);
  const meta = JSON.parse(all.subarray(4, 4 + metaLen).toString("utf8"));
  const pdf = all.subarray(4 + metaLen);
  // Reply on fd 3: [4-byte metaLen][meta JSON][4-byte pdfLen][pdf bytes]
  const replyMeta = Buffer.from(JSON.stringify({ ok: true, op: meta.op, pages: 7, outLen: pdf.byteLength }), "utf8");
  const header = Buffer.alloc(4);
  header.writeUInt32BE(replyMeta.length, 0);
  const outHeader = Buffer.alloc(4);
  outHeader.writeUInt32BE(pdf.byteLength, 0);
  // fd 3 is opened as a pipe for writing by the child.
  const combined = Buffer.concat([header, replyMeta, outHeader, pdf]);
  writeSync(3, combined);
  process.exitCode = 0;
});
