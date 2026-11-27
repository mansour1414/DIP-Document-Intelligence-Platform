// Does the child's writeAll() survive a frame much larger than the pipe buffer?
// The fake child emits a real framed fill result with a multi-megabyte payload.
import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { decodeResult } from "../../src/lib/pdf/worker-protocol";

function buildFrame(payload: Buffer) {
  const checksum = createHash("sha256").update(payload).digest("hex");
  const meta = Buffer.from(JSON.stringify({ ok: true, op: "fill", pages: 1, outBytes: payload.length, checksum, report: { filled: 1, untouched: 0, rasterAppearances: 0, flatten: false } }), "utf8");
  const u32 = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32BE(n, 0); return b; };
  return { frame: Buffer.concat([u32(meta.length), meta, u32(payload.length), payload]), checksum };
}
const SIZE = 8 * 1024 * 1024;
const payload = Buffer.alloc(SIZE); for (let i = 0; i < SIZE; i++) payload[i] = (i * 31 + 7) % 256;
const { frame } = buildFrame(payload);
// The fake child writes in 64 KiB slices *using the child's writeAll*, to reproduce
// the short-write condition the real child must handle.
const entry = "/tmp/large-child.mjs";
writeFileSync(entry, [
  "import { writeSync } from 'node:fs';",
  `const frame = Buffer.from(${JSON.stringify(frame.toString("hex"))}, "hex");`,
  "function writeAll(f) { let o = 0; while (o < f.byteLength) { const n = writeSync(3, f, o, Math.min(65536, f.byteLength - o)); if (n <= 0) throw new Error('short'); o += n; } }",
  "process.stdin.resume(); process.stdin.on('data', () => {});",
  "process.stdin.on('end', () => { writeAll(frame); process.exitCode = 0; });",
].join("\n"));
const child = spawn(process.execPath, [entry], { stdio: ["pipe", "pipe", "pipe", "pipe"], shell: false });
const chunks: Buffer[] = []; let total = 0;
const pipe = child.stdio[3]!;
pipe.on("data", (c: Buffer) => { chunks.push(c); total += c.byteLength; });
child.stdin.end(Buffer.from("x"));
child.on("close", (code) => {
  console.log("child exit:", code, "| received bytes:", total, "| expected:", frame.byteLength);
  const decoded = decodeResult(Buffer.concat(chunks), 32 * 1024 * 1024);
  if (decoded.meta.ok && decoded.meta.op === "fill") {
    const ok = decoded.output!.byteLength === SIZE && createHash("sha256").update(decoded.output!).digest("hex") === decoded.meta.checksum;
    console.log("decoded output bytes:", decoded.output!.byteLength, "| integrity:", ok);
    console.log("exceeds 64KiB pipe buffer:", frame.byteLength > 65536);
  }
});
