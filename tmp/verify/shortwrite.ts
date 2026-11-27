// Force the short-write condition: a reader that pauses, so the pipe buffer fills
// and writeSync must return a partial count.
import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";
const entry = "/tmp/short-child.mjs";
writeFileSync(entry, [
  "import { writeSync } from 'node:fs';",
  "const buf = Buffer.alloc(4 * 1024 * 1024, 0x41);",
  "const chunks = [];",
  "for (let attempt = 0; attempt < 50; attempt++) {",
  "  let o = 0;",
  "  while (o < buf.byteLength) { const n = writeSync(3, buf, o); chunks.push(n); o += n; if (o < buf.byteLength) break; }",
  "  if (o === buf.byteLength) { process.stdout.write(JSON.stringify({ singleCallWrote: chunks[0], totalBytes: buf.byteLength })); process.exit(0); }",
  "}",
  "process.stdout.write(JSON.stringify({ partialWrites: chunks.slice(0, 5), totalBytes: buf.byteLength }));",
].join("\n"));
const child = spawn(process.execPath, [entry], { stdio: ["pipe", "pipe", "pipe", "pipe"], shell: false });
let out = "";
child.stdout.on("data", (c: Buffer) => { out += c.toString(); });
// Read fd 3 slowly in tiny bites, with pauses, to keep the pipe full.
const pipe = child.stdio[3] as NodeJS.ReadableStream;
let total = 0;
pipe.on("data", (c: Buffer) => { total += c.byteLength; });
pipe.pause();
const timer = setInterval(() => { pipe.resume(); setTimeout(() => pipe.pause(), 5); }, 60);
child.on("close", () => {
  clearInterval(timer);
  console.log("child report:", out);
  console.log("parent received:", total, "bytes");
});
