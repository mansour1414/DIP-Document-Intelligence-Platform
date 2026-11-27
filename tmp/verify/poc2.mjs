import { spawn } from "node:child_process";
import { PDFDocument } from "pdf-lib";
// Bigger binary payload to force multiple chunks + backpressure.
const doc = await PDFDocument.create();
for (let i = 0; i < 40; i++) doc.addPage();
const pdf = new Uint8Array(await doc.save());
console.log("input pdf:", pdf.byteLength, "bytes");

const child = spawn(process.execPath, ["--max-old-space-size=256", "tmp/verify/poc-child.mjs"], {
  stdio: ["pipe", "pipe", "pipe", "pipe"],
  shell: false,
  env: { PATH: process.env.PATH, NODE_ENV: "production" },
});
const parts = [];
child.stdio[3].on("data", (c) => parts.push(c));
let stderr = "";
child.stderr.on("data", (c) => { stderr += c; });
child.once("close", (code) => {
  const buf = Buffer.concat(parts);
  const metaLen = buf.readUInt32BE(0);
  const m = JSON.parse(buf.subarray(4, 4 + metaLen).toString("utf8"));
  const pdfLen = buf.readUInt32BE(4 + metaLen);
  const out = buf.subarray(8 + metaLen);
  console.log("exit:", code, "| meta:", JSON.stringify(m));
  console.log("out bytes:", out.byteLength, "| declared:", pdfLen, "| identical:", Buffer.compare(Buffer.from(pdf), out) === 0);
  if (stderr) console.log("stderr:", stderr.slice(0, 200));
});
const control = Buffer.from(JSON.stringify({ op: "inspect" }), "utf8");
const h = Buffer.alloc(4); h.writeUInt32BE(control.length, 0);
child.stdin.end(Buffer.concat([h, control, Buffer.from(pdf)]));
