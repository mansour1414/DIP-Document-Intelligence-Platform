import { spawn } from "node:child_process";
const child = spawn(process.execPath, ["tmp/verify/poc-child.mjs"], {
  stdio: ["pipe", "pipe", "pipe", "pipe"],   // fd 3 becomes a pipe
  env: { PATH: process.env.PATH, NODE_ENV: "production" },
});
let meta = Buffer.alloc(0);
child.stdio[3].on("data", (c) => { meta = Buffer.concat([meta, c]); });
child.once("close", (code) => {
  console.log("exit:", code, "| fd3 bytes:", meta.byteLength);
  const metaLen = meta.readUInt32BE(0);
  const m = JSON.parse(meta.subarray(4, 4 + metaLen).toString("utf8"));
  const pdfLen = meta.readUInt32BE(4 + metaLen);
  const pdf = meta.subarray(8 + metaLen);
  console.log("meta:", JSON.stringify(m));
  console.log("pdf bytes recovered:", pdf.byteLength, "| match:", pdfLen === pdf.byteLength);
  console.log("pdf is binary-safe:", pdf.subarray(0,5).toString() === "%PDF-");
});
const control = Buffer.from(JSON.stringify({ op: "inspect" }), "utf8");
const h = Buffer.alloc(4); h.writeUInt32BE(control.length, 0);
const pdf = Buffer.from("%PDF-1.7\nbinary\u0000\u00ff bytes");
child.stdin.end(Buffer.concat([h, control, pdf]));
