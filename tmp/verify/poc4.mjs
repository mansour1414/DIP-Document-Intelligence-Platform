import { spawn } from "node:child_process";
import { PDFDocument } from "pdf-lib";
const doc = await PDFDocument.create(); doc.addPage(); doc.addPage();
const pdf = new Uint8Array(await doc.save());
const child = spawn(process.execPath, ["--import", "./scripts/node-platform-compat.mjs", "--import", "tsx", "tmp/verify/poc-child.ts"], {
  stdio: ["pipe", "pipe", "pipe", "pipe"], shell: false,
  env: { PATH: process.env.PATH, NODE_ENV: "production" },
});
const parts = []; let err = "";
child.stdio[3].on("data", (c) => parts.push(c));
child.stderr.on("data", (c) => { err += c; });
child.once("close", (code) => {
  console.log("exit:", code);
  if (err) console.log("stderr:", err.slice(0, 300));
  const buf = Buffer.concat(parts);
  if (buf.byteLength < 4) return console.log("no fd3 data");
  const len = buf.readUInt32BE(0);
  console.log("meta:", buf.subarray(4, 4 + len).toString("utf8"));
});
const ctrl = Buffer.from(JSON.stringify({ op: "inspect" }), "utf8");
const h = Buffer.alloc(4); h.writeUInt32BE(ctrl.length, 0);
child.stdin.end(Buffer.concat([h, ctrl, Buffer.from(pdf)]));
