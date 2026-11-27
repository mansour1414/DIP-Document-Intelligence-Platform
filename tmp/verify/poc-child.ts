import { writeSync } from "node:fs";
import { PDFDocument } from "pdf-lib";
// Exercise a path alias too: if tsconfig paths resolve in the child, this works.
import { FORM_FIELD_LIMIT } from "@/lib/pdf/form-types";

const chunks: Buffer[] = [];
process.stdin.on("data", (c: Buffer) => chunks.push(c));
process.stdin.on("end", async () => {
  const all = Buffer.concat(chunks);
  const metaLen = all.readUInt32BE(0);
  const meta = JSON.parse(all.subarray(4, 4 + metaLen).toString("utf8"));
  const input = all.subarray(4 + metaLen);
  const doc = await PDFDocument.load(input);
  const metaBuf = Buffer.from(JSON.stringify({
    ok: true, op: meta.op, pages: doc.getPageCount(), alias: FORM_FIELD_LIMIT,
  }), "utf8");
  const h = Buffer.alloc(4); h.writeUInt32BE(metaBuf.length, 0);
  writeSync(3, Buffer.concat([h, metaBuf]));
  process.exitCode = 0;
});
