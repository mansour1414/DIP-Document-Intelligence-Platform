import { readFile } from "node:fs/promises";
const source = await readFile("src/lib/jobs/orchestrator.ts", "utf8");
const pos = (n) => { const i = source.indexOf(n); if (i <= 0) throw new Error(`${n} missing`); return i; };
const cheap = pos("validateUploadBytes({"), scan = pos("requireCleanUpload("), parse = pos("validateUploadWithParse({");
const inspect = pos("await assertFillableInput(screened[0]"), store = pos("storage.put("), bill = pos("enforceJobCreation("), job = pos("tx.job.create(");
const checks = [
  ["parser-free before scan", cheap < scan],
  ["parse after scan", parse > scan],
  ["inspect after scan", inspect > scan],
  ["durable after scan", store > scan && job > scan && bill > scan],
  ["durable after inspect", store > inspect && job > inspect && bill > inspect],
];
for (const [name, ok] of checks) console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
console.log("positions:", { cheap, scan, parse, inspect, store, bill, job });
