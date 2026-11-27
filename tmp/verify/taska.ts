import { readFile } from "node:fs/promises";
async function main() {
  const source = await readFile(new URL("../../src/lib/jobs/orchestrator.ts", import.meta.url), "utf8");
  const shape = source.indexOf("assertCheapPdfShape(");
  const scan = source.indexOf("requireCleanUpload(");
  const parse = source.indexOf("validateUpload({");
  const store = source.indexOf("storage.put(");
  const bill = source.indexOf("enforceJobCreation(");
  const job = source.indexOf("tx.job.create(");
  console.log("shape:", shape, "| scan:", scan, "| parse(OLD):", parse);
  console.log("store:", store, "| bill:", bill, "| job:", job);
  console.log("=> 'upload validation must exist' would FAIL because parse ==", parse);
}
main();
