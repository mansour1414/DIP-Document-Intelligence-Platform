/**
 * PR-1 structural assertions.
 *
 * These are source-shape checks, not executed behaviour: they guard the two
 * properties that are easy to regress in review (ordering and single write path)
 * while `pr1-output-screening.test.ts` proves the behaviour itself.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path: string) => readFile(new URL(`../${path}`, import.meta.url), "utf8");

test("PR-1 (structure): the worker no longer writes outputs itself", async () => {
  const worker = await read("workers/document-worker.ts");
  assert.doesNotMatch(worker, /storage\.put\(/, "all output writes must go through the screening module");
  assert.doesNotMatch(worker, /validateWorkerOutputs/, "output validation moved with the pipeline");
  assert.match(worker, /import \{ processDocumentJob \} from "@\/lib\/jobs\/document-pipeline"/);
  assert.match(worker, /toDocumentQueueError/, "queue-level retry classification must be applied");
  assert.match(worker, /isUnrecoverableQueueError\(error\)/, "unrecoverable failures must not park the job in RETRYING");
});

test("PR-1 (structure): scan completes before the first put, and before any job success write", async () => {
  const pipeline = await read("src/lib/jobs/document-pipeline.ts");
  assert.doesNotMatch(pipeline, /storage\.put\(/);
  const validate = pipeline.indexOf("validateWorkerOutputs(");
  const screen = pipeline.indexOf("screenAndStoreWorkerOutputs(");
  const success = pipeline.indexOf("outputFileId: outputFileIds[0]");
  assert.ok(validate > -1 && screen > -1 && success > -1);
  assert.ok(validate < screen, "validation must run before screening");
  assert.ok(screen < success, "screening must run before the job is marked SUCCEEDED");
});

test("PR-1 (structure): the screening module scans the whole batch before storing", async () => {
  const screening = await read("src/lib/outputs/screening.ts");
  assert.ok(screening.indexOf("await screenWorkerOutputs(outputs") < screening.indexOf("await storeWorkerOutputs(outputs"));
  assert.match(screening, /requireCleanOutput/, "scans must reuse the audited scan primitive");
  assert.match(screening, /deleteObject/, "partial writes must be compensated");
  const malware = await read("src/lib/malware/index.ts");
  assert.match(malware, /source: "output"/, "output rejections are recorded as output-sourced security events");
});

test("PR-1a (structure): job state is only written through compare-and-set guards", async () => {
  const pipeline = await read("src/lib/jobs/document-pipeline.ts");
  assert.doesNotMatch(pipeline, /tx\.job\.update\(/, "job state must never be written as an unconditional row update");
  assert.doesNotMatch(pipeline, /tx\.jobStep\.update\(/, "step state must never be written as an unconditional row update");
  assert.match(pipeline, /updateMany\(\{\s*where: \{ id: job\.id, outputFileId: null, status: \{ notIn:/, "the SUCCEEDED commit is a compare-and-set on an uncommitted job");
  assert.match(pipeline, /status: \{ not: "SUCCEEDED" \}/, "a failure write cannot overwrite a committed job or step");
  assert.match(pipeline, /OutputCommitSupersededError/, "a lost commit race is recognised explicitly");
  assert.match(pipeline, /isReferenced: async \(key\) => owned\.has\(key\)/, "cleanup deletes only unreferenced objects");
  const screening = await read("src/lib/outputs/screening.ts");
  assert.match(screening, /\/\$\{attemptId\}\//, "output keys are attempt-scoped");
  assert.doesNotMatch(screening, /output\/\$\{job\.requesterId \?\? "system"\}\/\$\{job\.id\}\/\$\{index\}-/, "the shared per-job key must be gone");
});

test("PR-1 (structure): no retention, registry, licensing or security-gate configuration was touched", async () => {
  const screening = await read("src/lib/outputs/screening.ts");
  for (const forbidden of [/retention/i, /toolRegistry|tool-registry|src\/config/, /licen[cs]/i, /R1|R2/]) {
    assert.doesNotMatch(screening, forbidden);
  }
});
