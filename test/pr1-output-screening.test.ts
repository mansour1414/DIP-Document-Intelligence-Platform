/**
 * PR-1 behavioural coverage for fail-closed screening of generated worker outputs.
 *
 * These tests drive the real screening/storage module with injected scanners and
 * an in-memory object store, so ordering, batching and rollback are executed
 * rather than asserted against source text. Database-backed and real-clamd
 * evidence lives in `pr1-output-screening.integration.test.ts`.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  OutputScanError,
  discardStoredObjects,
  outputStorageKey,
  screenAndStoreWorkerOutputs,
  screenWorkerOutputs,
  storeWorkerOutputs,
} from "../src/lib/outputs/screening";
import { isUnrecoverableQueueError, toDocumentQueueError } from "../src/lib/jobs/queue-errors";
import { setMalwareScannerForTests, type MalwareScanner, type MalwareScanResultCode } from "../src/lib/malware";
import type { ObjectStorage, StoredObject } from "../src/lib/storage";
import type { WorkerOutput } from "../src/lib/outputs/validation";

const pdf = (label: string, padding = 0) => new TextEncoder().encode(`%PDF-1.7\n${label}${"x".repeat(padding)}\n%%EOF`);
const output = (name: string, padding = 0): WorkerOutput => ({ name, mimeType: "application/pdf", bytes: pdf(name, padding) });
const job = { id: "job-1", requesterId: "user-1" };

type Log = string[];

function scriptedScanner(script: Array<MalwareScanResultCode | "THROW">, log: Log = []): MalwareScanner {
  let index = 0;
  return {
    async scan() {
      const step = script[Math.min(index, script.length - 1)];
      log.push(`scan:${index}`);
      index += 1;
      if (step === "THROW") throw new Error("clamd socket closed");
      return { result: step, engine: "scripted", engineVersion: "1.0.0", signatureVersion: "sig-1", scannedAt: new Date(0) };
    },
  };
}

function fakeStorage(options: { failPut?: number[]; failDelete?: number[] } = {}) {
  const log: Log = [];
  const objects = new Map<string, Uint8Array>();
  let puts = 0;
  let deletes = 0;
  const storage: ObjectStorage = {
    createUploadKey: ({ filename }) => `input/${filename}`,
    async put({ key, bytes, contentType, checksum }): Promise<StoredObject> {
      log.push(`put:${key}`);
      const position = puts++;
      if (options.failPut?.includes(position)) throw Object.assign(new Error("storage write failed"), { code: "STORAGE_FAILURE" });
      objects.set(key, bytes);
      return { key, bucket: "dip-test", contentType, size: bytes.byteLength, checksum };
    },
    async get(key) { return objects.get(key) ?? new Uint8Array(); },
    async head(key) { const bytes = objects.get(key); return bytes ? { key, bucket: "dip-test", contentType: "application/pdf", size: bytes.byteLength } : undefined; },
    async exists(key) { return objects.has(key); },
    async deleteObject(key) {
      log.push(`delete:${key}`);
      const position = deletes++;
      if (options.failDelete?.includes(position)) throw new Error("delete failed");
      objects.delete(key);
    },
    async close() {},
  };
  return { storage, objects, log };
}

// ---------------------------------------------------------------- ordering

test("PR-1: every output is scanned before the first storage write", async () => {
  const log: Log = [];
  const { storage } = fakeStorage();
  const original = storage.put.bind(storage);
  storage.put = async (input) => { log.push(`put:${input.key.split("/").pop()}`); return original(input); };
  storage.deleteObject = async (key) => { log.push(`delete:${key}`); };

  const outputs = [output("a.pdf"), output("b.pdf"), output("c.pdf")];
  const { stored } = await screenAndStoreWorkerOutputs(outputs, { job, storage, scanner: scriptedScanner(["CLEAN"], log) });

  assert.equal(stored.length, 3);
  assert.deepEqual(log, ["scan:0", "scan:1", "scan:2", "put:0-a.pdf", "put:1-b.pdf", "put:2-c.pdf"], "all scans must precede every put");
});

// ------------------------------------------------------------------- clean

test("PR-1: a clean batch is stored under deterministic keys with base64 sha256 checksums", async () => {
  const { storage, objects } = fakeStorage();
  const outputs = [output("merge-result.pdf"), output("pages 1-2.pdf")];
  const { stored, scans } = await screenAndStoreWorkerOutputs(outputs, { job, storage, scanner: scriptedScanner(["CLEAN"]) });

  assert.deepEqual(stored.map((item) => item.object.key), [
    "output/user-1/job-1/0-merge-result.pdf",
    "output/user-1/job-1/1-pages_1-2.pdf",
  ]);
  assert.equal(stored[0].checksum, createHash("sha256").update(outputs[0].bytes).digest("base64"));
  assert.equal(scans.length, 2);
  assert.ok(scans.every((scan) => scan.engine === "scripted" && scan.signatureVersion === "sig-1"));
  assert.equal(objects.size, 2);
});

// ---------------------------------------------------------------- infected

test("PR-1: an infected output rejects the batch and writes nothing", async () => {
  const { storage, objects, log } = fakeStorage();
  const outputs = [output("only.pdf")];
  await assert.rejects(
    () => screenAndStoreWorkerOutputs(outputs, { job, storage, scanner: scriptedScanner(["INFECTED"]) }),
    (error: unknown) => {
      assert.ok(error instanceof OutputScanError);
      assert.equal(error.code, "INFECTED");
      assert.equal(error.unrecoverable, true, "infected outputs must not be retried");
      assert.equal(error.failures.length, 1);
      assert.equal(error.failures[0].index, 0);
      return true;
    },
  );
  assert.deepEqual(log.filter((entry) => entry.startsWith("put:")), [], "no bytes may be stored for a rejected batch");
  assert.equal(objects.size, 0);
});

test("PR-1: one infected member rejects a multi-output batch, and no clean sibling is stored", async () => {
  const { storage, objects, log } = fakeStorage();
  const outputs = [output("one.pdf"), output("two.pdf"), output("three.pdf")];
  await assert.rejects(
    () => screenAndStoreWorkerOutputs(outputs, { job, storage, scanner: scriptedScanner(["CLEAN", "INFECTED", "CLEAN"], log) }),
    (error: unknown) => {
      assert.ok(error instanceof OutputScanError);
      assert.equal(error.code, "INFECTED");
      assert.equal(error.failures.length, 1, "only the infected member is reported");
      assert.equal(error.failures[0].index, 1);
      return true;
    },
  );
  assert.equal(log.filter((entry) => entry.startsWith("scan:")).length, 3, "the whole batch is still scanned");
  assert.deepEqual(log.filter((entry) => entry.startsWith("put:")), [], "a clean sibling must not be published");
  assert.equal(objects.size, 0);
});

// ------------------------------------------------------- scanner unhealthy

test("PR-1: a scanner fault rejects the batch and stays retryable", async () => {
  const { storage, objects } = fakeStorage();
  for (const code of ["SCANNER_UNAVAILABLE", "SCAN_ERROR", "SCAN_TIMEOUT"] as const) {
    await assert.rejects(
      () => screenAndStoreWorkerOutputs([output("a.pdf")], { job, storage, scanner: scriptedScanner([code]) }),
      (error: unknown) => {
        assert.ok(error instanceof OutputScanError);
        assert.equal(error.code, code);
        assert.equal(error.unrecoverable, false, `${code} must remain retryable`);
        return true;
      },
    );
  }
  assert.equal(objects.size, 0);
});

test("PR-1: a thrown scanner error is normalized to SCAN_ERROR rather than escaping", async () => {
  const { storage, objects } = fakeStorage();
  await assert.rejects(
    () => screenAndStoreWorkerOutputs([output("a.pdf")], { job, storage, scanner: scriptedScanner(["THROW"]) }),
    (error: unknown) => error instanceof OutputScanError && error.code === "SCAN_ERROR" && error.unrecoverable === false,
  );
  assert.equal(objects.size, 0);
});

test("PR-1: an unconfigured scanner rejects every output instead of storing bytes", async () => {
  const previousHost = process.env.CLAMD_HOST;
  const { storage, objects } = fakeStorage();
  delete process.env.CLAMD_HOST;
  setMalwareScannerForTests(undefined);
  try {
    const outputs = [output("a.pdf"), output("b.pdf")];
    await assert.rejects(
      () => screenAndStoreWorkerOutputs(outputs, { job, storage }),
      (error: unknown) => {
        assert.ok(error instanceof OutputScanError);
        assert.equal(error.code, "SCANNER_UNAVAILABLE");
        assert.deepEqual(error.failures.map((failure) => failure.index), [0, 1]);
        assert.equal(error.unrecoverable, false);
        return true;
      },
    );
    assert.equal(objects.size, 0);
  } finally {
    setMalwareScannerForTests(undefined);
    if (previousHost === undefined) delete process.env.CLAMD_HOST; else process.env.CLAMD_HOST = previousHost;
  }
});

// --------------------------------------------------------- storage failures

test("PR-1: a mid-batch storage failure deletes the objects it already wrote and rethrows", async () => {
  const { storage, objects, log } = fakeStorage({ failPut: [1] });
  const outputs = [output("a.pdf"), output("b.pdf"), output("c.pdf")];
  await assert.rejects(
    () => screenAndStoreWorkerOutputs(outputs, { job, storage, scanner: scriptedScanner(["CLEAN"]) }),
    (error: unknown) => (error as { code?: string }).code === "STORAGE_FAILURE",
  );
  assert.deepEqual(log.filter((entry) => entry.startsWith("delete:")), ["delete:output/user-1/job-1/0-a.pdf"]);
  assert.equal(objects.size, 0, "no partial batch may survive a storage fault");
});

test("PR-1: a failing first write leaves nothing to clean up", async () => {
  const { storage, objects, log } = fakeStorage({ failPut: [0] });
  await assert.rejects(() => screenAndStoreWorkerOutputs([output("a.pdf"), output("b.pdf")], { job, storage, scanner: scriptedScanner(["CLEAN"]) }));
  assert.deepEqual(log.filter((entry) => entry.startsWith("delete:")), []);
  assert.equal(objects.size, 0);
});

test("PR-1: a failed compensating delete never masks the original storage error", async () => {
  const { storage } = fakeStorage({ failPut: [1], failDelete: [0] });
  await assert.rejects(
    () => storeWorkerOutputs([output("a.pdf"), output("b.pdf")], { storage, keyFor: (item, index) => outputStorageKey(job, item, index) }),
    (error: unknown) => (error as { code?: string }).code === "STORAGE_FAILURE",
  );
});

test("PR-1: discardStoredObjects is best effort and swallows cleanup faults", async () => {
  const { storage } = fakeStorage({ failDelete: [0] });
  await discardStoredObjects(storage, ["output/user-1/job-1/0-a.pdf", "output/user-1/job-1/1-b.pdf"]);
});

// ---------------------------------------------------------------- retries

test("PR-1: a retried job rewrites the same keys instead of orphaning new objects", async () => {
  const outputs = [output("a.pdf"), output("b.pdf")];
  const first = fakeStorage({ failPut: [1] });
  await assert.rejects(() => screenAndStoreWorkerOutputs(outputs, { job, storage: first.storage, scanner: scriptedScanner(["CLEAN"]) }));
  assert.equal(first.objects.size, 0, "the failed attempt leaves no residue");

  const second = fakeStorage();
  await screenAndStoreWorkerOutputs(outputs, { job, storage: second.storage, scanner: scriptedScanner(["CLEAN"]) });
  await screenAndStoreWorkerOutputs(outputs, { job, storage: second.storage, scanner: scriptedScanner(["CLEAN"]) });
  assert.deepEqual([...second.objects.keys()].sort(), [
    "output/user-1/job-1/0-a.pdf",
    "output/user-1/job-1/1-b.pdf",
  ], "a replay overwrites the same two keys, it does not add more");
});

test("PR-1: infected outputs map to an unrecoverable queue error; scanner faults stay retryable", async () => {
  const infected = new OutputScanError([{ index: 0, name: "a.pdf", code: "INFECTED" }]);
  const unavailable = new OutputScanError([{ index: 0, name: "a.pdf", code: "SCANNER_UNAVAILABLE" }]);

  const mapped = toDocumentQueueError(infected);
  assert.equal(mapped.name, "UnrecoverableError");
  assert.equal(isUnrecoverableQueueError(mapped), true);

  assert.equal(toDocumentQueueError(unavailable), unavailable, "a retryable scan fault is passed through unchanged");
  assert.equal(isUnrecoverableQueueError(unavailable), false);

  const plain = new Error("storage write failed");
  assert.equal(toDocumentQueueError(plain), plain);
  assert.equal(toDocumentQueueError("not an error").message, "Processing failed");
  assert.equal(isUnrecoverableQueueError(undefined), false);
});

// ------------------------------------------------------------- log hygiene

test("PR-1: rejection messages carry no output bytes or filenames", async () => {
  const { storage } = fakeStorage();
  const secret = "TENANT-CONTENT-MARKER";
  const outputs: WorkerOutput[] = [{ name: `${secret}.pdf`, mimeType: "application/pdf", bytes: new TextEncoder().encode(`%PDF-1.7\n${secret}`) }];
  await assert.rejects(
    () => screenAndStoreWorkerOutputs(outputs, { job, storage, scanner: scriptedScanner(["INFECTED"]) }),
    (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.doesNotMatch(error.message, new RegExp(secret));
      assert.doesNotMatch(JSON.stringify({ code: (error as OutputScanError).code }), new RegExp(secret));
      return true;
    },
  );
});

test("PR-1: output keys sanitize tenant filenames", () => {
  assert.equal(outputStorageKey(job, output("../../etc/passwd"), 0), "output/user-1/job-1/0-.._.._etc_passwd", "path separators are neutralised");
  assert.equal(outputStorageKey({ id: "job-2", requesterId: null }, output("x.pdf"), 3), "output/system/job-2/3-x.pdf");
});

test("PR-1: screenWorkerOutputs returns clean metadata without touching storage", async () => {
  const scans = await screenWorkerOutputs([output("a.pdf")], { scanner: scriptedScanner(["CLEAN"]) });
  assert.deepEqual(Object.keys(scans[0]).sort(), ["checksumSha256", "engine", "engineVersion", "index", "name", "signatureVersion"].sort());
  assert.match(scans[0].checksumSha256, /^[a-f0-9]{64}$/);
});
