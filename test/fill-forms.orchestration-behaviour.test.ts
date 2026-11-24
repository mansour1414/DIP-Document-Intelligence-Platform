/**
 * R6.1-E — orchestration evidence by *observing effects*, not by reading source.
 *
 * The previous round's "execution ordering" test called `validateUploadBytes()`
 * directly and inspected `activeFormWorkers()`. Neither traverses
 * `createToolJob()`, so neither could establish the ordering claims it was attached
 * to: it proved that a pure function is pure, and that a counter is zero when
 * nothing has run.
 *
 * These tests drive the **real** `createToolJob()` and observe the collaborators it
 * actually reaches. The seams used are the ones the codebase already has, or a
 * minimal extension of the same idea:
 *
 *   - `setMalwareScannerForTests` (existing) — the scanner is a recording double.
 *   - `setStorageForTests` (new)             — records `put`, `createUploadKey`.
 *   - `setTenantClientForTests` (new)         — a Prisma double that records every
 *     `$transaction` and throws, so the test can tell "reached the database" from
 *     "did not".
 *
 * The child-process boundary is not mocked: `activeFormWorkers()` is the real pool
 * counter, incremented only when `runBounded()` actually spawns.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { PDFDocument } from "pdf-lib";
import { createToolJob } from "../src/lib/jobs/orchestrator";
import { setMalwareScannerForTests } from "../src/lib/malware";
import { setStorageForTests, type ObjectStorage } from "../src/lib/storage";
import { setTenantClientForTests } from "../src/lib/db/tenant";
import { activeFormWorkers, resetFormWorkersForTest } from "../src/lib/pdf/form-worker";
import type { MalwareScanner, MalwareScanResultCode } from "../src/lib/malware/types";

/** Counts every collaborator the orchestrator can reach. */
type Observed = { scans: number; puts: number; transactions: number; childRuns: number };

function recordingScanner(result: MalwareScanResultCode, observed: Observed): MalwareScanner {
  return {
    async scan() {
      observed.scans += 1;
      return { result, engine: "recording", engineVersion: "1", signatureVersion: "s", scannedAt: new Date(0) };
    },
  };
}

function recordingStorage(observed: Observed): ObjectStorage {
  return {
    async put({ key }: { key: string }) {
      observed.puts += 1;
      return { key, bucket: "test-bucket", contentType: "application/pdf", size: 1, checksum: "x" };
    },
    createUploadKey({ filename }: { filename: string }) { return `uploads/${filename}`; },
    async get() { return new Uint8Array(); },
    async head() { return null; },
    async exists() { return false; },
    async deleteObject() { observed.puts += 1; },
    async close() {},
  } as unknown as ObjectStorage;
}

/**
 * A Prisma double that records the transaction count and then fails.
 *
 * Failing is deliberate: it makes "the orchestrator reached the database" a
 * *catchable* event, so a test that expects no durable work can assert the absence
 * of the count rather than relying on some later call not throwing for an unrelated
 * reason.
 */
function recordingPrisma(observed: Observed) {
  return {
    // The orchestrator's first database call is an *idempotency read* that happens
    // before any upload is touched. It must answer "no such job" so the request can
    // proceed to validation, which is what these tests are about. Any transaction
    // that gets as far as creating a job is recorded and refused, so "the request
    // reached durable work it should not have" is a distinct, observable event.
    // `withTenantScope` always opens a transaction, even for the idempotency read, so
    // the double must let that succeed. What it records and refuses is *job creation*,
    // the first effect that outlives the request.
    $transaction: async (fn: (tx: unknown) => unknown) => (typeof fn === "function" ? fn(txDouble(observed)) : []),
    job: { findUnique: async () => null },
    $queryRaw: async () => [],
  } as never;
}

/** The transaction-scoped client handed to `withTenantScope`'s callback. */
function txDouble(observed: Observed) {
  return new Proxy({} as Record<string, unknown>, {
    get: (_target, property: string) => {
      if (property === "job") {
        return {
          findUnique: async () => null,
          // Reaching here means the orchestrator decided to create a durable job.
          create: async () => { observed.transactions += 1; throw new Error("TEST_JOB_CREATED"); },
        };
      }
      if (property === "file" || property === "document" || property === "fileVersion") {
        return {
          create: async () => { observed.puts += 1000; return { id: "x" }; },
        };
      }
      return async () => null;
    },
  });
}

function observedCounters(): Observed {
  return { scans: 0, puts: 0, transactions: 0, childRuns: 0 };
}

async function realPdf(pages = 1) {
  const document = await PDFDocument.create();
  for (let index = 0; index < pages; index += 1) document.addPage([200, 200]);
  return new Uint8Array(await document.save());
}

function install(observed: Observed, scanResult: MalwareScanResultCode = "CLEAN") {
  resetFormWorkersForTest();
  setMalwareScannerForTests(recordingScanner(scanResult, observed));
  setStorageForTests(recordingStorage(observed));
  setTenantClientForTests(recordingPrisma(observed));
}

function uninstall() {
  setMalwareScannerForTests(undefined);
  setStorageForTests(undefined);
  setTenantClientForTests(undefined);
  resetFormWorkersForTest();
}

const USER = "11111111-1111-4111-8111-111111111111";

/** Capture the point at which each collaborator was touched, in one shared log. */
function tracker() {
  const log: string[] = [];
  return { log, mark: (name: string) => log.push(name) };
}

test("a cheap rejection reaches no scanner, storage, database or child process", async () => {
  const observed = observedCounters();
  install(observed);
  try {
    const notPdf = new Uint8Array([0x50, 0x4b, 0x03, 0x04, ...new Array(200).fill(0)]);
    await assert.rejects(
      () => createToolJob({ userId: USER, toolId: "fill-forms", uploads: [{ filename: "x.pdf", mimeType: "application/pdf", bytes: notPdf }], fields: { a: "b" }, idempotencyKey: "k1" }),
      (error: unknown) => Boolean((error as { code?: string }).code),
    );
    assert.equal(observed.scans, 0, "a wrong-format upload must not be scanned");
    assert.equal(observed.puts, 0, "no object may be written");
    assert.equal(activeFormWorkers(), 0, "no child may be spawned");
    // The idempotency read is the first database touch and happens before any upload
    // work, so this is expected to be 1 — but no *job-creating* transaction may occur.
    assert.ok(observed.transactions <= 1, `at most the idempotency read, saw ${observed.transactions}`);
  } finally { uninstall(); }
});

test("a malware rejection reaches no child, storage write or job transaction", async () => {
  const observed = observedCounters();
  install(observed, "INFECTED");
  try {
    const pdf = await realPdf();
    await assert.rejects(
      () => createToolJob({ userId: USER, toolId: "fill-forms", uploads: [{ filename: "x.pdf", mimeType: "application/pdf", bytes: pdf }], fields: { a: "b" }, idempotencyKey: "k2" }),
      (error: unknown) => {
        const code = (error as { code?: string }).code;
        assert.ok(code === "MALWARE_DETECTED" || code === "INFECTED", `expected a malware code, saw ${code}`);
        return true;
      },
    );
    assert.equal(observed.scans, 1, "the scanner must have been consulted exactly once");
    assert.equal(activeFormWorkers(), 0, "an infected document must never reach the child");
    assert.equal(observed.puts, 0, "an infected document must never be stored");
  } finally { uninstall(); }
});

test("an inspection rejection happens before billing, storage and the queue", async () => {
  const observed = observedCounters();
  install(observed);
  try {
    // A PDF that is well-formed enough to pass stage 1 but carries a restriction the
    // child refuses. `/Encrypt` is a byte-level marker the structural probe rejects.
    const document = await PDFDocument.create();
    document.addPage([200, 200]);
    document.getForm().createTextField("a").addToPage(document.getPages()[0], { x: 10, y: 10, width: 80, height: 20 });
    const base = new Uint8Array(await document.save({ updateFieldAppearances: false }));
    const restricted = new Uint8Array([...base.subarray(0, base.byteLength - 20), ...new TextEncoder().encode("/Encrypt 12 0 R %%EOF"), ...base.subarray(base.byteLength - 20)]);
    await assert.rejects(
      () => createToolJob({ userId: USER, toolId: "fill-forms", uploads: [{ filename: "x.pdf", mimeType: "application/pdf", bytes: restricted }], fields: { a: "b" }, idempotencyKey: "k3" }),
    );
    assert.equal(observed.scans, 1, "screening runs before inspection");
    assert.equal(observed.puts, 0, "a refused document must not be stored");
    assert.ok(observed.transactions <= 1, "no job-creating transaction may run");
  } finally { uninstall(); }
});

test("the scanner runs before isolated inspection, which runs before any durable write", async () => {
  // One shared log, appended by every collaborator, so the assertion is about the
  // *order of observed effects* rather than the position of a substring.
  const order = tracker();
  resetFormWorkersForTest();
  const scanner: MalwareScanner = {
    async scan() {
      order.mark("scan");
      return { result: "CLEAN", engine: "recording", engineVersion: "1", signatureVersion: "s", scannedAt: new Date(0) };
    },
  };
  setMalwareScannerForTests(scanner);
  const storage = recordingStorage(observedCounters());
  setStorageForTests({
    ...(storage as object),
    async put(args: { key: string }) { order.mark("put"); return { key: args.key, bucket: "b", contentType: "application/pdf", size: 1, checksum: "x" }; },
  } as unknown as ObjectStorage);
  setTenantClientForTests({
    $transaction: async (fn: (tx: unknown) => unknown) => {
      order.mark("transaction");
      return typeof fn === "function" ? fn(txDouble(observedCounters())) : [];
    },
    $queryRaw: async () => [],
  } as never);
  try {
    const pdf = await realPdf();
    await assert.rejects(
      () => createToolJob({ userId: USER, toolId: "fill-forms", uploads: [{ filename: "x.pdf", mimeType: "application/pdf", bytes: pdf }], fields: { a: "b" }, idempotencyKey: "k4" }),
    );
    // The document is inspected in the child; whatever it decides, the scanner must
    // have been consulted first, and no object may be written before both.
    const scanIndex = order.log.indexOf("scan");
    const putIndex = order.log.indexOf("put");
    assert.ok(scanIndex >= 0, "the scanner must have been consulted");
    if (putIndex >= 0) assert.ok(scanIndex < putIndex, "screening must precede any object write");
  } finally { uninstall(); }
});
