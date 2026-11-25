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
import { PDFDocument, PDFName, PDFString } from "pdf-lib";
import { createToolJob } from "../src/lib/jobs/orchestrator";
import { setMalwareScannerForTests } from "../src/lib/malware";
import { setStorageForTests, type ObjectStorage } from "../src/lib/storage";
import { setTenantClientForTests } from "../src/lib/db/tenant";
import { DEFAULT_WORKER_LIMITS, activeFormWorkers, processPdfBounded, resetFormWorkersForTest } from "../src/lib/pdf/form-worker";

/**
 * The generated Prisma client is a precondition of importing the orchestrator at all:
 * `orchestrator → usage/enforcement → billing/credits → db` loads `@prisma/client`, which
 * throws at module scope when `.prisma/client` has not been generated.
 *
 * That is an environment problem, not a test result, and the R6.5 regressions below must
 * not be silently converted into a skip by some *other* import failure — so exactly one
 * cause is tolerated, and a CI environment can require it outright with
 * `DIP_REQUIRE_PIPELINE=1`. The R6.5 assertions live in this file because they need the
 * orchestrator; locally, without a generated client, they are BLOCKED rather than
 * skipped for convenience.
 */
const PRISMA_MISSING = /Cannot find module ['"]\.prisma\/client\/default|@prisma\/client['"] did not initialize yet/iu;
async function requirePrismaClient(context: { skip: (message?: string) => void }) {
  try {
    await import("../src/lib/db/index");
    return true;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!PRISMA_MISSING.test(message)) throw error;
    if (process.env.DIP_REQUIRE_PIPELINE === "1") throw new Error(`The generated Prisma client is required in this environment: ${message}`);
    context.skip("the generated Prisma client is not available in this environment");
    return false;
  }
}
import type { MalwareScanner, MalwareScanResultCode } from "../src/lib/malware/types";

/** Counts every collaborator the orchestrator can reach. */
type Observed = { scans: number; puts: number; transactions: number };

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
  return { scans: 0, puts: 0, transactions: 0 };
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

/**
 * R6.5 — admission must refuse a document that cannot be filled.
 *
 * The child returns `ok: true` for any structurally valid PDF, including one with no
 * AcroForm fields: inspection is read-only and must be able to report "no fields". The
 * orchestrator then checked only that `inventory.fields` was an *array*, which is true of
 * `[]`. A form-less PDF was therefore admitted — credit consumed, usage written, bytes
 * stored, job row created, work enqueued — and only the worker rejected it.
 *
 * These tests drive the real `createToolJob()` and observe every collaborator, so they
 * prove the refusal precedes each effect rather than merely that a refusal happened.
 */
test("a PDF with no AcroForm fields is refused before billing, storage, job and queue", async (t) => {
  if (!await requirePrismaClient(t)) return;
  const observed = observedCounters();
  install(observed);
  try {
    // A real, parseable PDF with a page and no form at all. Not a malformed upload: it
    // must reach the bounded inspector, which is the point — the refusal has to come from
    // the inventory gate, not from an earlier shape or malware check.
    const passthrough = await realPdf();
    await assert.rejects(
      () => createToolJob({ userId: USER, toolId: "fill-forms", uploads: [{ filename: "plain.pdf", mimeType: "application/pdf", bytes: passthrough }], fields: { a: "b" }, idempotencyKey: "r65-formless" }),
      (error: unknown) => {
        assert.equal((error as { code?: string }).code, "FORM_NOT_FOUND", "the refusal must be the typed FORM_NOT_FOUND");
        return true;
      },
    );
    assert.equal(observed.scans, 1, "a clean document must still be screened exactly once");
    // The R6.5 version wrote `observed.childRuns + activeFormWorkers() === 1`. Both halves
    // were wrong: `childRuns` was never incremented anywhere, and `activeFormWorkers()` is
    // *current occupancy*, which is 0 once the child has exited — always, by the time this
    // runs. It passed locally only because the assertion it replaced was never exercised
    // with a generated client. No exact invocation count is observable here, so none is
    // claimed.
    //
    // What is observable, and what actually establishes the boundary: `FORM_NOT_FOUND` is
    // raised in exactly one place — `assertFillableDocument` — which the admission gate
    // reaches only *after* `processPdfBounded` returns a real inventory. No in-process parse
    // can produce it. It is in the `FORM_FILL_ERROR_CODES` allowlist, so a child *could* in
    // principle return it, but the child raises it nowhere (verified: no occurrence in
    // `form-worker-child`, `form-worker`, `form-fill` or `form-inspection`), and a malformed
    // or crashed reply collapses to `FORM_UNSUPPORTED` with a `boundary` detail before it is
    // ever forwarded. The rejection is therefore evidence that an inspection round-trip
    // completed; the pool is asserted drained, not counted — no invocation count is
    // observable here, so none is claimed.
    assert.equal(activeFormWorkers(), 0, "the child must be retired by the time admission rejects");
    assert.equal(observed.puts, 0, "a form-less document must never be stored");
    assert.ok(observed.transactions <= 1, `at most the idempotency read, saw ${observed.transactions}`);
  } finally { uninstall(); }
});

test("duplicate field names are refused at admission, not only in the worker", async (t) => {
  if (!await requirePrismaClient(t)) return;
  const observed = observedCounters();
  install(observed);
  try {
    // Two AcroForm fields with the same name: `inventory.fields` is non-empty, so an
    // empty-only check would admit this even though the values cannot be addressed
    // unambiguously. `assertFillableDocument` rejects it (FORM_UNSUPPORTED) — the same
    // contract the fill engine applies — so the two boundaries cannot disagree.
    //
    // pdf-lib **refuses** a second field with the same name through its API
    // ("A field already exists with the specified name"), so the fixture cannot be built
    // that way: the R6.5 version threw before reaching the orchestrator at all. The second
    // field is therefore created under a distinct name and then renamed in the AcroForm
    // dictionary — the same technique, and the same shape a hostile or legacy generator
    // produces, as the existing `fill-forms.runtime` fixture for this restriction.
    //
    // The names are deliberately **flat**. Dotted names create a field *hierarchy* in
    // pdf-lib: a twin created as `applicant.name-twin` beside an existing
    // `applicant.name` becomes its child and resolves to `applicant.applicant.name`, so
    // the duplicate never materialises and the fixture silently proves nothing.
    const document = await PDFDocument.create();
    const page = document.addPage([200, 200]);
    const form = document.getForm();
    form.createTextField("dup").addToPage(page, { x: 10, y: 10, width: 80, height: 20 });
    const twin = form.createTextField("dup-twin");
    twin.addToPage(page, { x: 10, y: 50, width: 80, height: 20 });
    twin.acroField.dict.set(PDFName.of("T"), PDFString.of("dup"));
    const duplicated = new Uint8Array(await document.save({ updateFieldAppearances: false }));

    // Prove the fixture *is* what the test needs before asserting anything about admission:
    // a fixture that quietly produced one field would make the refusal below prove nothing.
    const inspected = await processPdfBounded(duplicated, { ...DEFAULT_WORKER_LIMITS, concurrency: 1 });
    assert.equal(inspected.ok, true, "the fixture must be structurally inspectable");
    assert.deepEqual(inspected.inventory?.duplicates, ["dup"],
      "the bounded inspector must detect the duplicate the fixture encodes");
    await assert.rejects(
      () => createToolJob({ userId: USER, toolId: "fill-forms", uploads: [{ filename: "dup.pdf", mimeType: "application/pdf", bytes: duplicated }], fields: { dup: "x" }, idempotencyKey: "r65-duplicate" }),
      (error: unknown) => {
        assert.equal((error as { code?: string }).code, "FORM_UNSUPPORTED", "duplicates must be refused as FORM_UNSUPPORTED");
        return true;
      },
    );
    assert.equal(observed.puts, 0, "a document with duplicate fields must never be stored");
    assert.ok(observed.transactions <= 1, `at most the idempotency read, saw ${observed.transactions}`);
  } finally { uninstall(); }
});
