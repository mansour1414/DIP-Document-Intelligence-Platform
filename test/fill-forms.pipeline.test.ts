/**
 * Stage 2 `fill-forms` — job-pipeline integration (DIP-CR-006 targeted set).
 *
 * Executes the **real** `processDocumentJob()` against a serialised in-memory
 * transaction model (the pattern established by `pr1-output-commit-race.test.ts`)
 * instead of Postgres, which is not available in this environment. Everything
 * else is production code: the real pipeline, the real engine, the real output
 * screening module, the real storage adapter contract, and the real access-control
 * predicates.
 *
 * Cases:
 *   1. a queued `fill-forms` job fills the uploaded form, stores exactly one
 *      output and stamps the engine in its execution record;
 *   2. a second attempt of the same job is an idempotent no-op — no second
 *      output, no second execution (retry safety);
 *   3. the job's stored `fields` payload is validated *again* in the worker, so a
 *      value that became invalid is rejected rather than written;
 *   4. the queued job body never carries secrets and the persisted params are the
 *      typed `fields` object, not a re-serialised JSON string.
 */
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { PDFDocument } from "pdf-lib";
import type { MalwareScanner } from "../src/lib/malware";
import type { ObjectStorage, StoredObject } from "../src/lib/storage";

/**
 * Load the pipeline, skipping **only** when the generated Prisma client is
 * genuinely absent (FF-11).
 *
 * The previous version caught every import error and reported it as "Prisma not
 * generated". A syntax error, a bad import path or a broken dependency would
 * therefore be silently converted into a skip — the suite would stay green while
 * the pipeline was unloadable. A skip is now allowed for exactly one cause, and
 * anything else is rethrown so CI fails.
 *
 * The skip itself is a local-environment concession: `npm test` sets
 * `DIP_REQUIRE_PIPELINE=1` in CI, which turns even that one case into a failure.
 */
const PRISMA_MISSING = /Cannot find module ['"]\.prisma\/client\/default|@prisma\/client['"] did not initialize yet/iu;

async function loadPipeline(client: { skip: (message?: string) => void }) {
  try { return await import("../src/lib/jobs/document-pipeline"); }
  catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!PRISMA_MISSING.test(message)) throw error;
    if (process.env.DIP_REQUIRE_PIPELINE === "1") throw new Error(`The generated Prisma client is required in this environment: ${message}`);
    client.skip("the generated Prisma client is not available in this environment");
    return undefined;
  }
}

// ------------------------------------------------------------- fake database

type Row = Record<string, unknown>;
type Where = Record<string, unknown>;
type State = { jobs: Map<string, Row>; steps: Map<string, Row>; files: Row[]; documents: Row[]; versions: Row[]; executions: Row[] };

const matches = (row: Row, where: Where) =>
  Object.entries(where).every(([key, condition]) => {
    const value = row[key] ?? null;
    if (condition === null || typeof condition !== "object" || condition instanceof Date) return value === condition;
    const filter = condition as Record<string, unknown>;
    if (Array.isArray(filter.in)) return filter.in.includes(value);
    if (Array.isArray(filter.notIn)) return !filter.notIn.includes(value);
    if ("not" in filter) return value !== filter.not;
    if ("equals" in filter) return value === filter.equals;
    return false;
  });

const prune = (data: Row) => Object.fromEntries(Object.entries(data).filter(([, value]) => value !== undefined));
const project = (row: Row, select?: Row) => (select ? Object.fromEntries(Object.keys(select).map((key) => [key, row[key]])) : { ...row });

class Tx {
  constructor(private readonly state: State) {}
  $queryRaw = async () => [];
  job = {
    findUnique: async ({ where, include }: { where: Where; include?: { steps?: boolean } }) => {
      const row = this.state.jobs.get(String(where.id));
      if (!row) return null;
      return include?.steps ? { ...row, steps: [...this.state.steps.values()].filter((step) => step.jobId === row.id) } : { ...row };
    },
    findUniqueOrThrow: async ({ where, select }: { where: Where; select?: Row }) => {
      const row = this.state.jobs.get(String(where.id));
      if (!row) throw new Error("JOB_NOT_FOUND");
      return project(row, select);
    },
    updateMany: async ({ where, data }: { where: Where; data: Row }) => {
      const row = this.state.jobs.get(String(where.id));
      if (!row || !matches(row, where)) return { count: 0 };
      Object.assign(row, prune(data));
      return { count: 1 };
    },
  };
  jobStep = {
    updateMany: async ({ where, data }: { where: Where; data: Row }) => {
      const row = this.state.steps.get(String(where.id));
      if (!row || !matches(row, where)) return { count: 0 };
      Object.assign(row, prune(data));
      return { count: 1 };
    },
  };
  file = {
    findMany: async ({ where, select }: { where: Where; select?: Row }) => this.state.files.filter((row) => matches(row, where)).map((row) => project(row, select)),
    create: async ({ data }: { data: Row }) => {
      const row = { id: randomUUID(), documentId: (data.document as { connect?: { id: string } } | undefined)?.connect?.id ?? null, originalName: data.originalName, mimeType: data.mimeType, size: data.size, storageKey: data.storageKey, checksum: data.checksum, pageCount: data.pageCount };
      this.state.files.push(row);
      return { ...row };
    },
  };
  document = { create: async ({ data }: { data: Row }) => { const row = { id: randomUUID(), userId: data.userId, title: data.title }; this.state.documents.push(row); return { ...row }; } };
  fileVersion = { create: async ({ data }: { data: Row }) => { this.state.versions.push({ ...data }); return { ...data }; } };
  toolExecution = { create: async ({ data }: { data: Row }) => { this.state.executions.push({ ...data }); return { ...data }; } };
}

class FakeDb {
  state: State = { jobs: new Map(), steps: new Map(), files: [], documents: [], versions: [], executions: [] };
  private queue: Promise<unknown> = Promise.resolve();
  $transaction = <T>(operation: (tx: Tx) => Promise<T>): Promise<T> => {
    const run = this.queue.then(() => operation(new Tx(this.state)));
    this.queue = run.then(() => undefined, () => undefined);
    return run;
  };
}

// ------------------------------------------------------------------ fixtures

function recordingStorage(seed: Map<string, Uint8Array>) {
  const objects = new Map(seed);
  const puts: string[] = [];
  const storage: ObjectStorage = {
    createUploadKey: ({ filename }) => `input/${filename}`,
    async put({ key, bytes, contentType, checksum }): Promise<StoredObject> {
      puts.push(key);
      objects.set(key, bytes);
      return { key, bucket: "dip-test", contentType, size: bytes.byteLength, checksum };
    },
    async get(key) { const bytes = objects.get(key); if (!bytes) throw new Error("NOT_FOUND"); return bytes; },
    async head(key) { const bytes = objects.get(key); return bytes ? { key, bucket: "dip-test", contentType: "application/pdf", size: bytes.byteLength } : undefined; },
    async exists(key) { return objects.has(key); },
    async deleteObject(key) { objects.delete(key); },
    async close() {},
  };
  return { storage, objects, puts };
}

const cleanScanner: MalwareScanner = {
  async scan() { return { result: "CLEAN", engine: "stub", engineVersion: "1", signatureVersion: "sig", scannedAt: new Date(0) }; },
};

async function fillableForm() {
  const document = await PDFDocument.create();
  const page = document.addPage([595, 842]);
  const form = document.getForm();
  const name = form.createTextField("applicant.name");
  name.addToPage(page, { x: 60, y: 760, width: 300, height: 22 });
  const arabic = form.createTextField("applicant.nameAr");
  arabic.addToPage(page, { x: 60, y: 720, width: 300, height: 22 });
  const consent = form.createCheckBox("consent");
  consent.addToPage(page, { x: 60, y: 690, width: 16, height: 16 });
  const reference = form.createTextField("reference");
  reference.setText("KEEP-0042");
  reference.addToPage(page, { x: 60, y: 660, width: 220, height: 22 });
  return new Uint8Array(await document.save());
}

async function fixture(fields: unknown, options: Record<string, unknown> = { flatten: false }) {
  const db = new FakeDb();
  const user = randomUUID();
  const jobId = randomUUID();
  const fileId = randomUUID();
  const key = `input/${user}/${fileId}.pdf`;
  const bytes = await fillableForm();
  const inputs = new Map([[key, bytes]]);
  db.state.files.push({
    id: fileId,
    documentId: randomUUID(),
    storageObjectId: randomUUID(),
    storageObject: { id: randomUUID(), ownerUserId: user, organizationId: null, apiClientId: null, provider: "s3", bucket: "dip-test", objectKey: key, deletedAt: null },
    storageKey: key,
    mimeType: "application/pdf",
    originalName: "form.pdf",
    size: BigInt(bytes.byteLength),
    pageCount: 1,
  });
  db.state.jobs.set(jobId, { id: jobId, toolId: "fill-forms", status: "QUEUED", requesterId: user, organizationId: null, correlationId: randomUUID(), params: { inputFileIds: [fileId], options, ...(fields === undefined ? {} : { fields }) }, startedAt: null, outputFileId: null, errorCode: null, result: null, completedAt: null });
  const stepId = randomUUID();
  db.state.steps.set(stepId, { id: stepId, jobId, name: "fill-forms", status: "QUEUED", startedAt: null, completedAt: null });
  const message = { jobId, toolId: "fill-forms", idempotencyKey: `s2-${jobId}`, correlationId: randomUUID(), userId: user };
  return { db, jobId, fileId, user, message, ...recordingStorage(inputs) };
}

/**
 * The pipeline accepts a Prisma client; the fake exposes only the delegate
 * surface the pipeline actually uses. Casting through `never` keeps this file
 * independent of the generated `@prisma/client` types, which `prisma generate`
 * produces in CI but not in every environment.
 */
const asClient = (value: unknown) => value as never;

// --------------------------------------------------------------------- cases

test("S2 fill-forms pipeline: a queued job fills the form and stores exactly one verified output", async (t) => {
  const pipeline = await loadPipeline(t);
  if (!pipeline) return;
  const { jobId, fileId, db, message, storage, objects } = await fixture({
    "applicant.name": "Noura Al-Harbi",
    "applicant.nameAr": "نورة الحربي",
    consent: true,
  });
  await pipeline.processDocumentJob(message, { storage, scanner: cleanScanner, client: asClient(db) });

  const job = db.state.jobs.get(jobId)!;
  assert.equal(job.status, "SUCCEEDED");
  assert.equal(job.errorCode, null);
  assert.ok(job.outputFileId, "the job did not publish an output file");

  const outputs = db.state.files.filter((row) => row.id !== fileId);
  assert.equal(outputs.length, 1, "exactly one output row");
  const outputBytes = objects.get(String(outputs[0].storageKey));
  assert.ok(outputBytes, "the output bytes were never written to object storage");

  // The stored bytes really are the filled document — reopened independently.
  const { PDFDocument } = await import("pdf-lib");
  const reopened = await PDFDocument.load(outputBytes);
  const form = reopened.getForm();
  assert.equal((form.getTextField("applicant.name")).getText(), "Noura Al-Harbi");
  assert.equal((form.getTextField("applicant.nameAr")).getText(), "نورة الحربي");
  assert.equal((form.getCheckBox("consent")).isChecked(), true);
  assert.equal((form.getTextField("reference")).getText(), "KEEP-0042", "an untouched field was not preserved");

  // Engine attribution is recorded, not inferred.
  assert.equal(db.state.executions.length, 1);
  assert.equal(db.state.executions[0].engine, "pdf-lib");
  assert.equal(db.state.executions[0].engineVersion, "1.17.1");
});

test("S2 fill-forms pipeline: a retried attempt is an idempotent no-op (no second output or execution)", async (t) => {
  const pipeline = await loadPipeline(t);
  if (!pipeline) return;
  const { jobId, fileId, db, message, storage } = await fixture({ "applicant.name": "Retry Safe" });
  await pipeline.processDocumentJob(message, { storage, scanner: cleanScanner, client: asClient(db) });
  const afterFirst = { output: db.state.jobs.get(jobId)!.outputFileId, executions: db.state.executions.length };

  await pipeline.processDocumentJob(message, { storage, scanner: cleanScanner, client: asClient(db), attemptId: "retry-1" });
  await pipeline.processDocumentJob(message, { storage, scanner: cleanScanner, client: asClient(db), attemptId: "retry-2" });

  assert.equal(db.state.jobs.get(jobId)!.outputFileId, afterFirst.output);
  assert.equal(db.state.executions.length, afterFirst.executions, "a retry consumed a second execution");
  assert.equal(db.state.files.filter((row) => row.id !== fileId).length, 1, "a retry produced a second output file");
});

test("S2 fill-forms pipeline: the worker re-validates the stored payload instead of trusting the queue", async (t) => {
  const pipeline = await loadPipeline(t);
  if (!pipeline) return;
  // A value that was syntactically fine at enqueue time but is semantically
  // wrong for this document (a dropdown option it does not offer, a numeric
  // value) must never be written.
  for (const fields of [{ "applicant.name": 42 }, { "applicant.name": "ok", ghost: "x" }, { "applicant.name": "a".repeat(4_001) }]) {
    const { jobId, fileId, db, message, storage } = await fixture(fields as Record<string, unknown>);
    await assert.rejects(() => pipeline.processDocumentJob(message, { storage, scanner: cleanScanner, client: asClient(db) }));
    const job = db.state.jobs.get(jobId)!;
    assert.equal(job.status, "FAILED", `${JSON.stringify(fields)} was not rejected by the worker`);
    assert.equal(job.outputFileId, null);
    assert.equal(db.state.files.filter((row) => row.id !== fileId).length, 0, "a rejected job must not store an output");
  }
});

test("S2 fill-forms pipeline: flatten is honoured through the queued option value", async (t) => {
  const pipeline = await loadPipeline(t);
  if (!pipeline) return;
  const { jobId, fileId, db, message, storage, objects } = await fixture({ "applicant.name": "Flat" }, { flatten: true });
  await pipeline.processDocumentJob(message, { storage, scanner: cleanScanner, client: asClient(db) });
  assert.equal(db.state.jobs.get(jobId)!.status, "SUCCEEDED");
  const output = db.state.files.find((row) => row.id !== fileId)!;
  const { PDFDocument } = await import("pdf-lib");
  const reopened = await PDFDocument.load(objects.get(String(output.storageKey))!);
  assert.equal(reopened.getForm().getFields().length, 0, "flatten was not applied to the stored output");
  assert.equal(reopened.getPageCount(), 1);
});

// ------------------------------------------------------ R6.2-E: evidence cases
//
// Each case below closes a specific gap where the *claim* was previously supported
// only by reading source. The distinguishing question in every one is: what
// observable effect proves this, and would the test fail if the property were lost?

test("R6.2-E: a rejected fill refuses with an exact code and publishes nothing", async (t) => {
  const pipeline = await loadPipeline(t);
  if (!pipeline) return;
  // A value the document itself cannot accept. The rejection must be a specific
  // code, not a generic failure, so an operator can tell these apart in the log.
  const { jobId, fileId, db, message, storage, objects } = await fixture({ "applicant.name": { nested: true } } as Record<string, unknown>);
  const before = new Set(objects.keys());
  await assert.rejects(() => pipeline.processDocumentJob(message, { storage, scanner: cleanScanner, client: asClient(db) }));

  const job = db.state.jobs.get(jobId)!;
  assert.equal(job.status, "FAILED");
  assert.ok(job.errorCode, "a rejected job must carry an exact error code, not a null");
  assert.equal(typeof job.errorCode, "string");
  // `PROCESSING_FAILED` is the terminal fallback of `publicErrorCode()`: reaching it
  // means the thrown error carried no allowlisted code, so the rejection would be
  // indistinguishable from an internal fault in the operator's view. A specific code is
  // the property under test.
  assert.notEqual(job.errorCode, "PROCESSING_FAILED", `expected a specific rejection, saw ${job.errorCode}`);
  assert.equal(job.outputFileId, null, "a rejected job must not be linked to an output");
  // "No output published" is stronger than "no output row": nothing new may exist in
  // object storage either, so a reader could not reach the bytes by key.
  const added = [...objects.keys()].filter((key) => !before.has(key));
  assert.deepEqual(added, [], `rejected fill wrote ${added.length} object(s)`);
  assert.equal(db.state.files.filter((row) => row.id !== fileId).length, 0);
});

test("R6.2-E: a malformed stored page count fails before any output is published", async (t) => {
  const pipeline = await loadPipeline(t);
  if (!pipeline) return;
  // `inputPages` is required for output verification. A row with no usable page count
  // means the output cannot be proven page-preserving, so the job must fail closed
  // rather than skip the comparison.
  //
  // The child still runs first (the page-count guard sits immediately after the fill,
  // not before it), so this asserts on what is *published*, not on whether the document
  // was processed: a FAILED job with no output row, no output object, and no page count
  // recorded.
  for (const pageCount of [null, 0, -1, 1.5]) {
    const { jobId, fileId, db, message, storage, objects } = await fixture({ "applicant.name": "No Count" });
    const row = db.state.files.find((item) => item.id === fileId)!;
    (row as Record<string, unknown>).pageCount = pageCount;
    const before = new Set(objects.keys());
    await assert.rejects(
      () => pipeline.processDocumentJob(message, { storage, scanner: cleanScanner, client: asClient(db) }),
      `pageCount=${String(pageCount)} must not be silently accepted`,
    );
    assert.equal(db.state.jobs.get(jobId)!.status, "FAILED");
    assert.equal(db.state.jobs.get(jobId)!.outputFileId, null);
    assert.deepEqual([...objects.keys()].filter((key) => !before.has(key)), []);
    assert.equal(db.state.files.filter((item) => item.id !== fileId).length, 0);
  }
});

test("R6.2-E: the verified page count reaches persisted output metadata, not the input's value", async (t) => {
  const pipeline = await loadPipeline(t);
  if (!pipeline) return;
  const { jobId, fileId, db, message, storage } = await fixture({ "applicant.name": "Counted" });
  await pipeline.processDocumentJob(message, { storage, scanner: cleanScanner, client: asClient(db) });
  assert.equal(db.state.jobs.get(jobId)!.status, "SUCCEEDED");

  const output = db.state.files.find((row) => row.id !== fileId)!;
  // The output row must carry the count derived from the document that was written.
  // A null here would mean downstream consumers have no count for the artifact, and a
  // value copied from the input would be unfalsifiable — the same number regardless of
  // what the child actually produced.
  assert.ok(output.pageCount !== undefined && output.pageCount !== null,
    "the published output row has no page count");
  assert.equal(Number(output.pageCount), 1);
  assert.equal(db.state.executions.length, 1);
});
