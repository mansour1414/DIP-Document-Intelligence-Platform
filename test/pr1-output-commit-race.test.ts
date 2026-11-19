/**
 * PR-1a concurrency coverage for `processDocumentJob()`.
 *
 * These cases execute the real pipeline (real output generation, real screening
 * module, real storage-adapter calls) against a **serialised in-memory
 * transaction model** instead of Postgres. They exist to prove the pipeline's own
 * decision logic — the compare-and-set commit, the superseded-attempt return, the
 * suppressed failure and the ownership-checked cleanup — runs as written.
 *
 * The database semantics they rely on (a second `updateMany ... WHERE
 * output_file_id IS NULL` matching no row once the first attempt commits) are
 * proven against real PostgreSQL with RLS, real MinIO and real clamd by
 * `pr1-output-screening.integration.test.ts`, which executes in the CI
 * "Integration / Processing" job.
 */
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { PDFDocument } from "pdf-lib";
import type { PrismaClient } from "@prisma/client";
import type { MalwareScanner } from "../src/lib/malware";
import type { ObjectStorage, StoredObject } from "../src/lib/storage";

/**
 * The pipeline module imports the Prisma client singleton, which only exists
 * after `prisma generate`. CI generates it, so the cases below execute there; in
 * an environment without it they report as skipped instead of failing the file.
 */
async function loadPipeline(client: { skip: (message?: string) => void }) {
  try { return await import("../src/lib/jobs/document-pipeline"); }
  catch { client.skip("the generated Prisma client is not available in this environment"); return undefined; }
}

// --------------------------------------------------------------- fake database

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

/** Prisma treats `undefined` as "leave untouched". */
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
      const row = { id: randomUUID(), documentId: (data.document as { connect?: { id: string } } | undefined)?.connect?.id ?? null, originalName: data.originalName, mimeType: data.mimeType, size: data.size, storageKey: data.storageKey, checksum: data.checksum };
      this.state.files.push(row);
      return { ...row };
    },
  };
  document = {
    create: async ({ data }: { data: Row }) => {
      const row = { id: randomUUID(), userId: data.userId, title: data.title };
      this.state.documents.push(row);
      return { ...row };
    },
  };
  fileVersion = { create: async ({ data }: { data: Row }) => { this.state.versions.push({ ...data }); return { ...data }; } };
  toolExecution = { create: async ({ data }: { data: Row }) => { this.state.executions.push({ ...data }); return { ...data }; } };
}

/** Transactions are serialised, so a rollback can restore the shared state in place. */
class FakeDb {
  state: State = { jobs: new Map(), steps: new Map(), files: [], documents: [], versions: [], executions: [] };
  private queue: Promise<unknown> = Promise.resolve();
  $transaction = <T>(operation: (tx: Tx) => Promise<T>): Promise<T> => {
    const run = this.queue.then(async () => {
      const snapshot = structuredClone(this.state);
      try {
        return await operation(new Tx(this.state));
      } catch (error) {
        const restored = structuredClone(snapshot);
        this.state.jobs = restored.jobs;
        this.state.steps = restored.steps;
        this.state.files = restored.files;
        this.state.documents = restored.documents;
        this.state.versions = restored.versions;
        this.state.executions = restored.executions;
        throw error;
      }
    });
    this.queue = run.then(() => undefined, () => undefined);
    return run;
  };
}

/** Makes the commit update fail inside its transaction, exactly where it would publish. */
function failingCommitClient(db: FakeDb) {
  return {
    $transaction: <T>(operation: (tx: Tx) => Promise<T>) => db.$transaction((tx) => operation(new Proxy(tx, {
      get(target, property, receiver) {
        const value = Reflect.get(target, property, receiver);
        if (property !== "job") return value;
        return new Proxy(value as object, {
          get(model, method, modelReceiver) {
            const call = Reflect.get(model, method, modelReceiver) as unknown;
            if (method !== "updateMany" || typeof call !== "function") return call;
            return (args: { data?: { status?: string } }) => {
              if (args?.data?.status === "SUCCEEDED") throw Object.assign(new Error("simulated metadata write failure"), { code: "COMMIT_FAILED" });
              return (call as (input: unknown) => Promise<unknown>)(args);
            };
          },
        });
      },
    }) as Tx)),
  } as unknown as PrismaClient;
}

/** Applies the commit transaction and only then reports a transport fault. */
function commitAcknowledgementLost(db: FakeDb) {
  const committed = () => [...db.state.jobs.values()].some((job) => Boolean(job.outputFileId));
  return {
    $transaction: async <T>(operation: (tx: Tx) => Promise<T>) => {
      const before = committed();
      const result = await db.$transaction(operation);
      if (!before && committed()) throw Object.assign(new Error("connection lost after commit"), { code: "COMMIT_ACK_LOST" });
      return result;
    },
  } as unknown as PrismaClient;
}

// ------------------------------------------------------------------- fixtures

function recordingStorage(options: { failPutAt?: number; gate?: () => Promise<void> } = {}) {
  const log: string[] = [];
  const objects = new Map<string, Uint8Array>();
  let puts = 0;
  const storage: ObjectStorage = {
    createUploadKey: ({ filename }) => `input/${filename}`,
    async put({ key, bytes, contentType, checksum }): Promise<StoredObject> {
      if (options.gate) await options.gate();
      const position = puts++;
      if (options.failPutAt === position) throw Object.assign(new Error("simulated storage write failure"), { code: "STORAGE_FAILURE" });
      log.push(`put:${key}`);
      objects.set(key, bytes);
      return { key, bucket: "dip-test", contentType, size: bytes.byteLength, checksum };
    },
    async get(key) { const bytes = objects.get(key); if (!bytes) throw new Error("NOT_FOUND"); return bytes; },
    async head(key) { const bytes = objects.get(key); return bytes ? { key, bucket: "dip-test", contentType: "application/pdf", size: bytes.byteLength } : undefined; },
    async exists(key) { return objects.has(key); },
    async deleteObject(key) { log.push(`delete:${key}`); objects.delete(key); },
    async close() {},
  };
  const puts_ = () => log.filter((entry) => entry.startsWith("put:")).map((entry) => entry.slice(4));
  const deletes = () => log.filter((entry) => entry.startsWith("delete:")).map((entry) => entry.slice(7));
  return { storage, objects, puts: puts_, deletes };
}

const cleanScanner: MalwareScanner = {
  async scan() { return { result: "CLEAN", engine: "stub", engineVersion: "1", signatureVersion: "sig", scannedAt: new Date(0) }; },
};

const pdfBytes = async (pages = 1) => {
  const document = await PDFDocument.create();
  for (let index = 0; index < pages; index += 1) document.addPage();
  return new Uint8Array(await document.save());
};

async function fixture() {
  const db = new FakeDb();
  const inputs = new Map<string, Uint8Array>();
  const user = randomUUID(); const jobId = randomUUID(); const inputIds: string[] = [];
  for (let index = 0; index < 2; index += 1) {
    const id = randomUUID();
    const key = `input/${user}/${id}.pdf`;
    const bytes = await pdfBytes();
    inputs.set(key, bytes);
    db.state.files.push({ id, documentId: randomUUID(), storageKey: key, mimeType: "application/pdf", originalName: `in-${index}.pdf`, size: BigInt(bytes.byteLength), pageCount: 1 });
    inputIds.push(id);
  }
  db.state.jobs.set(jobId, { id: jobId, toolId: "merge-pdf", status: "QUEUED", requesterId: user, organizationId: null, correlationId: randomUUID(), params: { inputFileIds: inputIds, options: {} }, startedAt: null, outputFileId: null, errorCode: null, result: null, completedAt: null });
  const message = { jobId, toolId: "", idempotencyKey: `pr1-${jobId}`, correlationId: randomUUID(), userId: user };
  const attemptStorage = (options: { failPutAt?: number; gate?: () => Promise<void> } = {}) => {
    const recording = recordingStorage(options);
    for (const [key, bytes] of inputs) recording.objects.set(key, bytes);
    return recording;
  };
  return { db, jobId, user, inputIds, message, attemptStorage };
}

const barrier = (parties: number) => {
  let arrived = 0;
  let release = () => {};
  const gate = new Promise<void>((resolve) => { release = resolve; });
  return async () => { arrived += 1; if (arrived >= parties) release(); await gate; };
};

const outputFiles = (db: FakeDb, inputIds: string[]) => db.state.files.filter((row) => !inputIds.includes(String(row.id)));
const asClient = (value: unknown) => value as PrismaClient;

// ---------------------------------------------------------------------- cases

test("PR-1a: two concurrent attempts of one job publish exactly one output", async (t) => {
  const pipeline = await loadPipeline(t);
  if (!pipeline) return;
  const { processDocumentJob } = pipeline;
  const { db, jobId, inputIds, message, attemptStorage } = await fixture();
  const gate = barrier(2);
  const a = attemptStorage({ gate });
  const b = attemptStorage({ gate });

  const results = await Promise.allSettled([
    processDocumentJob(message, { storage: a.storage, scanner: cleanScanner, client: asClient(db), attemptId: "attempt-a" }),
    processDocumentJob(message, { storage: b.storage, scanner: cleanScanner, client: asClient(db), attemptId: "attempt-b" }),
  ]);

  assert.deepEqual(results.map((result) => result.status), ["fulfilled", "fulfilled"], "the losing attempt returns instead of throwing");
  assert.equal(a.puts().length, 1, "both attempts reached the write, so the race really happened");
  assert.equal(b.puts().length, 1);
  assert.notEqual(a.puts()[0], b.puts()[0], "each attempt owns a distinct key");

  const job = db.state.jobs.get(jobId)!;
  assert.equal(job.status, "SUCCEEDED");
  assert.equal(job.errorCode, null, "a losing attempt never stamps a failure code on a committed job");
  assert.ok(job.outputFileId);
  const outputs = outputFiles(db, inputIds);
  assert.equal(outputs.length, 1, "exactly one output file row exists");
  assert.equal(db.state.documents.filter((row) => row.userId === db.state.jobs.get(jobId)!.requesterId).length, 1, "exactly one output document exists");
  assert.equal(db.state.executions.length, 1, "exactly one ToolExecution exists");

  const committed = String(outputs[0].storageKey);
  const winner = committed === a.puts()[0] ? a : b;
  const loser = committed === a.puts()[0] ? b : a;
  assert.ok(await winner.storage.head(committed), "the committed object exists");
  assert.equal(loser.puts().length, 1);
  assert.deepEqual(loser.deletes(), loser.puts(), "the losing attempt deleted its own object");
  assert.equal(await loser.storage.head(loser.puts()[0]), undefined, "the losing attempt's object is gone");
  assert.deepEqual(winner.deletes(), [], "the winner deleted nothing");
});

test("PR-1a: a failed commit rolls back its metadata, removes its own object and leaves a clean retry", async (t) => {
  const pipeline = await loadPipeline(t);
  if (!pipeline) return;
  const { processDocumentJob } = pipeline;
  const { db, jobId, inputIds, message, attemptStorage } = await fixture();
  const failing = attemptStorage();

  await assert.rejects(
    () => processDocumentJob(message, { storage: failing.storage, scanner: cleanScanner, client: asClient(failingCommitClient(db)), attemptId: "attempt-fail" }),
    (error: unknown) => (error as { code?: string }).code === "COMMIT_FAILED",
  );
  assert.equal(db.state.jobs.get(jobId)!.status, "FAILED");
  assert.deepEqual(outputFiles(db, inputIds), [], "the rolled-back transaction created no file rows");
  assert.equal(db.state.executions.length, 0, "no ToolExecution survived the rollback");
  assert.equal(failing.puts().length, 1);
  assert.deepEqual(failing.deletes(), failing.puts(), "the orphaned object is deleted");

  const retry = attemptStorage();
  await processDocumentJob(message, { storage: retry.storage, scanner: cleanScanner, client: asClient(db), attemptId: "attempt-retry" });
  assert.equal(db.state.jobs.get(jobId)!.status, "SUCCEEDED");
  assert.equal(outputFiles(db, inputIds).length, 1, "the retry committed exactly one output file");
  assert.equal(db.state.executions.length, 1, "only the retry committed a ToolExecution");
});

test("PR-1a: a failing duplicate attempt cannot fail or deface a job another attempt commits", async (t) => {
  const pipeline = await loadPipeline(t);
  if (!pipeline) return;
  const { processDocumentJob } = pipeline;
  const { db, jobId, inputIds, message, attemptStorage } = await fixture();
  const broken = attemptStorage({ failPutAt: 0 });
  const good = attemptStorage();

  const results = await Promise.allSettled([
    processDocumentJob(message, { storage: broken.storage, scanner: cleanScanner, client: asClient(db), attemptId: "attempt-broken" }),
    processDocumentJob(message, { storage: good.storage, scanner: cleanScanner, client: asClient(db), attemptId: "attempt-good" }),
  ]);

  const job = db.state.jobs.get(jobId)!;
  assert.equal(results.some((result) => result.status === "rejected"), true, "the storage fault still reaches the queue");
  assert.equal(job.status, "SUCCEEDED", "the committed attempt owns the terminal state");
  assert.equal(job.errorCode, null, "a suppressed failure cannot stamp a committed job");
  assert.equal(outputFiles(db, inputIds).length, 1);
  assert.match(String(outputFiles(db, inputIds)[0].storageKey), /attempt-good/, "the healthy attempt's object is the committed one");
  assert.ok(await good.storage.head(good.puts()[0]), "the committed object is untouched");
});

test("PR-1a: a commit that succeeds but loses its acknowledgement still deletes nothing", async (t) => {
  const pipeline = await loadPipeline(t);
  if (!pipeline) return;
  const { processDocumentJob } = pipeline;
  const { db, jobId, inputIds, message, attemptStorage } = await fixture();
  const attempt = attemptStorage();

  await assert.rejects(
    () => processDocumentJob(message, { storage: attempt.storage, scanner: cleanScanner, client: asClient(commitAcknowledgementLost(db)), attemptId: "attempt-ack-lost" }),
    (error: unknown) => (error as { code?: string }).code === "COMMIT_ACK_LOST",
  );

  const job = db.state.jobs.get(jobId)!;
  assert.equal(job.status, "SUCCEEDED", "the committed state is never overwritten with FAILED");
  assert.ok(job.outputFileId);
  assert.equal(outputFiles(db, inputIds).length, 1);
  assert.deepEqual(attempt.deletes(), [], "a referenced object is never deleted");
  assert.ok(await attempt.storage.head(String(outputFiles(db, inputIds)[0].storageKey)), "the committed output survives the lost acknowledgement");
});
