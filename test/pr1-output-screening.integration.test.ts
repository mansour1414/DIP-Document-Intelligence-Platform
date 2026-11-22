/**
 * PR-1 database + object-storage + clamd integration evidence.
 *
 * Runs the real `processDocumentJob()` pipeline (extracted from the BullMQ
 * worker so it can be exercised without Redis) against:
 *   - Postgres with the least-privilege runtime role (RLS enforced),
 *   - the real S3-compatible adapter (MinIO in CI), and
 *   - the real clamd scanner for the clean case.
 *
 * The CI "Integration / Processing" job provisions all of the above, so these
 * cases execute there. Locally they report as skipped (see the PR description).
 *
 * The PR-1a cases at the end are the concurrency and failure-recovery evidence:
 * two attempts of one job run against the same database row and bucket, and the
 * assertions are on what Postgres and MinIO actually committed.
 *
 * Injected scanners are used only where a real infection or outage cannot be
 * produced on demand; the storage adapter, database and RLS path are always real.
 */
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import type { ObjectStorage } from "../src/lib/storage";

const runtimeUrl = process.env.DIP_RLS_TEST_DATABASE_URL;
const ownerUrl = process.env.DIP_RLS_TEST_OWNER_URL;
const storageReady = ["STORAGE_ENDPOINT", "STORAGE_BUCKET", "STORAGE_ACCESS_KEY", "STORAGE_SECRET_KEY"].every((name) => Boolean(process.env[name]));
const scannerReady = Boolean(process.env.CLAMD_HOST);
const integrationTest = runtimeUrl && ownerUrl && storageReady && scannerReady ? test : test.skip;

type Fixture = { user: string; document: string; inputFiles: string[]; inputKeys: string[]; job: string };
type Spy = { puts: string[]; deletes: string[]; failPutAt?: number };

integrationTest("PR-1 (integration): generated outputs are screened before storage", { timeout: 240_000 }, async (t) => {
  const { PrismaPg } = await import("@prisma/adapter-pg");
  const { PrismaClient } = await import("@prisma/client");
  const pg = await import("pg");
  const { PDFDocument } = await import("pdf-lib");
  const { createS3Storage } = await import("../src/lib/storage");
  const { processDocumentJob } = await import("../src/lib/jobs/document-pipeline");
  const { getMalwareScanner } = await import("../src/lib/malware");
  const { OutputScanError } = await import("../src/lib/outputs/screening");

  const owner = new pg.default.Client({ connectionString: ownerUrl });
  const runtime = new PrismaClient({ adapter: new PrismaPg({ connectionString: runtimeUrl }), log: ["error"] });
  const bucket = createS3Storage();
  await owner.connect();

  const spyStorage = (spy: Spy): ObjectStorage => ({
    createUploadKey: (input) => bucket.createUploadKey(input),
    async put(input) {
      spy.puts.push(input.key);
      if (spy.failPutAt !== undefined && spy.puts.length - 1 === spy.failPutAt) throw Object.assign(new Error("simulated storage write failure"), { code: "STORAGE_FAILURE" });
      return bucket.put(input);
    },
    get: (key) => bucket.get(key),
    head: (key) => bucket.head(key),
    exists: (key) => bucket.exists(key),
    async deleteObject(key) { spy.deletes.push(key); return bucket.deleteObject(key); },
    close: () => bucket.close(),
  });

  const scannerReturning = (...codes: Array<"CLEAN" | "INFECTED" | "SCANNER_UNAVAILABLE" | "SCAN_ERROR">) => {
    let index = 0;
    const calls: number[] = [];
    return {
      calls,
      scanner: {
        async scan() {
          calls.push(index);
          const code = codes[Math.min(index, codes.length - 1)];
          index += 1;
          return { result: code, engine: "pr1-stub", engineVersion: "1", signatureVersion: "sig", scannedAt: new Date(0) };
        },
      },
    };
  };

  const pdfBytes = async (pages: number) => {
    const document = await PDFDocument.create();
    for (let index = 0; index < pages; index += 1) document.addPage();
    return new Uint8Array(await document.save());
  };

  /**
   * `merge-pdf` requires at least two inputs, so the fixture seeds one file per
   * requested input; `split-pdf` needs a single multi-page file instead.
   */
  const seed = async (toolId: string, pages: number, inputCount = 1): Promise<Fixture> => {
    const user = randomUUID(); const document = randomUUID(); const job = randomUUID();
    const inputFiles: string[] = []; const inputKeys: string[] = [];
    await owner.query(`INSERT INTO users (id,email,status,created_at,updated_at) VALUES ($1,$2,'ACTIVE',now(),now())`, [user, `pr1-${user}@example.invalid`]);
    await owner.query(`INSERT INTO documents (id,user_id,title,status,created_at,updated_at) VALUES ($1,$2,'PR-1 input','ACTIVE',now(),now())`, [document, user]);
    for (let index = 0; index < inputCount; index += 1) {
      const inputFile = randomUUID();
      const inputStorageObject = randomUUID();
      const inputBytes = await pdfBytes(pages);
      const inputKey = `input/${user}/${inputFile}-${index}.pdf`;
      const bucketName = process.env.STORAGE_BUCKET ?? "dip-test";
      await bucket.put({ key: inputKey, bytes: inputBytes, contentType: "application/pdf" });
      await owner.query(`INSERT INTO storage_objects (id,owner_user_id,provider,bucket,object_key,size,created_at) VALUES ($1,$2,'s3',$3,$4,$5,now())`, [inputStorageObject, user, bucketName, inputKey, inputBytes.byteLength]);
      await owner.query(`INSERT INTO files (id,document_id,storage_object_id,original_name,mime_type,size,storage_key,version,created_at) VALUES ($1,$2,$3,$4,'application/pdf',$5,$6,1,now())`, [inputFile, document, inputStorageObject, `in-${index}.pdf`, inputBytes.byteLength, inputKey]);
      inputFiles.push(inputFile); inputKeys.push(inputKey);
    }
    await owner.query(`INSERT INTO jobs (id,tool_id,idempotency_key,requester_id,status,params,correlation_id,created_at,updated_at) VALUES ($1,$2,$3,$4,'QUEUED',$5::jsonb,$6,now(),now())`, [job, toolId, `pr1-${job}`, user, JSON.stringify({ inputFileIds: inputFiles, options: {} }), randomUUID()]);
    return { user, document, inputFiles, inputKeys, job };
  };

  const cleanup = async (fixture: Fixture, extraKeys: string[] = []) => {
    await owner.query(`DELETE FROM tool_executions WHERE job_id = $1`, [fixture.job]);
    await owner.query(`DELETE FROM job_steps WHERE job_id = $1`, [fixture.job]);
    await owner.query(`DELETE FROM jobs WHERE id = $1`, [fixture.job]);
    await owner.query(`DELETE FROM file_versions WHERE file_id IN (SELECT id FROM files WHERE document_id IN (SELECT id FROM documents WHERE user_id = $1))`, [fixture.user]);
    await owner.query(`DELETE FROM files WHERE document_id IN (SELECT id FROM documents WHERE user_id = $1)`, [fixture.user]);
    await owner.query(`DELETE FROM documents WHERE user_id = $1`, [fixture.user]);
    await owner.query(`DELETE FROM storage_objects WHERE owner_user_id = $1`, [fixture.user]);
    await owner.query(`DELETE FROM users WHERE id = $1`, [fixture.user]);
    for (const key of [...fixture.inputKeys, ...extraKeys]) await bucket.deleteObject(key).catch(() => undefined);
  };

  const message = (fixture: Fixture) => ({ jobId: fixture.job, toolId: "", idempotencyKey: `pr1-${fixture.job}`, correlationId: randomUUID(), userId: fixture.user });
  const jobRow = async (id: string) => (await owner.query(`SELECT status, error_code, output_file_id FROM jobs WHERE id = $1`, [id])).rows[0];
  const outputRows = async (fixture: Fixture) => (await owner.query(`SELECT f.id, f.storage_key, f.checksum FROM files f JOIN documents d ON d.id = f.document_id WHERE d.user_id = $1 AND f.id <> ALL($2::uuid[])`, [fixture.user, fixture.inputFiles])).rows;
  /** Security events written by this run, scoped by time because `details` carries no job id. */
  const securityEventsSince = async (since: Date) => (await owner.query(`SELECT id, details FROM security_events WHERE created_at >= $1 AND details->>'source' = 'output' ORDER BY created_at ASC`, [since])).rows;
  const purgeSecurityEventsSince = async (since: Date) => { await owner.query(`DELETE FROM security_events WHERE created_at >= $1 AND details->>'source' = 'output'`, [since]); };
  const count = async (sql: string, parameters: unknown[]) => Number((await owner.query(sql, parameters)).rows[0].count);
  const outputFileCount = (fixture: Fixture) => count(`SELECT count(*) FROM files f JOIN documents d ON d.id = f.document_id WHERE d.user_id = $1 AND f.id <> ALL($2::uuid[])`, [fixture.user, fixture.inputFiles]);
  const documentCount = (fixture: Fixture) => count(`SELECT count(*) FROM documents WHERE user_id = $1`, [fixture.user]);
  const executionCount = (jobId: string) => count(`SELECT count(*) FROM tool_executions WHERE job_id = $1`, [jobId]);

  /**
   * A losing attempt must not simply be lucky. Both attempts are held inside
   * `storeWorkerOutputs()` until the other one arrives, so the commit race is
   * always exercised instead of occasionally resolving to an early idempotent skip.
   */
  const barrier = (parties: number, timeoutMs = 20_000) => {
    let arrived = 0;
    let release = () => {};
    const gate = new Promise<void>((resolve) => { release = resolve; });
    return async () => {
      arrived += 1;
      if (arrived >= parties) release();
      let timer: ReturnType<typeof setTimeout> | undefined;
      await Promise.race([gate, new Promise<void>((resolve) => { timer = setTimeout(resolve, timeoutMs); timer.unref?.(); })]);
      if (timer) clearTimeout(timer);
    };
  };

  const gatedStorage = (spy: Spy, gate: () => Promise<void>): ObjectStorage => {
    const storage = spyStorage(spy);
    const put = storage.put.bind(storage);
    return { ...storage, put: async (input) => { await gate(); return put(input); } };
  };

  /** Fails the metadata transaction exactly where it would publish the output. */
  const commitFailingClient = (): typeof runtime => ({
    $transaction: (operation: (transaction: unknown) => Promise<unknown>) => runtime.$transaction(async (transaction) => {
      const guarded = new Proxy(transaction as object, {
        get(target, property, receiver) {
          const value = Reflect.get(target, property, receiver);
          if (property !== "job" || !value) return typeof value === "function" ? value.bind(target) : value;
          return new Proxy(value as object, {
            get(model, method, modelReceiver) {
              const operation2 = Reflect.get(model, method, modelReceiver);
              if (method !== "updateMany" || typeof operation2 !== "function") return typeof operation2 === "function" ? operation2.bind(model) : operation2;
              return (args: { data?: { status?: string } }) => {
                if (args?.data?.status === "SUCCEEDED") throw Object.assign(new Error("simulated metadata commit failure"), { code: "SIMULATED_COMMIT_FAILURE" });
                return operation2.call(model, args);
              };
            },
          });
        },
      });
      return operation(guarded);
    }),
  } as unknown as typeof runtime);

  try {
    await t.test("clean output is scanned with real clamd, stored once and the job succeeds", async () => {
      const fixture = await seed("merge-pdf", 1, 2);
      const spy: Spy = { puts: [], deletes: [] };
      try {
        await processDocumentJob(message(fixture), { storage: spyStorage(spy), scanner: getMalwareScanner(), client: runtime });
        const row = await jobRow(fixture.job);
        assert.equal(row.status, "SUCCEEDED");
        assert.ok(row.output_file_id, "the job must reference its stored output");
        assert.equal(spy.puts.length, 1, "exactly one put for one generated output");
        assert.equal(spy.deletes.length, 0);
        const objects = await outputRows(fixture);
        assert.equal(objects.length, 1);
        assert.equal(objects[0].storage_key, spy.puts[0]);
        assert.match(objects[0].checksum, /^[A-Za-z0-9+/=]{40,}$/, "checksum is base64 sha256 as stored by the worker");
        assert.ok(await bucket.head(spy.puts[0]), "the output object exists in object storage");
        await cleanup(fixture, spy.puts);
      } catch (error) { await cleanup(fixture, spy.puts); throw error; }
    });

    await t.test("an infected output is rejected before storage, the job fails closed and the rejection is persisted", async () => {
      const fixture = await seed("merge-pdf", 1, 2);
      const spy: Spy = { puts: [], deletes: [] };
      const since = new Date();
      try {
        await assert.rejects(
          () => processDocumentJob(message(fixture), { storage: spyStorage(spy), scanner: scannerReturning("INFECTED").scanner, client: runtime }),
          (error: unknown) => error instanceof OutputScanError && error.code === "INFECTED" && error.unrecoverable === true,
        );
        const row = await jobRow(fixture.job);
        assert.equal(row.status, "FAILED");
        assert.equal(row.error_code, "INFECTED");
        assert.equal(row.output_file_id, null);
        assert.deepEqual(spy.puts, [], "no bytes may reach object storage");
        assert.deepEqual(await outputRows(fixture), [], "no file row may be created");

        // PR-1 regression: the raw insert must supply `security_events.id`
        // (there is no database default), otherwise every rejection was dropped.
        const events = await securityEventsSince(since);
        assert.equal(events.length, 1, "exactly one output rejection is persisted");
        assert.ok(events[0].id, "security_events.id must be non-null");
        assert.equal(events[0].details.result, "INFECTED");
        assert.equal(events[0].details.source, "output");
        assert.equal(events[0].details.engine, "pr1-stub");
        await purgeSecurityEventsSince(since);
        await cleanup(fixture);
      } catch (error) { await purgeSecurityEventsSince(since); await cleanup(fixture, spy.puts); throw error; }
    });

    await t.test("an unavailable scanner fails the job closed without storing anything", async () => {
      const fixture = await seed("merge-pdf", 1, 2);
      const spy: Spy = { puts: [], deletes: [] };
      const since = new Date();
      try {
        await assert.rejects(
          () => processDocumentJob(message(fixture), { storage: spyStorage(spy), scanner: scannerReturning("SCANNER_UNAVAILABLE").scanner, client: runtime }),
          (error: unknown) => error instanceof OutputScanError && error.code === "SCANNER_UNAVAILABLE" && error.unrecoverable === false,
        );
        const row = await jobRow(fixture.job);
        assert.equal(row.status, "FAILED");
        assert.equal(row.error_code, "SCANNER_UNAVAILABLE");
        assert.deepEqual(spy.puts, []);
        assert.deepEqual(await outputRows(fixture), []);
        const events = await securityEventsSince(since);
        assert.equal(events.length, 1);
        assert.equal(events[0].details.result, "SCANNER_UNAVAILABLE");
        await purgeSecurityEventsSince(since);
        await cleanup(fixture);
      } catch (error) { await purgeSecurityEventsSince(since); await cleanup(fixture, spy.puts); throw error; }
    });

    await t.test("a multi-output batch with one infected member stores nothing at all", async () => {
      const fixture = await seed("split-pdf", 2);
      const spy: Spy = { puts: [], deletes: [] };
      const scripted = scannerReturning("CLEAN", "INFECTED");
      const since = new Date();
      try {
        await assert.rejects(
          () => processDocumentJob(message(fixture), { storage: spyStorage(spy), scanner: scripted.scanner, client: runtime }),
          (error: unknown) => error instanceof OutputScanError && error.code === "INFECTED" && error.failures.length === 1 && error.failures[0].index === 1,
        );
        assert.equal(scripted.calls.length, 2, "both split outputs are scanned");
        assert.deepEqual(spy.puts, [], "the clean sibling must not be published either");
        assert.equal((await jobRow(fixture.job)).status, "FAILED");
        assert.deepEqual(await outputRows(fixture), []);
        const events = await securityEventsSince(since);
        assert.equal(events.length, 1, "only the infected member is persisted as a rejection");
        assert.equal(events[0].details.result, "INFECTED");
        await purgeSecurityEventsSince(since);
        await cleanup(fixture);
      } catch (error) { await purgeSecurityEventsSince(since); await cleanup(fixture, spy.puts); throw error; }
    });

    await t.test("a storage failure mid-batch deletes the partial object and fails the job", async () => {
      const fixture = await seed("split-pdf", 2);
      const spy: Spy = { puts: [], deletes: [], failPutAt: 1 };
      try {
        await assert.rejects(
          () => processDocumentJob(message(fixture), { storage: spyStorage(spy), scanner: getMalwareScanner(), client: runtime }),
          (error: unknown) => (error as { code?: string }).code === "STORAGE_FAILURE",
        );
        assert.equal(spy.puts.length, 2, "the first write succeeded, the second failed");
        assert.deepEqual(spy.deletes, [spy.puts[0]], "the already-written object is removed");
        assert.equal(await bucket.head(spy.puts[0]), undefined, "the partial object is gone from object storage");
        assert.equal((await jobRow(fixture.job)).status, "FAILED");
        assert.deepEqual(await outputRows(fixture), []);
        await cleanup(fixture);
      } catch (error) { await cleanup(fixture, spy.puts); throw error; }
    });
    await t.test("two concurrent attempts of one job commit exactly one output and remove only the loser's objects", async () => {
      const fixture = await seed("merge-pdf", 1, 2);
      const gate = barrier(2);
      const a: Spy = { puts: [], deletes: [] };
      const b: Spy = { puts: [], deletes: [] };
      const keys: string[] = [];
      try {
        const results = await Promise.allSettled([
          processDocumentJob(message(fixture), { storage: gatedStorage(a, gate), scanner: getMalwareScanner(), client: runtime, attemptId: "attempt-a" }),
          processDocumentJob(message(fixture), { storage: gatedStorage(b, gate), scanner: getMalwareScanner(), client: runtime, attemptId: "attempt-b" }),
        ]);
        keys.push(...a.puts, ...b.puts);
        assert.deepEqual(results.map((result) => result.status), ["fulfilled", "fulfilled"], "a lost commit race returns instead of throwing");
        assert.equal(a.puts.length, 1, "both attempts reached the write, so the commit race really happened");
        assert.equal(b.puts.length, 1);
        assert.notEqual(a.puts[0], b.puts[0], "each attempt owns a distinct object key");

        const row = await jobRow(fixture.job);
        assert.equal(row.status, "SUCCEEDED");
        assert.equal(row.error_code, null, "a losing attempt must not stamp a failure code on a committed job");
        assert.ok(row.output_file_id, "the job references one output");

        const outputs = await outputRows(fixture);
        assert.equal(outputs.length, 1, "exactly one output file row exists");
        assert.equal(await outputFileCount(fixture), 1, "no duplicate output file was left behind");
        assert.equal(await documentCount(fixture), 2, "one input document plus exactly one output document");
        assert.equal(await executionCount(fixture.job), 1, "exactly one ToolExecution was committed");

        const committed = outputs[0].storage_key;
        assert.ok(committed === a.puts[0] || committed === b.puts[0], "the committed row points at one attempt's object");
        assert.ok(await bucket.head(committed), "the committed object exists in object storage");
        for (const key of [a.puts[0], b.puts[0]].filter((key) => key !== committed)) {
          assert.equal(await bucket.head(key), undefined, "the losing attempt deleted its own object");
        }
        await cleanup(fixture, keys);
      } catch (error) { await cleanup(fixture, keys); throw error; }
    });

    await t.test("a committed attempt never touches objects left by an abandoned attempt", async () => {
      const fixture = await seed("merge-pdf", 1, 2);
      const staleKey = `output/${fixture.user}/${fixture.job}/attempt-crashed/0-stale.pdf`;
      await bucket.put({ key: staleKey, bytes: await pdfBytes(1), contentType: "application/pdf" });
      const spy: Spy = { puts: [], deletes: [] };
      try {
        await processDocumentJob(message(fixture), { storage: spyStorage(spy), scanner: getMalwareScanner(), client: runtime, attemptId: "attempt-live" });
        const outputs = await outputRows(fixture);
        assert.equal(outputs.length, 1);
        assert.match(outputs[0].storage_key, new RegExp(`/attempt-live/0-`), "the committed key belongs to the live attempt");
        assert.deepEqual(spy.deletes, [], "no delete was issued for another attempt's object");
        assert.ok(await bucket.head(staleKey), "an abandoned attempt's object is neither deleted nor overwritten");
        await cleanup(fixture, [...spy.puts, staleKey]);
      } catch (error) { await cleanup(fixture, [...spy.puts, staleKey]); throw error; }
    });

    await t.test("a failed metadata commit deletes only its own objects, and the retry then commits once", async () => {
      const fixture = await seed("merge-pdf", 1, 2);
      const failing: Spy = { puts: [], deletes: [] };
      const retry: Spy = { puts: [], deletes: [] };
      try {
        await assert.rejects(
          () => processDocumentJob(message(fixture), { storage: spyStorage(failing), scanner: getMalwareScanner(), client: commitFailingClient(), attemptId: "attempt-fail" }),
          (error: unknown) => (error as { code?: string }).code === "SIMULATED_COMMIT_FAILURE",
        );
        assert.equal(failing.puts.length, 1);
        assert.equal(await bucket.head(failing.puts[0]), undefined, "the object orphaned by the rolled-back transaction is deleted");
        assert.deepEqual(await outputRows(fixture), [], "the rolled-back transaction created no file rows");
        assert.equal(await executionCount(fixture.job), 0, "no ToolExecution survived the rollback");
        assert.equal((await jobRow(fixture.job)).status, "FAILED");

        await processDocumentJob(message(fixture), { storage: spyStorage(retry), scanner: getMalwareScanner(), client: runtime, attemptId: "attempt-retry" });
        const row = await jobRow(fixture.job);
        assert.equal(row.status, "SUCCEEDED");
        assert.ok(await bucket.head(retry.puts[0]), "the retry's object is committed");
        assert.equal(await outputFileCount(fixture), 1, "the retry produced exactly one output file");
        assert.equal(await executionCount(fixture.job), 1);
        await cleanup(fixture, [...failing.puts, ...retry.puts]);
      } catch (error) { await cleanup(fixture, [...failing.puts, ...retry.puts]); throw error; }
    });

    await t.test("a failing duplicate attempt cannot fail a job another attempt commits", async () => {
      const fixture = await seed("merge-pdf", 1, 2);
      const broken: Spy = { puts: [], deletes: [], failPutAt: 0 };
      const good: Spy = { puts: [], deletes: [] };
      // Both attempts are held inside screening until the other one arrives, so the
      // broken attempt cannot be skipped as an idempotent duplicate: it is already
      // past the job read when the healthy attempt commits.
      const scanGate = barrier(2);
      const real = getMalwareScanner();
      const sharedScanner = { async scan(bytes: Uint8Array) { await scanGate(); return real.scan(bytes); } };
      try {
        const results = await Promise.allSettled([
          processDocumentJob(message(fixture), { storage: spyStorage(broken), scanner: sharedScanner, client: runtime, attemptId: "attempt-broken" }),
          processDocumentJob(message(fixture), { storage: spyStorage(good), scanner: sharedScanner, client: runtime, attemptId: "attempt-good" }),
        ]);
        assert.equal(results.some((result) => result.status === "rejected"), true, "the storage fault is still reported to the queue");
        const row = await jobRow(fixture.job);
        assert.equal(row.status, "SUCCEEDED", "the committed attempt owns the terminal state");
        assert.equal(row.error_code, null, "a suppressed failure cannot stamp the committed job");
        assert.equal(await outputFileCount(fixture), 1);
        assert.ok(await bucket.head(good.puts[0]), "the committed output survives the duplicate's failure");
        await cleanup(fixture, [...broken.puts, ...good.puts]);
      } catch (error) { await cleanup(fixture, [...broken.puts, ...good.puts]); throw error; }
    });
  } finally {
    await runtime.$disconnect();
    await bucket.close();
    await owner.end();
  }
});
