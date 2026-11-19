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

type Fixture = { user: string; document: string; inputFile: string; job: string; inputKey: string; inputBytes: Uint8Array };
type Spy = { puts: string[]; deletes: string[]; failPutAt?: number };

integrationTest("PR-1 (integration): generated outputs are screened before storage", { timeout: 240_000 }, async (t) => {
  const { PrismaPg } = await import("@prisma/adapter-pg");
  const { PrismaClient } = await import("@prisma/client");
  const pg = await import("pg");
  const { createS3Storage } = await import("../src/lib/storage");
  const { processDocumentJob } = await import("../src/lib/jobs/document-pipeline");
  const { getMalwareScanner } = await import("../src/lib/malware");
  const { OutputScanError } = await import("../src/lib/outputs/screening");
  const { PDFDocument: Pdf } = await import("pdf-lib");

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
    const document = await Pdf.create();
    for (let index = 0; index < pages; index += 1) document.addPage();
    return new Uint8Array(await document.save());
  };

  const seed = async (toolId: string, pages: number): Promise<Fixture> => {
    const user = randomUUID(); const document = randomUUID(); const inputFile = randomUUID(); const job = randomUUID();
    const inputBytes = await pdfBytes(pages);
    const inputKey = `input/${user}/${inputFile}-in.pdf`;
    await bucket.put({ key: inputKey, bytes: inputBytes, contentType: "application/pdf" });
    await owner.query(`INSERT INTO users (id,email,status,created_at,updated_at) VALUES ($1,$2,'ACTIVE',now(),now())`, [user, `pr1-${user}@example.invalid`]);
    await owner.query(`INSERT INTO documents (id,user_id,title,status,created_at,updated_at) VALUES ($1,$2,'PR-1 input','ACTIVE',now(),now())`, [document, user]);
    await owner.query(`INSERT INTO files (id,document_id,original_name,mime_type,size,storage_key,version,created_at) VALUES ($1,$2,'in.pdf','application/pdf',$3,$4,1,now())`, [inputFile, document, inputBytes.byteLength, inputKey]);
    await owner.query(`INSERT INTO jobs (id,tool_id,idempotency_key,requester_id,status,params,correlation_id,created_at,updated_at) VALUES ($1,$2,$3,$4,'QUEUED',$5::jsonb,$6,now(),now())`, [job, toolId, `pr1-${job}`, user, JSON.stringify({ inputFileIds: [inputFile], options: {} }), randomUUID()]);
    return { user, document, inputFile, job, inputKey, inputBytes };
  };

  const cleanup = async (fixture: Fixture, extraKeys: string[] = []) => {
    await owner.query(`DELETE FROM tool_executions WHERE job_id = $1`, [fixture.job]);
    await owner.query(`DELETE FROM job_steps WHERE job_id = $1`, [fixture.job]);
    await owner.query(`DELETE FROM jobs WHERE id = $1`, [fixture.job]);
    await owner.query(`DELETE FROM file_versions WHERE file_id IN (SELECT id FROM files WHERE document_id IN (SELECT id FROM documents WHERE user_id = $1))`, [fixture.user]);
    await owner.query(`DELETE FROM files WHERE document_id IN (SELECT id FROM documents WHERE user_id = $1)`, [fixture.user]);
    await owner.query(`DELETE FROM documents WHERE user_id = $1`, [fixture.user]);
    await owner.query(`DELETE FROM users WHERE id = $1`, [fixture.user]);
    for (const key of [fixture.inputKey, ...extraKeys]) await bucket.deleteObject(key).catch(() => undefined);
  };

  const message = (fixture: Fixture) => ({ jobId: fixture.job, toolId: "", idempotencyKey: `pr1-${fixture.job}`, correlationId: randomUUID(), userId: fixture.user });
  const jobRow = async (id: string) => (await owner.query(`SELECT status, error_code, output_file_id FROM jobs WHERE id = $1`, [id])).rows[0];
  const outputRows = async (fixture: Fixture) => (await owner.query(`SELECT f.id, f.storage_key, f.checksum FROM files f JOIN documents d ON d.id = f.document_id WHERE d.user_id = $1 AND f.id <> $2`, [fixture.user, fixture.inputFile])).rows;

  try {
    await t.test("clean output is scanned with real clamd, stored once and the job succeeds", async () => {
      const fixture = await seed("merge-pdf", 1);
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

    await t.test("an infected output is rejected before storage and the job fails closed", async () => {
      const fixture = await seed("merge-pdf", 1);
      const spy: Spy = { puts: [], deletes: [] };
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
        await cleanup(fixture);
      } catch (error) { await cleanup(fixture, spy.puts); throw error; }
    });

    await t.test("an unavailable scanner fails the job closed without storing anything", async () => {
      const fixture = await seed("merge-pdf", 1);
      const spy: Spy = { puts: [], deletes: [] };
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
        await cleanup(fixture);
      } catch (error) { await cleanup(fixture, spy.puts); throw error; }
    });

    await t.test("a multi-output batch with one infected member stores nothing at all", async () => {
      const fixture = await seed("split-pdf", 2);
      const spy: Spy = { puts: [], deletes: [] };
      const scripted = scannerReturning("CLEAN", "INFECTED");
      try {
        await assert.rejects(
          () => processDocumentJob(message(fixture), { storage: spyStorage(spy), scanner: scripted.scanner, client: runtime }),
          (error: unknown) => error instanceof OutputScanError && error.code === "INFECTED" && error.failures.length === 1 && error.failures[0].index === 1,
        );
        assert.equal(scripted.calls.length, 2, "both split outputs are scanned");
        assert.deepEqual(spy.puts, [], "the clean sibling must not be published either");
        assert.equal((await jobRow(fixture.job)).status, "FAILED");
        assert.deepEqual(await outputRows(fixture), []);
        await cleanup(fixture);
      } catch (error) { await cleanup(fixture, spy.puts); throw error; }
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
  } finally {
    await runtime.$disconnect();
    await bucket.close();
    await owner.end();
  }
});
