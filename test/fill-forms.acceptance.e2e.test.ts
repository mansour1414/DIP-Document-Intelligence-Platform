/**
 * R6.3 — Fill Forms acceptance through the *real* application paths.
 *
 * ## Why this file exists
 *
 * The artifact smoke script executes the child process directly. That proves the child can
 * run inside a built artifact; it does **not** prove that an authenticated request reaches
 * it, that admission runs, or that a BullMQ worker picks the job up. This file covers the
 * six scenarios that only the real stack can answer:
 *
 *   1. authenticated standalone `POST /api/fill-forms/inspect`
 *   2. authenticated web `fill-forms` submission (browser path)
 *   3. authenticated Public API `fill-forms` submission
 *   4. `fill-forms` processed by the production BullMQ worker image
 *   5. the same worker flattening
 *   6. the same worker with an Arabic value (native canvas + bundled font)
 *
 * It reuses the infrastructure the Release B job already provisions — Postgres, Redis,
 * MinIO, ClamAV, the standalone server and the worker image. No new framework, no global
 * production test overrides, no service added.
 *
 * Gated on `FILL_FORMS_ACCEPTANCE_E2E=1` so it never runs in a unit-test environment.
 * Locally this is BLOCKED: it needs Postgres, Redis, object storage and a running server.
 */
import assert from "node:assert/strict";
import test, { after } from "node:test";
import { randomUUID } from "node:crypto";
import { PDFDocument } from "pdf-lib";

const integration = process.env.FILL_FORMS_ACCEPTANCE_E2E === "1" ? test : test.skip;

/**
 * Close every resource this suite opens, once, after the last test.
 *
 * The R6.3 version closed only `getJobQueue()`. The process then stayed alive — the CI log
 * showed the acceptance step still running ~50 minutes after its assertion failed — because
 * a BullMQ `Queue.close()` leaves the shared ioredis connection that the *worker* path and
 * `closeQueueResources()` own, and the storage and Prisma clients were never closed at all.
 * The existing Public API HTTP test already solves exactly this, so the same helpers are
 * reused rather than a second convention invented.
 *
 * `Promise.allSettled` so one failing close cannot prevent the others; the results are then
 * inspected and rethrown, because a cleanup that fails silently is how the leak survived.
 */
after(async () => {
  if (process.env.FILL_FORMS_ACCEPTANCE_E2E !== "1") return;
  const { closeQueueResources } = await import("../src/lib/queue/index");
  const { closeStorage } = await import("../src/lib/storage/index");
  const { db } = await import("../src/lib/db/index");
  const results = await Promise.allSettled([closeQueueResources(), closeStorage(), db.$disconnect()]);
  const failed = results.filter((result): result is PromiseRejectedResult => result.status === "rejected");
  if (failed.length) {
    throw new AggregateError(failed.map((result) => result.reason), "acceptance suite resource cleanup failed");
  }
});
const base = process.env.ACCEPTANCE_BASE_URL ?? "http://127.0.0.1:3000";

/** A one-page AcroForm with a real text field, so inspection accepts it. */
async function fillableForm(name = "applicant.name") {
  const document = await PDFDocument.create();
  const page = document.addPage([300, 300]);
  document.getForm().createTextField(name).addToPage(page, { x: 20, y: 20, width: 160, height: 22 });
  return new Uint8Array(await document.save());
}

/** A document with no form at all: valid PDF, nothing to fill. */
async function formlessPdf() {
  const document = await PDFDocument.create();
  document.addPage([300, 300]);
  return new Uint8Array(await document.save());
}

/**
 * Remove a fixture tenant and everything it owns, in dependency order.
 *
 * `User → Document` has **no** `onDelete: Cascade`, so deleting the user while the
 * submission's documents still exist raises `documents_user_id_fkey`. The previous
 * version called `db.user.delete()` directly and swallowed the error with
 * `.catch(() => undefined)` — a cleanup failure that looked like a clean run.
 *
 * Order matters and is taken from the schema, not guessed: files reference documents,
 * job rows reference files, then the tenant rows that carry a `Restrict` relation
 * (workflows, agent runs, API clients) go before the user. Objects in storage are
 * removed first, because a database row is the only record of where they are.
 *
 * Cleanup failures are **reported**, never swallowed: a leaked fixture in a disposable
 * database is tolerable, but a silent one hides a schema change that will break the next
 * run.
 */
async function removeFixtureTenant(userId: string, options: { storage?: { deleteObject(key: string): Promise<void> } } = {}) {
  const { db } = await import("../src/lib/db/index");
  // Explicit types: without a generated Prisma client these queries infer `{}`, and the
  // annotations keep that pre-existing environment gap from adding avoidable errors here.
  const files = await db.file.findMany({ where: { document: { userId } }, select: { storageKey: true } }) as Array<{ storageKey: string }>;
  if (options.storage) {
    await Promise.all(files.map((file: { storageKey: string }) => options.storage!.deleteObject(file.storageKey).catch((error: unknown) => {
      throw new Error(`fixture storage cleanup failed for ${file.storageKey}: ${String(error)}`);
    })));
  }
  // Order is taken from the foreign keys in `prisma/schema.prisma`, not from intuition.
  // Several relations have no `onDelete: Cascade` at all — `Document.user`, `File.document`,
  // `Job.inputFile/outputFile`, `AuditLog.organization` — and a few carry `Restrict`
  // (`Workflow.owner`, `AgentRun.owner`, `ApiClient.createdByUser`). Deleting the user first
  // is what produced `documents_user_id_fkey`.
  await db.$transaction(async (tx: Record<string, { deleteMany: (args: unknown) => Promise<unknown>; findMany: (args: unknown) => Promise<unknown>; delete: (args: unknown) => Promise<unknown> }>) => {
    // Job rows reference files, so they go first.
    await tx.job.deleteMany({ where: { requesterId: userId } });
    await tx.file.deleteMany({ where: { document: { userId } } });
    await tx.document.deleteMany({ where: { userId } });
    // Tenant-scoped records.
    await tx.usageEvent.deleteMany({ where: { userId } });
    await tx.creditLedger.deleteMany({ where: { userId } });
    await tx.aiUsage.deleteMany({ where: { userId } });
    // `Restrict` relations must go before the user.
    await tx.workflow.deleteMany({ where: { ownerId: userId } });
    await tx.agentRun.deleteMany({ where: { ownerId: userId } });
    await tx.apiClient.deleteMany({ where: { createdByUserId: userId } });
    // Organization-owned rows. `createOrganization` writes an audit entry, and `AuditLog`
    // references `Organization` without a cascade, so it must be removed first.
    const organizations = await tx.organization.findMany({ where: { memberships: { some: { userId } } }, select: { id: true } }) as Array<{ id: string }>;
    const organizationIds = organizations.map((organization: { id: string }) => organization.id);
    if (organizationIds.length) {
      await tx.auditLog.deleteMany({ where: { organizationId: { in: organizationIds } } });
      await tx.membership.deleteMany({ where: { organizationId: { in: organizationIds } } });
    }
    await tx.membership.deleteMany({ where: { userId } });
    await tx.organization.deleteMany({ where: { id: { in: organizationIds } } });
    await tx.user.delete({ where: { id: userId } });
  });
}

integration("R6.3-1: authenticated web session reaches isolated inspection", { timeout: 120_000 }, async (t) => {
  // The inspect route authenticates a browser session, not an API key. `PUBLIC_API_HTTP_E2E`
  // covers the API-key path; here the point is that the *web* route admits, scans, and
  // parses in a bounded child — and that the session is required.
  const { db } = await import("../src/lib/db/index");
  const { createSessionToken } = await import("../src/lib/auth/session");
  const userId = randomUUID();
  await db.user.create({ data: { id: userId, email: `${userId}@example.invalid`, status: "ACTIVE" } });
  const cookie = `dip_session=${createSessionToken(userId)}`;
  try {
    const form = new FormData();
    form.set("file", new File([await fillableForm() as BlobPart], "form.pdf", { type: "application/pdf" }));
    const response = await fetch(`${base}/api/fill-forms/inspect`, { method: "POST", headers: { cookie }, body: form });
    if (response.status !== 200) t.diagnostic(`inspect returned ${response.status}: ${(await response.clone().text()).slice(0, 400)}`);
    assert.equal(response.status, 200, "an authenticated session must be able to inspect a fillable form");
    const body = await response.json() as { inventory?: { pages?: number; fields?: Array<{ name: string }> } };
    assert.equal(body.inventory?.pages, 1, "the child's parsed page count must reach the response");
    assert.ok(body.inventory?.fields?.some((field) => field.name === "applicant.name"), "the field inventory must include the real field");

    // Unauthenticated must be refused, and must not reach a parser.
    const anonymous = new FormData();
    anonymous.set("file", new File([await fillableForm() as BlobPart], "form.pdf", { type: "application/pdf" }));
    const denied = await fetch(`${base}/api/fill-forms/inspect`, { method: "POST", body: anonymous });
    assert.ok([401, 403].includes(denied.status), `an anonymous request must be refused, saw ${denied.status}`);

    // A PDF with no form is **inspectable**: the route is documented as inventory-only and
    // must be able to report "no fields" so the workspace can say so. R6.5 deliberately did
    // not change this. Asserting a rejection here would have conflated the read-only
    // inspector with job admission — the distinction this round exists to establish.
    //
    // The refusal that matters is at admission, and it is asserted separately below.
    const empty = new FormData();
    empty.set("file", new File([await formlessPdf() as BlobPart], "plain.pdf", { type: "application/pdf" }));
    const noForm = await fetch(`${base}/api/fill-forms/inspect`, { method: "POST", headers: { cookie }, body: empty });
    assert.equal(noForm.status, 200, "inspection is read-only and must report an empty inventory, not refuse the document");
    const emptyInventory = await noForm.json() as { inventory?: { pages?: number; fields?: unknown[] } };
    assert.equal(emptyInventory.inventory?.pages, 1, "the page count must still be reported");
    assert.deepEqual(emptyInventory.inventory?.fields, [], "the inventory must be empty rather than absent");
  } finally {
    await removeFixtureTenant(userId);
  }
});

integration("R6.3-2: authenticated web submission reaches plan enforcement with the real page count", { timeout: 240_000 }, async (t) => {
  const { db } = await import("../src/lib/db/index");
  const { createSessionToken } = await import("../src/lib/auth/session");
  const { getJobQueue } = await import("../src/lib/queue/index");
  const { getStorage } = await import("../src/lib/storage/index");
  const userId = randomUUID();
  const proPlan = await db.planCatalog.findUniqueOrThrow({ where: { code: "PRO" }, select: { id: true } });
  await db.user.create({ data: { id: userId, email: `${userId}@example.invalid`, status: "ACTIVE", subscriptions: { create: { planId: proPlan.id, status: "ACTIVE" } }, creditLedger: { create: { type: "BONUS", amount: 100, balance: 100, idempotencyKey: "r63-web-seed", reason: "PROMOTIONAL_GRANT" } } } });
  const cookie = `dip_session=${createSessionToken(userId)}`;
  try {
    const form = new FormData();
    form.set("toolId", "fill-forms");
    form.set("files", new File([await fillableForm() as BlobPart], "form.pdf", { type: "application/pdf" }));
    form.set("fields", JSON.stringify({ "applicant.name": "Noura Al-Harbi" }));
    const response = await fetch(`${base}/api/jobs/fill-forms`, { method: "POST", headers: { cookie, "idempotency-key": "r63-web-fill" }, body: form });
    if (response.status !== 202 && response.status !== 200) t.diagnostic(`web submit returned ${response.status}: ${(await response.clone().text()).slice(0, 600)}`);
    assert.ok([200, 202].includes(response.status), "an authenticated web submission must be accepted");
    // The web route answers `{ jobId, status, correlationId, reused }`.
    const jobId = (await response.json() as { jobId: string }).jobId;
    assert.ok(jobId, "the submission must return a job id");

    // Plan enforcement must have run against the *inspected* page count, and the input
    // file row must carry it: that value is what the worker later verifies output against.
    const input = await db.file.findFirstOrThrow({ where: { document: { userId }, originalName: "form.pdf" } });
    assert.equal(input.pageCount, 1, "the authoritative page count must be persisted on the input file");
    assert.equal(await db.usageEvent.count({ where: { userId, kind: "job.created" } }), 1, "exactly one usage event per submission");
    const queued = await getJobQueue().getJob(jobId);
    assert.ok(queued, "the job must be submitted to the document queue");
  } finally {
    await removeFixtureTenant(userId, { storage: getStorage() });
  }
});

integration("R6.3-3: authenticated Public API submission is accepted for fill-forms", { timeout: 240_000 }, async (t) => {
  const { db } = await import("../src/lib/db/index");
  const { createOrganization } = await import("../src/lib/business/organizations");
  const { createApiClient, createApiKey } = await import("../src/lib/api-platform/clients");
  const { getStorage } = await import("../src/lib/storage/index");
  const userId = randomUUID();
  await db.user.create({ data: { id: userId, email: `${userId}@example.invalid`, creditLedger: { create: { type: "BONUS", amount: 100, balance: 100, idempotencyKey: "r63-api-seed", reason: "PROMOTIONAL_GRANT" } } } });
  const organization = await createOrganization(userId, "R6.3 API");
  const client = await createApiClient(userId, organization.id, "R6.3 client");
  const key = await createApiKey(userId, organization.id, client.id, "R6.3 key", ["*"]);
  try {
    const form = new FormData();
    form.set("toolId", "fill-forms");
    form.set("files", new File([await fillableForm() as BlobPart], "form.pdf", { type: "application/pdf" }));
    form.set("fields", JSON.stringify({ "applicant.name": "API Caller" }));
    const response = await fetch(`${base}/v1/jobs`, { method: "POST", headers: { authorization: `Bearer ${key.key}`, "idempotency-key": "r63-api-fill" }, body: form });
    if (response.status !== 202) t.diagnostic(`api submit returned ${response.status}: ${(await response.clone().text()).slice(0, 600)}`);
    assert.equal(response.status, 202, "an authenticated API submission must be accepted");
    const jobId = (await response.json() as { data: { id: string } }).data.id;
    const input = await db.file.findFirstOrThrow({ where: { document: { userId }, originalName: "form.pdf" } });
    assert.equal(input.pageCount, 1, "the API path must persist the authoritative page count too");
    assert.ok(jobId);
  } finally {
    await removeFixtureTenant(userId, { storage: getStorage() });
  }
});

integration("R6.3-4/5/6: the production worker fills, flattens and renders Arabic", { timeout: 300_000 }, async (t) => {
  // The worker image is already running in the Release B job (`EXTERNAL_WORKER_E2E=1`), so
  // these jobs are claimed by the *image*, not by an in-process worker. This is the only
  // placement that exercises the deployed worker container.
  const { db } = await import("../src/lib/db/index");
  const { createToolJob } = await import("../src/lib/jobs/orchestrator");
  const { getStorage } = await import("../src/lib/storage/index");
  const { getJobQueue } = await import("../src/lib/queue/index");
  const storage = getStorage();
  const userId = randomUUID();
  const proPlan = await db.planCatalog.findUniqueOrThrow({ where: { code: "PRO" }, select: { id: true } });
  await db.user.create({ data: { id: userId, email: `${userId}@example.invalid`, subscriptions: { create: { planId: proPlan.id, status: "ACTIVE" } }, creditLedger: { create: { type: "BONUS", amount: 100, balance: 100, idempotencyKey: "r63-worker-seed", reason: "PROMOTIONAL_GRANT" } } } });

  const wait = async (id: string) => {
    for (let index = 0; index < 1200; index += 1) {
      const job = await db.job.findUniqueOrThrow({ where: { id }, include: { steps: true, toolExecutions: true } });
      if (["SUCCEEDED", "FAILED", "CANCELLED", "EXPIRED"].includes(job.status)) return job;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    throw new Error(`R63_JOB_STUCK:${id}`);
  };

  try {
    const form = await fillableForm();

    // R6.3-4 — plain fill through the worker image.
    const filled = await createToolJob({ userId, toolId: "fill-forms", idempotencyKey: "r63-fill", correlationId: randomUUID(), uploads: [{ filename: "form.pdf", mimeType: "application/pdf", bytes: form }], fields: { "applicant.name": "Worker Filled" } });
    const filledJob = await wait(filled.id);
    if (filledJob.status !== "SUCCEEDED") t.diagnostic(`fill failed: ${filledJob.errorCode}`);
    assert.equal(filledJob.status, "SUCCEEDED", "the production worker must complete a fill");
    assert.ok(filledJob.outputFileId, "a successful fill must publish an output");
    const filledOutput = await db.file.findUniqueOrThrow({ where: { id: filledJob.outputFileId! } });
    // The verified page count must be persisted on the published artifact.
    assert.equal(filledOutput.pageCount, 1, "the published output must record the verified page count");
    assert.equal(await storage.exists(filledOutput.storageKey), true, "the output bytes must be in object storage");
    const reopened = await PDFDocument.load(await storage.get(filledOutput.storageKey));
    assert.equal(reopened.getForm().getTextField("applicant.name").getText(), "Worker Filled");

    // R6.3-5 — flatten through the worker image.
    const flattened = await createToolJob({ userId, toolId: "fill-forms", idempotencyKey: "r63-flatten", correlationId: randomUUID(), options: { flatten: true }, uploads: [{ filename: "form.pdf", mimeType: "application/pdf", bytes: form }], fields: { "applicant.name": "Worker Flattened" } });
    const flattenedJob = await wait(flattened.id);
    if (flattenedJob.status !== "SUCCEEDED") t.diagnostic(`flatten failed: ${flattenedJob.errorCode}`);
    assert.equal(flattenedJob.status, "SUCCEEDED", "the production worker must complete a flatten");
    const flattenedOutput = await db.file.findUniqueOrThrow({ where: { id: flattenedJob.outputFileId! } });
    const flattenedDoc = await PDFDocument.load(await storage.get(flattenedOutput.storageKey));
    assert.equal(flattenedDoc.getForm().getFields().length, 0, "flatten must remove the form");
    assert.equal(flattenedDoc.getPageCount(), 1, "flatten must preserve the page count");

    // R6.3-6 — Arabic appearance through the worker image (native canvas + bundled font).
    const arabic = await createToolJob({ userId, toolId: "fill-forms", idempotencyKey: "r63-arabic", correlationId: randomUUID(), uploads: [{ filename: "form.pdf", mimeType: "application/pdf", bytes: form }], fields: { "applicant.name": "نورة الحربي" } });
    const arabicJob = await wait(arabic.id);
    if (arabicJob.status !== "SUCCEEDED") t.diagnostic(`arabic failed: ${arabicJob.errorCode}`);
    assert.equal(arabicJob.status, "SUCCEEDED", "the production worker must render an Arabic value");
    const arabicOutput = await db.file.findUniqueOrThrow({ where: { id: arabicJob.outputFileId! } });
    const arabicDoc = await PDFDocument.load(await storage.get(arabicOutput.storageKey));
    assert.equal(arabicDoc.getForm().getTextField("applicant.name").getText(), "نورة الحربي", "the Arabic value must round-trip through the worker");

    // Rejection side. Two distinct cases, deliberately:
    //
    //   (a) an empty upload — proves the *byte* gate rejects before anything is written;
    //   (b) a structurally valid PDF with no form — proves *isolated form inspection*
    //       rejects it. The R6.3 version only had (a), which a byte check satisfies, so it
    //       said nothing about the inspection path that this release changed.
    const before = {
      usage: await db.usageEvent.count({ where: { userId } }),
      files: await db.file.count({ where: { document: { userId } } }),
      // Tenant-specific evidence, not a global depth reading: the document queue is
      // shared, and any other suite (or the worker image draining its own jobs) changes
      // global counts between two samples. What must not change is this tenant's own set
      // of job rows and queue entries.
      jobsBefore: (await db.job.findMany({ where: { requesterId: userId }, select: { id: true } })).map((job: { id: string }) => job.id),
    };
    // The earlier scenarios legitimately enqueued jobs, so "no queue entry" is not the
    // invariant — *unchanged* is. Snapshot which of this tenant's jobs are on the queue,
    // then require exactly the same answer after the rejections.
    const queuedBefore = new Set<string>();
    for (const id of before.jobsBefore) if (await getJobQueue().getJob(id)) queuedBefore.add(id);

    await assert.rejects(
      () => createToolJob({ userId, toolId: "fill-forms", idempotencyKey: "r63-reject-empty", correlationId: randomUUID(), uploads: [{ filename: "plain.pdf", mimeType: "application/pdf", bytes: new Uint8Array(0) }], fields: { "applicant.name": "x" } }),
      "an empty upload must be rejected",
    );

    // A real, parseable PDF that simply has no form: the rejection must come from
    // inspection, not from the byte gate.
    const formless = await formlessPdf();
    await assert.rejects(
      () => createToolJob({ userId, toolId: "fill-forms", idempotencyKey: "r63-reject-formless", correlationId: randomUUID(), uploads: [{ filename: "plain.pdf", mimeType: "application/pdf", bytes: formless }], fields: { "applicant.name": "x" } }),
      (error: unknown) => {
        // Typed rejection, not an internal failure: a 500 here would mean the inspection
        // path collapsed rather than refused.
        const code = (error as { code?: string }).code;
        assert.equal(code, "FORM_NOT_FOUND", `a form-less PDF must be refused by inspection, saw ${String(code)}`);
        return true;
      },
    );

    assert.equal(await db.usageEvent.count({ where: { userId } }), before.usage, "a rejected submission must not write usage");
    assert.equal(await db.file.count({ where: { document: { userId } } }), before.files, "a rejected submission must not write files");
    // The tenant's job set must be byte-identical: no new row, and no row removed.
    const jobsAfter = (await db.job.findMany({ where: { requesterId: userId }, select: { id: true } })).map((job: { id: string }) => job.id);
    assert.deepEqual([...jobsAfter].sort(), [...before.jobsBefore].sort(), "a rejected submission must not create a job row");
    // And no *new* queue entry may exist for this tenant. Scoped to the tenant's own job
    // ids, so a concurrently running suite cannot make this flaky.
    for (const id of jobsAfter) {
      const queued = await getJobQueue().getJob(id);
      assert.equal(Boolean(queued), queuedBefore.has(id), `the queue state of job ${id} changed during a rejected submission`);
    }
  } finally {
    // Not `getJobQueue().close()`: that closed only the document queue and left the
    // shared connection open, which is why the process outlived the suite. The suite-level
    // `after` hook calls `closeQueueResources()`, which is the supported teardown.
    await removeFixtureTenant(userId, { storage });
  }
});
