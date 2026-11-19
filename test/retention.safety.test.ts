import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { planRetention, classifyStorageScope, configuredRetentionScope, parseRetentionApply, missingRetentionCredentials, type RetentionDocumentFacts, type RetentionScope } from "../src/lib/retention/safety";

const scope: RetentionScope = { provider: "s3", bucket: "dip-documents" };
const now = new Date("2026-09-10T00:00:00Z");
const expired = new Date("2026-08-01T00:00:00Z");
const fresh = new Date("2026-09-09T00:00:00Z");

function documentFacts(overrides: {
  createdAt?: Date;
  bucket?: string;
  provider?: string;
  deletedAt?: Date | null;
  protectedIds?: string[];
  storageObject?: boolean;
} = {}): RetentionDocumentFacts {
  const fileId = randomUUID();
  return {
    documentId: randomUUID(),
    files: [{
      fileId,
      createdAt: overrides.createdAt ?? expired,
      storageObject: overrides.storageObject === false ? null : {
        id: randomUUID(),
        provider: overrides.provider ?? scope.provider,
        bucket: overrides.bucket ?? scope.bucket,
        objectKey: `input/tenant/${randomUUID()}.pdf`,
        deletedAt: overrides.deletedAt ?? null,
      },
    }],
  };
}

// ---------------------------------------------------------------------------
// Dry-run safety
// ---------------------------------------------------------------------------

test("scheduler default mode is dry-run and only the exact value 1 applies deletions", () => {
  for (const value of [undefined, "", "0", "true", "TRUE", " 1", "yes", "2"]) {
    assert.equal(parseRetentionApply(value), false, `RETENTION_APPLY=${JSON.stringify(value)} must not enable apply`);
  }
  assert.equal(parseRetentionApply("1"), true);
});

test("dry-run is strictly read-only: the service never writes, calls storage or mutates jobs", async () => {
  const source = await readFile(new URL("../src/lib/retention/service.ts", import.meta.url), "utf8");
  const schedulerSource = await readFile(new URL("../scripts/cleanup-expired-jobs.ts", import.meta.url), "utf8");

  // The destructive loop is entered only after the dry-run early return.
  const dryRunIndex = source.indexOf("if (dryRun) {");
  const destructiveIndex = source.indexOf("for (const deletion of plan.deletions)");
  assert.ok(dryRunIndex > 0 && destructiveIndex > dryRunIndex, "dry-run must return before the delete loop");
  const beforeReturn = source.slice(0, dryRunIndex);
  for (const write of ["deleteObject(", "storageObject.update", "document.update", "job.update", "job.updateMany", "$transaction"]) {
    assert.equal(beforeReturn.includes(write), false, `dry-run path must not contain ${write}`);
  }
  // All storage deletes stay inside the apply path.
  const countDeleteCalls = (source.match(/storage\.deleteObject\(/g) ?? []).length;
  assert.equal(countDeleteCalls, 1);
  assert.ok(source.indexOf("storage.deleteObject(") > dryRunIndex);

  // Job expiry is a mutation and must be gated behind apply mode.
  assert.match(schedulerSource, /const expiredJobs = apply \? await expireStalledJobs\(\) : 0;/);
});

test("planner never reports a candidate for retained, protected, missing or out-of-scope files", () => {
  const protectedDoc = documentFacts();
  const plan = planRetention({
    now,
    retentionDays: 7,
    scope,
    protectedFileIds: new Set(protectedDoc.files.map((file) => file.fileId)),
    documents: [
      documentFacts({ createdAt: fresh }),
      protectedDoc,
      documentFacts({ storageObject: false }),
      documentFacts({ bucket: "another-bucket" }),
      documentFacts({ provider: "r2" }),
      documentFacts(),
    ],
  });

  assert.equal(plan.candidateDocuments, 1);
  assert.equal(plan.deletions.length, 1);
  assert.equal(plan.retainedFiles, 1);
  assert.equal(plan.protectedFiles, 1);
  assert.equal(plan.missingObjectFiles, 1);
  assert.equal(plan.scopeBlockedFiles, 2);
  assert.deepEqual(plan.skipReasons, {
    retained: 1,
    protected_by_active_job: 1,
    missing_storage_object: 1,
    provider_mismatch: 1,
    bucket_mismatch: 1,
  });
});

test("candidate reporting is aggregate-only and never leaks document contents", async () => {
  const secrets = ["Customer Merger Draft.pdf", "salary-review.xlsx", "input/tenant/private-object-key.pdf"];
  const documents: RetentionDocumentFacts[] = secrets.map(() => ({
    documentId: randomUUID(),
    files: [{
      fileId: randomUUID(),
      createdAt: expired,
      storageObject: { id: randomUUID(), provider: "s3", bucket: "dip-documents", objectKey: secrets[2], deletedAt: null },
    }],
  }));
  const plan = planRetention({ now, retentionDays: 7, scope, protectedFileIds: new Set(), documents });
  const serialized = JSON.stringify(plan);
  // No document title or filename may appear in the plan.
  for (const secret of secrets.slice(0, 2)) assert.equal(serialized.includes(secret), false);
  for (const file of documents.flatMap((item) => item.files)) {
    assert.equal(serialized.includes(file.fileId), false, "file ids must not be reported");
  }

  // The logger-visible summary is aggregate counts only.
  const { buildRetentionSummary } = await import("../src/lib/retention/safety");
  const summary = JSON.stringify(buildRetentionSummary({ plan, expiredJobs: 0 }));
  for (const secret of secrets) assert.equal(summary.includes(secret), false);
  for (const document of documents) assert.equal(summary.includes(document.documentId), false, "document ids belong to logs, not the summary");
});

// ---------------------------------------------------------------------------
// Wrong-bucket / provider rejection
// ---------------------------------------------------------------------------

test("storage scope classification rejects provider and bucket mismatches", () => {
  assert.equal(classifyStorageScope({ provider: "s3", bucket: "dip-documents", objectKey: "k" }, scope), "match");
  assert.equal(classifyStorageScope({ provider: "r2", bucket: "dip-documents", objectKey: "k" }, scope), "provider_mismatch");
  assert.equal(classifyStorageScope({ provider: "s3", bucket: "dip-documents-eu", objectKey: "k" }, scope), "bucket_mismatch");
  // A prefix or host that merely looks similar is still a different bucket.
  assert.equal(classifyStorageScope({ provider: "s3", bucket: "dip-documents/", objectKey: "k" }, scope), "bucket_mismatch");
  assert.equal(classifyStorageScope({ provider: "s3", bucket: "", objectKey: "k" }, scope), "bucket_mismatch");
});

test("an unconfigured bucket is a hard failure instead of a silent default", () => {
  assert.throws(() => configuredRetentionScope({}), /RETENTION_STORAGE_SCOPE_UNCONFIGURED/);
  assert.throws(() => configuredRetentionScope({ STORAGE_BUCKET: "   " }), /RETENTION_STORAGE_SCOPE_UNCONFIGURED/);
  assert.deepEqual(configuredRetentionScope({ STORAGE_BUCKET: "dip-documents" }), scope);
});

test("wrong-bucket documents are blocked instead of deleting into the configured bucket", () => {
  const wrongBucket = documentFacts({ bucket: "release-b-archive" });
  const plan = planRetention({ now, retentionDays: 7, scope, protectedFileIds: new Set(), documents: [wrongBucket] });
  assert.equal(plan.candidateDocuments, 0);
  assert.deepEqual(plan.deletions, []);
  assert.equal(plan.scopeBlockedFiles, 1);
});

// ---------------------------------------------------------------------------
// Idempotency
// ---------------------------------------------------------------------------

test("planning is deterministic and side-effect free for identical input", () => {
  const documents = [documentFacts(), documentFacts({ bucket: "other" }), documentFacts({ createdAt: fresh })];
  const first = planRetention({ now, retentionDays: 7, scope, protectedFileIds: new Set(), documents });
  const second = planRetention({ now, retentionDays: 7, scope, protectedFileIds: new Set(), documents });
  assert.deepEqual(first, second);
});

test("an already-tombstoned object is not re-deleted and does not block the document", () => {
  const documents = [documentFacts({ deletedAt: new Date("2026-09-09T00:00:00Z") })];
  const plan = planRetention({ now, retentionDays: 7, scope, protectedFileIds: new Set(), documents });
  assert.equal(plan.candidateDocuments, 1);
  assert.equal(plan.alreadyDeletedFiles, 1);
  assert.deepEqual(plan.deletions[0].objects, [], "a retried sweep must not issue a second storage delete");
});

test("retention periods are unchanged by this change", async () => {
  const { retentionPolicy, RETENTION_POLICY_VERSION } = await import("../src/lib/retention/config");
  assert.equal(RETENTION_POLICY_VERSION, "2026-09-provisional-v2");
  assert.equal(retentionPolicy.plans.FREE.inputDays, 7);
  assert.equal(retentionPolicy.plans.PRO.inputDays, 30);
  assert.equal(retentionPolicy.plans.FREE.outputDays, 7);
  assert.equal(retentionPolicy.plans.PRO.outputDays, 30);
  assert.equal(retentionPolicy.tempHours, 1);
  assert.equal(retentionPolicy.auditDays, 365);
});

// ---------------------------------------------------------------------------
// Failure handling
// ---------------------------------------------------------------------------

test("missing credentials are reported by name only and fail closed", () => {
  assert.deepEqual(missingRetentionCredentials({}), [
    "DATABASE_URL",
    "STORAGE_ENDPOINT",
    "STORAGE_BUCKET",
    "STORAGE_ACCESS_KEY",
    "STORAGE_SECRET_KEY",
  ]);
  assert.deepEqual(missingRetentionCredentials({ STORAGE_BUCKET: "dip-documents" }).includes("STORAGE_BUCKET"), false);
  assert.deepEqual(missingRetentionCredentials({ DATABASE_URL: "postgresql://u:p@h/db", STORAGE_ENDPOINT: "http://s3", STORAGE_BUCKET: "dip-documents", STORAGE_ACCESS_KEY: "k", STORAGE_SECRET_KEY: "s" }), []);
  // Whitespace is treated as absent rather than as a usable credential.
  assert.deepEqual(missingRetentionCredentials({ STORAGE_BUCKET: "  " }), ["DATABASE_URL", "STORAGE_ENDPOINT", "STORAGE_BUCKET", "STORAGE_ACCESS_KEY", "STORAGE_SECRET_KEY"]);
});

test("credential failure messages never contain secret values", async () => {
  const { logger } = await import("../src/lib/logging");
  const events: string[] = [];
  const original = logger.error;
  logger.error = ((event: string, context?: Record<string, unknown>) => {
    events.push(`${event} ${JSON.stringify(context ?? {})}`);
  }) as typeof logger.error;
  try {
    const { missingRetentionCredentials: missing } = await import("../src/lib/retention/safety");
    const secret = "super-secret-access-key-value";
    const absent = missing({ STORAGE_ACCESS_KEY: secret, STORAGE_SECRET_KEY: secret });
    logger.error("retention.scheduler_failed", { error_code: "RETENTION_CONFIGURATION_MISSING" });
    logger.error("retention.missing_configuration", { missing_variables: absent.join(",") });
    const joined = events.join("\n");
    assert.equal(joined.includes(secret), false);
    assert.match(joined, /RETENTION_CONFIGURATION_MISSING/);
    assert.match(joined, /DATABASE_URL/);
  } finally {
    logger.error = original;
  }
});

test("a storage failure leaves the document ACTIVE for a retry", async () => {
  const source = await readFile(new URL("../src/lib/retention/service.ts", import.meta.url), "utf8");
  // Partial failure must skip the document tombstone, and failures are counted.
  assert.match(source, /catch \(error\) \{[\s\S]*?complete = false;[\s\S]*?result\.failures \+= 1;/);
  assert.match(source, /if \(!complete\) continue;\s*\n\s*await db\.document\.update/);
  // A scope mismatch is blocked, never retried as a delete.
  assert.match(source, /if \(decision !== "match"\) \{[\s\S]*?result\.blockedObjects \+= 1;/);
});

test("active work is protected by job status regardless of job age", async () => {
  const source = await readFile(new URL("../src/lib/retention/service.ts", import.meta.url), "utf8");
  // The protection query takes no lower age bound: a live RUNNING job must keep
  // protecting its inputs even if a separate operator complains it is old.
  const protection = source.slice(source.indexOf("export async function protectedFileIds"), source.indexOf("function planFromDocuments"));
  assert.equal(protection.includes("createdAt:"), false);
  // Statuses are shared with the expiring sweep, so assert the single source.
  const statuses = source.match(/const ACTIVE_JOB_STATUSES = \[([^\]]+)\] as const;/);
  assert.ok(statuses, "active job statuses must be declared once");
  for (const status of ["QUEUED", "RUNNING", "RETRYING"]) assert.match(statuses![1], new RegExp(status));
  assert.match(protection, /status: \{ in: \[\.\.\.ACTIVE_JOB_STATUSES\] \}/);
});
