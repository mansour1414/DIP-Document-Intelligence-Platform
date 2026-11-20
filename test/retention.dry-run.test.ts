import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { runRetentionDryRun } from "../src/lib/retention/dry-run";
import { runRetentionCleanup } from "../src/lib/retention/service";
import { parseDryRunArgs } from "../src/lib/retention/dry-run-cli";
import { missingRetentionCredentials, type RetentionScope } from "../src/lib/retention/safety";
import type { RetentionDocumentRow, RetentionRepository } from "../src/lib/retention/repository";
import type { ObjectStorage } from "../src/lib/storage";

/**
 * Dry-run preparation contract.
 *
 * These tests are hermetic: no PostgreSQL, no Redis and no object store is
 * contacted. The point is to prove *by construction* that the read-only path
 * cannot mutate anything, rather than observing that it happened not to.
 */

const scope: RetentionScope = { provider: "s3", bucket: "dip-documents" };
const now = new Date("2026-11-20T00:00:00Z");
const expired = new Date("2026-09-01T00:00:00Z");
const fresh = new Date("2026-11-19T00:00:00Z");

/** Dry-run needs only these two; the S3 endpoint and key pair are apply-only. */
const dryRunEnv = { DATABASE_URL: "postgresql://not-used/no-db", STORAGE_BUCKET: scope.bucket };

function documentRow(options: {
  createdAt?: Date;
  bucket?: string;
  plan?: "FREE" | "PRO";
  objectKey?: string;
} = {}): RetentionDocumentRow {
  return {
    id: randomUUID(),
    user: { subscriptions: [{ plan: { code: options.plan ?? "FREE" } }] },
    files: [
      {
        id: randomUUID(),
        createdAt: options.createdAt ?? expired,
        storageObject: {
          id: randomUUID(),
          provider: "s3",
          bucket: options.bucket ?? scope.bucket,
          objectKey: options.objectKey ?? `input/tenant/${randomUUID()}.pdf`,
          deletedAt: null,
        },
      },
    ],
  };
}

/**
 * Repository whose writes throw. A dry-run that reached one would fail the test
 * with an explicit message instead of silently mutating a fixture.
 */
function fakeRepository(documents: ReadonlyArray<RetentionDocumentRow>, options: { writable?: boolean } = {}) {
  const state = { reads: 0, writes: [] as string[] };
  // Read-only by default: a dry-run that reached a write fails loudly instead of
  // silently mutating a fixture. Apply tests opt in explicitly.
  const onWrite = (name: string) => {
    state.writes.push(name);
    if (!options.writable) throw new Error(`dry-run must never ${name}`);
  };
  const repository: RetentionRepository = {
    async loadActiveDocuments() {
      state.reads += 1;
      return documents;
    },
    async loadProtectedFileIds() {
      state.reads += 1;
      return new Set<string>();
    },
    async markStorageObjectDeleted() {
      onWrite("markStorageObjectDeleted");
    },
    async markDocumentDeleted() {
      onWrite("markDocumentDeleted");
    },
  };
  return { repository, state };
}

function countingStorage() {
  const calls: string[] = [];
  const storage: ObjectStorage = {
    createUploadKey: () => "",
    put: async () => {
      calls.push("put");
      return { key: "", bucket: "", contentType: "", size: 0 };
    },
    get: async () => {
      calls.push("get");
      return new Uint8Array();
    },
    head: async () => {
      calls.push("head");
      return undefined;
    },
    exists: async () => {
      calls.push("exists");
      return false;
    },
    deleteObject: async () => {
      calls.push("deleteObject");
    },
    close: async () => undefined,
  };
  return { storage, calls };
}

/** A candidate the policy WOULD expire if queue evidence said `absent`. */
const staleCandidate = {
  id: "11111111-1111-4111-8111-111111111111",
  status: "QUEUED" as const,
  createdAt: new Date(now.getTime() - 5 * 86_400_000),
  startedAt: null,
  updatedAt: new Date(now.getTime() - 3 * 86_400_000),
  completedAt: null,
};

// ---------------------------------------------------------------------------
// Requirement: dry-run is independent of the object store
// ---------------------------------------------------------------------------

test("dry-run succeeds with no S3 endpoint, access key or secret key configured", async () => {
  const { repository, state } = fakeRepository([documentRow()]);
  const report = await runRetentionDryRun({
    now,
    env: dryRunEnv,
    scope,
    repository,
    loadCandidates: async () => [],
  });

  assert.equal(report.mode, "dry_run");
  assert.equal(report.candidates.candidate_documents, 1, "the expired document is still planned");
  assert.equal(report.mutations.storage_operations, 0);
  assert.equal(report.mutations.metadata_mutations, 0);
  assert.equal(report.zero_mutations, true);
  assert.deepEqual(state.writes, [], "no PostgreSQL write may be attempted");
  assert.ok(state.reads > 0, "the planner must still read");
});

test("the dry-run path never resolves an object store, while apply does", async () => {
  const { repository } = fakeRepository([documentRow()]);
  const boom = () => {
    throw new Error("object storage must not be resolved by a dry-run");
  };

  // Dry-run: the factory is never reached.
  const preview = await runRetentionCleanup({ now, dryRun: true, scope, repository, resolveStorage: boom });
  assert.equal(preview.dryRun, true);
  assert.equal(preview.storageOperations, 0);
  assert.equal(preview.metadataMutations, 0);

  // Apply still resolves it, which is what makes the assertion above meaningful.
  await assert.rejects(
    () => runRetentionCleanup({ now, dryRun: false, scope, repository, resolveStorage: boom }),
    /object storage must not be resolved/,
  );
});

test("dry-run performs zero storage operations and zero PostgreSQL mutations", async () => {
  const { repository, state } = fakeRepository([
    documentRow(),
    documentRow({ createdAt: fresh }),
    documentRow({ bucket: "some-other-bucket" }),
  ]);
  const { storage, calls } = countingStorage();

  const report = await runRetentionDryRun({
    now,
    env: dryRunEnv,
    scope,
    repository,
    loadCandidates: async () => [],
  });

  assert.deepEqual(calls, [], "no storage call of any kind");
  assert.deepEqual(state.writes, [], "no metadata write of any kind");
  assert.equal(report.mutations.objects_deleted, 0);
  assert.equal(report.mutations.documents_tombstoned, 0);
  assert.equal(report.mutations.jobs_expired_applied, 0);
  assert.equal(report.mutations.storage_operations, 0);
  assert.equal(report.mutations.metadata_mutations, 0);
  assert.equal(report.zero_mutations, true);
  // Sanity: candidate counting still works, so the run is not trivially empty.
  assert.equal(report.candidates.candidate_documents, 1);
  assert.equal(report.candidates.scanned_documents, 3);
  assert.equal(report.candidates.scope_blocked_files, 1);
  assert.equal(report.candidates.retained_files, 1);

  // A storage instance passed to the apply path is never touched by a dry-run.
  await storage.close();
});

// ---------------------------------------------------------------------------
// Requirement: dry-run rejects destructive intent
// ---------------------------------------------------------------------------

test("RETENTION_APPLY=1 aborts a dry-run before any dependency is touched", async () => {
  const { repository, state } = fakeRepository([documentRow()]);
  await assert.rejects(
    () => runRetentionDryRun({ now, env: { ...dryRunEnv, RETENTION_APPLY: "1" }, scope, repository }),
    /RETENTION_APPLY_FORBIDDEN_IN_DRY_RUN/,
  );
  assert.equal(state.reads, 0, "the refusal must happen before any read");
  assert.deepEqual(state.writes, []);
});

test("the dry-run entrypoint rejects apply-shaped arguments", () => {
  for (const argument of ["--apply", "--force", "--yes", "--dry-run=false", "apply"]) {
    assert.throws(() => parseDryRunArgs([argument]), /RETENTION_DRY_RUN_ARGUMENT_REJECTED/, `${argument} must be rejected`);
  }
  assert.throws(() => parseDryRunArgs(["--summary-json"]), /RETENTION_DRY_RUN_ARGUMENT_REJECTED/);
  assert.deepEqual(parseDryRunArgs(["--summary-json=/tmp/report.json"]), { summaryJsonPath: "/tmp/report.json", help: false });
  assert.deepEqual(parseDryRunArgs(["--help"]), { help: true });
});

test("the dry-run module contains no apply path", async () => {
  const raw = await readFile(new URL("../src/lib/retention/dry-run.ts", import.meta.url), "utf8");
  // Strip comments: documentation *about* apply must not be mistaken for the code.
  const source = raw.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
  assert.match(source, /dryRun: true/, "the sweep mode is a literal, not a parameter");
  assert.equal(/dryRun:\s*false/.test(source), false, "the dry-run module must not be able to apply");
  assert.equal(/import[^;]*expireStalledJobs/.test(source), false, "job expiry application is never imported here");
  assert.equal(/applyExpiryPlan/.test(source), false, "the expiry write port is never imported here");
  assert.equal(/deleteObject/.test(source), false, "no object deletion is reachable from this module");
  assert.match(source, /mode: "plan"/);
  assert.match(source, /assertDryRunAllowed\(env\)/);
});

// ---------------------------------------------------------------------------
// Requirement: dry-run configuration is mode-aware
// ---------------------------------------------------------------------------

test("dry-run requires DATABASE_URL and STORAGE_BUCKET only", async () => {
  const { repository, state } = fakeRepository([documentRow()]);
  assert.deepEqual(missingRetentionCredentials(dryRunEnv, "dry_run"), []);
  // Apply keeps its full, fail-closed requirement.
  assert.deepEqual(missingRetentionCredentials(dryRunEnv, "apply"), [
    "STORAGE_ENDPOINT",
    "STORAGE_ACCESS_KEY",
    "STORAGE_SECRET_KEY",
  ]);

  await assert.rejects(
    () => runRetentionDryRun({ now, env: { DATABASE_URL: "postgresql://not-used/no-db" }, scope, repository }),
    (error: Error) => {
      assert.match(error.message, /^RETENTION_CONFIGURATION_MISSING:STORAGE_BUCKET$/);
      assert.equal(error.message.includes("STORAGE_ACCESS_KEY"), false, "dry-run must not require S3 keys");
      return true;
    },
  );
  assert.equal(state.reads, 0);
});

test("storage scope is still enforced from metadata, with no object store involved", async () => {
  const { repository } = fakeRepository([documentRow({ bucket: "release-b-archive" })]);
  const report = await runRetentionDryRun({
    now,
    env: { DATABASE_URL: "postgresql://not-used/no-db", STORAGE_BUCKET: "dip-documents" },
    repository,
    loadCandidates: async () => [],
  });
  assert.equal(report.candidates.candidate_documents, 0, "a wrong-bucket document is never a candidate");
  assert.equal(report.candidates.scope_blocked_files, 1);
});

// ---------------------------------------------------------------------------
// Requirement: missing / unavailable Redis is UNKNOWN, never expiry
// ---------------------------------------------------------------------------

test("an unconfigured queue reports unknown evidence and plans no expiry", async () => {
  const { repository } = fakeRepository([]);
  const report = await runRetentionDryRun({
    now,
    env: dryRunEnv,
    scope,
    repository,
    loadCandidates: async () => [staleCandidate],
    queueUnavailable: "not_configured",
  });

  assert.equal(report.redis.redis_configured, false);
  assert.equal(report.redis.unavailable, "not_configured");
  assert.equal(report.redis.connectivity, "UNAVAILABLE");
  assert.equal(report.redis.queue_evidence, "UNAVAILABLE");
  assert.equal(report.redis.reads_attempted, 0, "nothing was configured, so nothing was read");
  assert.equal(report.queue.queue_unknown, 1, "the candidate's liveness is unknown, not absent");
  assert.equal(report.queue.planned_expiry, 0, "unknown evidence must never authorise expiry");
  assert.equal(report.mutations.jobs_expired_applied, 0);
  assert.equal(report.zero_mutations, true);
});

test("an unreachable queue is also unknown, never expiry", async () => {
  const { repository } = fakeRepository([]);
  const failingProvider = {
    unavailable: "error" as const,
    async read() {
      throw new Error("connection refused");
    },
    async probe() {
      return "UNAVAILABLE" as const;
    },
    async close() {},
  };
  const report = await runRetentionDryRun({
    now,
    env: dryRunEnv,
    scope,
    repository,
    loadCandidates: async () => [staleCandidate],
    evidence: failingProvider,
  });
  assert.equal(report.redis.redis_configured, false);
  assert.equal(report.queue.queue_unknown, 1);
  assert.equal(report.queue.planned_expiry, 0);
});

test("a complete empty queue read is the only way absence is concluded (still no expiry in a dry-run)", async () => {
  const { repository } = fakeRepository([]);
  const bothQueuesEmpty = {
    async read() {
      return [
        { present: new Map(), ok: true },
        { present: new Map(), ok: true },
      ];
    },
    async close() {},
    async probe() {
      return "VERIFIED" as const;
    },
  };
  const report = await runRetentionDryRun({
    now,
    env: dryRunEnv,
    scope,
    repository,
    loadCandidates: async () => [staleCandidate],
    evidence: bothQueuesEmpty,
  });
  assert.equal(report.redis.redis_configured, true);
  assert.equal(report.redis.connectivity, "VERIFIED");
  assert.equal(report.redis.queue_evidence, "VERIFIED");
  assert.equal(report.redis.reads_attempted, 2);
  assert.equal(report.redis.queues_read, 2);
  assert.equal(report.redis.failed_reads, 0);
  assert.equal(report.queue.queue_unknown, 0);
  // The plan may now identify a stale job, but a dry-run still applies nothing.
  assert.equal(report.queue.planned_expiry, 1);
  assert.equal(report.mutations.jobs_expired_applied, 0);
  assert.equal(report.mutations.metadata_mutations, 0);
});

test("a partial read is INCOMPLETE and never reported as verified", async () => {
  const { repository } = fakeRepository([]);
  const partial = {
    async read() {
      // Two queues expected; one answered. The second could have held the job.
      return [
        { present: new Map(), ok: true },
        { present: new Map(), ok: false },
      ];
    },
    async probe() {
      return "VERIFIED" as const;
    },
    async close() {},
  };
  const report = await runRetentionDryRun({
    now,
    env: dryRunEnv,
    scope,
    repository,
    loadCandidates: async () => [staleCandidate],
    evidence: partial,
  });
  assert.equal(report.redis.connectivity, "VERIFIED");
  assert.equal(report.redis.queue_evidence, "INCOMPLETE", "a failed read must never read as complete");
  assert.equal(report.redis.reads_attempted, 2);
  assert.equal(report.redis.queues_read, 1);
  assert.equal(report.redis.failed_reads, 1);
  assert.equal(report.queue.queue_unknown, 1);
  assert.equal(report.queue.planned_expiry, 0);
});

test("zero candidates with healthy Redis reports NOT_CHECKED evidence, not a fake success", async () => {
  const { repository, state } = fakeRepository([]);
  let readCalls = 0;
  const healthy = {
    async read() {
      readCalls += 1;
      return [
        { present: new Map(), ok: true },
        { present: new Map(), ok: true },
      ];
    },
    async probe() {
      return "VERIFIED" as const;
    },
    async close() {},
  };
  const report = await runRetentionDryRun({
    now,
    env: dryRunEnv,
    scope,
    repository,
    loadCandidates: async () => [],
    evidence: healthy,
  });

  // The connection is reachable…
  assert.equal(report.redis.connectivity, "VERIFIED");
  // …but no queue was actually read, so completeness is explicitly not claimed.
  assert.equal(report.redis.queue_evidence, "NOT_CHECKED");
  assert.equal(report.redis.reads_attempted, 0);
  assert.equal(report.redis.queues_read, 0, "constructed readers are not completed reads");
  assert.equal(readCalls, 0, "a run with no candidates must not open queue reads");
  assert.equal(report.redis.candidates_scanned, 0);
  assert.equal(report.redis.queues_expected, 2);
  assert.equal(report.queue.queue_unknown, 0);
  assert.equal(report.mutations.metadata_mutations, 0);
  assert.equal(report.mutations.storage_operations, 0);
  assert.deepEqual(state.writes, [], "no write path may be reached");
});

test("zero candidates with unreachable Redis is UNAVAILABLE, never healthy", async () => {
  const { repository, state } = fakeRepository([]);
  const unreachable = {
    async read() {
      throw new Error("must not be called: there is nothing to read");
    },
    async probe() {
      return "UNAVAILABLE" as const;
    },
    async close() {},
  };
  const report = await runRetentionDryRun({
    now,
    env: dryRunEnv,
    scope,
    repository,
    loadCandidates: async () => [],
    evidence: unreachable,
  });

  // This is the regression the previous revision had: two readers were
  // constructed, so the run reported queues_read: 2 and looked healthy while
  // Redis was unreachable.
  assert.equal(report.redis.connectivity, "UNAVAILABLE");
  assert.equal(report.redis.queue_evidence, "UNAVAILABLE");
  assert.equal(report.redis.reads_attempted, 0);
  assert.equal(report.redis.queues_read, 0);
  assert.equal(report.redis.failed_reads, 0);
  assert.equal(report.zero_mutations, true);
  assert.deepEqual(state.writes, []);
});

test("a provider without a probe reports connectivity as NOT_CHECKED, never VERIFIED", async () => {
  const { repository } = fakeRepository([]);
  const noProbe = {
    async read() {
      return [
        { present: new Map(), ok: true },
        { present: new Map(), ok: true },
      ];
    },
    async close() {},
  };
  const report = await runRetentionDryRun({
    now,
    env: dryRunEnv,
    scope,
    repository,
    loadCandidates: async () => [staleCandidate],
    evidence: noProbe,
  });
  // Completing every read still proves the queues were read…
  assert.equal(report.redis.queue_evidence, "VERIFIED");
  // …but reachability was never independently measured, so it is not claimed.
  assert.equal(report.redis.connectivity, "NOT_CHECKED");
  assert.equal(report.redis.queues_read, 2);
  assert.equal(report.mutations.metadata_mutations, 0);
});

test("a partially read queue poisons the batch to unknown", async () => {
  const { repository } = fakeRepository([]);
  const partial = {
    async read() {
      return [{ present: new Map(), ok: true }];
    },
    async close() {},
    async probe() {
      return "VERIFIED" as const;
    },
  };
  const report = await runRetentionDryRun({
    now,
    env: dryRunEnv,
    scope,
    repository,
    loadCandidates: async () => [staleCandidate],
    evidence: partial,
  });
  assert.equal(report.queue.queue_unknown, 1);
  assert.equal(report.queue.planned_expiry, 0);
});

// ---------------------------------------------------------------------------
// Requirement: aggregate-only diagnostics
// ---------------------------------------------------------------------------

test("the dry-run report is aggregate-only and leaks no identifiers", async () => {
  const secretKey = "input/tenant/very-secret-object-key.pdf";
  const { repository } = fakeRepository([documentRow({ objectKey: secretKey })]);
  const { calls } = countingStorage();
  const report = await runRetentionDryRun({
    now,
    env: dryRunEnv,
    scope,
    repository,
    loadCandidates: async () => [staleCandidate],
    queueUnavailable: "not_configured",
  });

  const serialized = JSON.stringify(report);
  assert.equal(serialized.includes(secretKey), false, "object keys must never reach diagnostics");
  assert.equal(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i.test(serialized), false, "no ids");
  assert.equal(serialized.includes(staleCandidate.id), false, "no job ids");
  assert.equal(serialized.includes("postgresql://"), false, "no connection strings");
  for (const field of [
    "redis",
    "queue",
    "candidates",
    "mutations",
    "zero_mutations",
    "policy_version",
    "retention_days",
    "duration_ms",
  ]) {
    assert.ok(field in report, `missing diagnostics section: ${field}`);
  }
  assert.equal(report.policy_version, "2026-09-provisional-v2");
  assert.deepEqual(report.retention_days, { free: 7, pro: 30 }, "approved periods are unchanged");
  assert.deepEqual(calls, []);
});

// ---------------------------------------------------------------------------
// Requirement: apply stays fail-closed with every deletion safety check
// ---------------------------------------------------------------------------

test("apply refuses a read-only repository instead of deleting untracked objects", async () => {
  const readOnly: RetentionRepository = {
    async loadActiveDocuments() {
      return [documentRow()];
    },
    async loadProtectedFileIds() {
      return new Set<string>();
    },
  };
  const { storage, calls } = countingStorage();
  await assert.rejects(
    () => runRetentionCleanup({ now, dryRun: false, scope, repository: readOnly, storage }),
    /RETENTION_REPOSITORY_READ_ONLY/,
  );
  assert.deepEqual(calls, [], "no object may be deleted before the write path is known to work");
});

test("apply still blocks wrong-bucket objects and keeps the document ACTIVE", async () => {
  const { repository, state } = fakeRepository([documentRow({ bucket: "release-b-archive" })]);
  const { storage, calls } = countingStorage();
  const result = await runRetentionCleanup({ now, dryRun: false, scope, repository, storage });

  assert.equal(result.candidateDocuments, 0);
  assert.equal(result.deletedObjects, 0);
  assert.equal(result.blockedObjects, 0, "a wrong-bucket document never becomes a deletion candidate");
  assert.deepEqual(calls, []);
  assert.deepEqual(state.writes, []);
});

test("apply deletes storage before metadata and counts both", async () => {
  const { repository, state } = fakeRepository([documentRow()], { writable: true });
  const { storage, calls } = countingStorage();
  const result = await runRetentionCleanup({ now, dryRun: false, scope, repository, storage });

  assert.equal(result.deletedDocuments, 1);
  assert.equal(result.deletedObjects, 1);
  assert.equal(result.storageOperations, 1);
  assert.equal(result.metadataMutations, 2, "object tombstone + document tombstone");
  assert.deepEqual(calls, ["deleteObject"]);
  assert.deepEqual(state.writes, ["markStorageObjectDeleted", "markDocumentDeleted"]);
});

test("a failed storage delete leaves the document ACTIVE for a retry", async () => {
  const { repository, state } = fakeRepository([documentRow()]);
  const failing = countingStorage();
  failing.storage.deleteObject = async () => {
    failing.calls.push("deleteObject");
    throw new Error("storage unavailable");
  };
  const result = await runRetentionCleanup({ now, dryRun: false, scope, repository, storage: failing.storage });

  assert.equal(result.failures, 1);
  assert.equal(result.deletedObjects, 0);
  assert.equal(result.deletedDocuments, 0);
  assert.deepEqual(state.writes, [], "a failed object delete must not tombstone the document");
});
