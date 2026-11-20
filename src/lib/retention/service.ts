import { getStorage, type ObjectStorage } from "@/lib/storage";
import { approvedRetentionDays, currentPlanCode } from "./plan";
import { logger } from "@/lib/logging";
import { recordMetric } from "@/lib/observability/metrics";
import {
  buildRetentionSummary,
  classifyStorageScope,
  configuredRetentionScope,
  parseRetentionApply,
  planRetention,
  type RetentionPlan,
  type RetentionScope,
  type RetentionFileSkipReason,
} from "./safety";
import { prismaRetentionRepository, type RetentionDocumentRow, type RetentionRepository } from "./repository";
import type { PlanCode } from "@/lib/entitlements/policy";

export type CleanupResult = {
  scanned: number;
  candidateDocuments: number;
  candidateFiles: number;
  deletedObjects: number;
  deletedDocuments: number;
  failures: number;
  blockedObjects: number;
  dryRun: boolean;
  /** Object-store calls issued. Always 0 in a dry-run; proven by test. */
  storageOperations: number;
  /** PostgreSQL rows written (object tombstones + document tombstones). Always 0 in a dry-run. */
  metadataMutations: number;
};

export type RetentionCleanupInput = {
  now?: Date;
  /** Defaults to dry-run: retention is only destructive when explicitly applied. */
  dryRun?: boolean;
  /** Apply-only. A dry-run must never be handed an object store, and never resolves one. */
  storage?: ObjectStorage;
  /**
   * Apply-only storage factory, used when `storage` is omitted.
   *
   * Exists so a dry-run can be proven independent of S3 client construction: an
   * injected factory that throws must never be reached.
   */
  resolveStorage?: () => ObjectStorage;
  /** Configured storage scope; resolved from STORAGE_BUCKET when omitted. */
  scope?: RetentionScope;
  /** Data-access port. Defaults to the Prisma implementation. */
  repository?: RetentionRepository;
};

/** Grace window before an abandoned job counts as terminal work. */
export const EXPIRED_JOB_GRACE_MS = 86_400_000;

/**
 * Files referenced by live jobs. Re-exported for callers that need the same
 * protection set the sweep uses; the query itself lives in `repository.ts`.
 */
export async function protectedFileIds(repository: RetentionRepository = prismaRetentionRepository): Promise<Set<string>> {
  return repository.loadProtectedFileIds();
}

/**
 * LogContext is a flat record, and nested per-plan maps must not be silently
 * dropped. Flatten them into explicit scalars so a plan regression is visible
 * in logs and dashboards.
 */
function summaryLogContext(summary: ReturnType<typeof buildRetentionSummary>) {
  return {
    policy_version: summary.policyVersion,
    retention_days_free: summary.retentionDays.FREE,
    retention_days_pro: summary.retentionDays.PRO,
    scanned_documents: summary.scannedDocuments,
    candidate_documents: summary.candidateDocuments,
    candidate_documents_free: summary.candidateDocumentsByPlan.FREE,
    candidate_documents_pro: summary.candidateDocumentsByPlan.PRO,
    candidate_files: summary.candidateFiles,
    retained_files: summary.retainedFiles,
    protected_files: summary.protectedFiles,
    scope_blocked_files: summary.scopeBlockedFiles,
    missing_object_files: summary.missingObjectFiles,
    already_deleted_files: summary.alreadyDeletedFiles,
  };
}

/**
 * Approved per-plan input retention periods. Each document is evaluated against
 * its own plan: a PRO document keeps 30 days and is never truncated to the
 * shorter FREE period.
 */
export function retentionDaysByPlan(): Record<PlanCode, number> {
  return approvedRetentionDays();
}

function planFromDocuments(options: {
  now: Date;
  scope: RetentionScope;
  protectedIds: ReadonlySet<string>;
  documents: ReadonlyArray<RetentionDocumentRow>;
}): RetentionPlan {
  return planRetention({
    now: options.now,
    retentionDays: retentionDaysByPlan(),
    scope: options.scope,
    protectedFileIds: options.protectedIds,
    documents: options.documents.map((document) => ({
      documentId: document.id,
      plan: currentPlanCode(document.user.subscriptions),
      files: document.files.map((file) => ({
        fileId: file.id,
        createdAt: file.createdAt,
        storageObject: file.storageObject,
      })),
    })),
  });
}

async function buildPlan(now: Date, scope: RetentionScope, repository: RetentionRepository) {
  const documents = await repository.loadActiveDocuments(now);
  const plan = planFromDocuments({ now, scope, protectedIds: await repository.loadProtectedFileIds(), documents });
  return { plan, documents };
}

/**
 * Plan a retention sweep. Strictly read-only: no document, file, storage object
 * or job row is written, and the object store is never called.
 */
export async function planRetentionCleanup(
  input: { now?: Date; scope?: RetentionScope; repository?: RetentionRepository } = {},
): Promise<RetentionPlan> {
  const scope = input.scope ?? configuredRetentionScope(process.env);
  const now = input.now ?? new Date();
  const { plan } = await buildPlan(now, scope, input.repository ?? prismaRetentionRepository);
  logger.info("retention.scanned", summaryLogContext(buildRetentionSummary({ plan, expiredJobs: 0 })));
  return plan;
}

/**
 * Run the retention sweep.
 *
 * `dryRun` is the default. A dry-run only reads and reports aggregate counts: it
 * never expires jobs, tombstones documents or deletes objects, and it never
 * constructs the object-storage client — so it needs no S3 write/delete
 * credential. Storage-scope validation stays fully enforced because it compares
 * the `provider`/`bucket` recorded in PostgreSQL metadata against the configured
 * scope, without contacting the object store.
 *
 * Apply mode resolves the object store, deletes storage first, then tombstones
 * metadata, and refuses any object whose provider/bucket does not match the
 * configured storage scope.
 */
export async function runRetentionCleanup(input: RetentionCleanupInput = {}): Promise<CleanupResult> {
  return (await runRetentionSweep(input)).result;
}

/**
 * The sweep itself, returning both the plan and the outcome.
 *
 * A dry-run needs the full plan for its aggregate diagnostics (per-plan
 * candidates and skip reasons); re-running the document query to obtain them
 * would double the cost of the most expensive read in the system. The plan is
 * never logged — only its aggregate counts are.
 */
export async function runRetentionSweep(input: RetentionCleanupInput = {}): Promise<{ plan: RetentionPlan; result: CleanupResult }> {
  const now = input.now ?? new Date();
  const dryRun = input.dryRun ?? true;
  const scope = input.scope ?? configuredRetentionScope(process.env);
  const repository = input.repository ?? prismaRetentionRepository;

  const { plan, documents } = await buildPlan(now, scope, repository);
  const result: CleanupResult = {
    scanned: plan.scannedDocuments,
    candidateDocuments: plan.candidateDocuments,
    candidateFiles: plan.candidateFiles,
    deletedObjects: 0,
    deletedDocuments: 0,
    failures: 0,
    blockedObjects: 0,
    dryRun,
    storageOperations: 0,
    metadataMutations: 0,
  };

  // The summary is aggregate-only and shared by both modes, so a dry-run and an
  // apply run report the same candidate counts.
  const summary = buildRetentionSummary({ plan, expiredJobs: 0 });
  const logContext = summaryLogContext(summary);
  logger.info(dryRun ? "retention.dry_run" : "retention.apply_started", logContext);
  if (dryRun) {
    // Strictly read-only: no object store, no metadata write, no job expiry.
    recordMetric("cleanup_candidates_total", plan.candidateDocuments, "count", { mode: "dry_run" });
    logger.info("retention.dry_run_completed", {
      ...logContext,
      deleted: 0,
      storage_operations: 0,
      metadata_mutations: 0,
    });
    return { plan, result };
  }

  // Apply only. Prove the write path exists before touching the object store, so
  // a read-only repository fails closed without deleting objects whose tombstone
  // could never be recorded — that would leave the next sweep blind.
  const markStorageObjectDeleted = repository.markStorageObjectDeleted?.bind(repository);
  const markDocumentDeleted = repository.markDocumentDeleted?.bind(repository);
  if (!markStorageObjectDeleted || !markDocumentDeleted) throw new Error("RETENTION_REPOSITORY_READ_ONLY");

  // Resolve the object store here, never earlier: a dry-run must not even
  // construct an S3 client, and therefore needs no S3 credential.
  const storage = input.storage ?? (input.resolveStorage ?? getStorage)();

  const objectById = new Map<string, { provider: string; bucket: string; objectKey: string; deletedAt: Date | null }>();
  for (const document of documents) {
    for (const file of document.files) {
      if (file.storageObject) objectById.set(file.storageObject.id, file.storageObject);
    }
  }

  for (const deletion of plan.deletions) {
    let complete = true;
    for (const object of deletion.objects) {
      const stored = objectById.get(object.storageObjectId);
      const decision = stored ? classifyStorageScope(stored, scope) : "provider_mismatch";
      if (decision !== "match") {
        // Never issue a delete for an object we cannot prove belongs to the
        // configured bucket. The document stays ACTIVE and is retried later.
        complete = false;
        result.blockedObjects += 1;
        recordMetric("cleanup_scope_blocked_total", 1, "count", { reason: decision });
        logger.warn("retention.storage_scope_blocked", { storage_object_id: object.storageObjectId, reason: decision });
        continue;
      }
      try {
        result.storageOperations += 1;
        await storage.deleteObject(object.objectKey);
        await markStorageObjectDeleted(object.storageObjectId, now);
        result.metadataMutations += 1;
        result.deletedObjects += 1;
      } catch (error) {
        complete = false;
        result.failures += 1;
        recordMetric("cleanup_failure_total", 1, "count", { status: "failed" });
        logger.error("retention.storage_delete_failed", { storage_object_id: object.storageObjectId, error_code: error instanceof Error ? error.name : "UNKNOWN" });
      }
    }
    if (!complete) continue;
    await markDocumentDeleted(deletion.documentId);
    result.metadataMutations += 1;
    result.deletedDocuments += 1;
  }

  logger.info("retention.completed", {
    scanned: result.scanned,
    deleted_objects: result.deletedObjects,
    deleted_documents: result.deletedDocuments,
    failures: result.failures,
    blocked_objects: result.blockedObjects,
    storage_operations: result.storageOperations,
    metadata_mutations: result.metadataMutations,
    policy_version: summary.policyVersion,
    retention_days_free: summary.retentionDays.FREE,
    retention_days_pro: summary.retentionDays.PRO,
  });
  return { plan, result };
}

export { parseRetentionApply };
export type { RetentionFileSkipReason };
