import { db } from "@/lib/db";
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
};

export type RetentionCleanupInput = {
  now?: Date;
  /** Defaults to dry-run: retention is only destructive when explicitly applied. */
  dryRun?: boolean;
  storage?: ObjectStorage;
  /** Configured storage scope; resolved from STORAGE_BUCKET when omitted. */
  scope?: RetentionScope;
};

const ACTIVE_JOB_STATUSES = ["QUEUED", "RUNNING", "RETRYING"] as const;
/** Grace window before an abandoned job counts as terminal work. */
export const EXPIRED_JOB_GRACE_MS = 86_400_000;

type LoadedDocuments = Awaited<ReturnType<typeof loadDocuments>>;

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


function loadDocuments(now: Date) {
  return db.document.findMany({
    where: { status: "ACTIVE" },
    include: {
      files: { include: { storageObject: true }, orderBy: { createdAt: "asc" } },
      user: {
        include: {
          subscriptions: {
            where: {
              status: { in: ["ACTIVE", "TRIALING"] },
              startsAt: { lte: now },
              OR: [{ currentPeriodEnd: null }, { currentPeriodEnd: { gt: now } }],
            },
            include: { plan: true },
            orderBy: { createdAt: "desc" },
            take: 1,
          },
        },
      },
    },
  });
}

/**
 * Files referenced by live jobs must never be deleted. Jobs are read without a
 * lower age bound: a stale QUEUED/RUNNING/RETRYING row still represents work
 * that has not reached a terminal state, so expiring it in the same sweep must
 * not also release its inputs for deletion.
 */
export async function protectedFileIds(): Promise<Set<string>> {
  const activeJobs = await db.job.findMany({
    where: { status: { in: [...ACTIVE_JOB_STATUSES] } },
    select: { inputFileId: true, outputFileId: true, params: true },
  });
  const protectedIds = new Set<string>();
  for (const job of activeJobs) {
    if (job.inputFileId) protectedIds.add(job.inputFileId);
    if (job.outputFileId) protectedIds.add(job.outputFileId);
    const ids = (job.params as { inputFileIds?: unknown })?.inputFileIds;
    if (Array.isArray(ids)) for (const id of ids) if (typeof id === "string") protectedIds.add(id);
  }
  return protectedIds;
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
  documents: LoadedDocuments;
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

async function buildPlan(now: Date, scope: RetentionScope) {
  const documents = await loadDocuments(now);
  const plan = planFromDocuments({ now, scope, protectedIds: await protectedFileIds(), documents });
  return { plan, documents };
}

/**
 * Plan a retention sweep. Strictly read-only: no document, file, storage object
 * or job row is written, and the object store is never called.
 */
export async function planRetentionCleanup(input: { now?: Date; scope?: RetentionScope } = {}): Promise<RetentionPlan> {
  const scope = input.scope ?? configuredRetentionScope(process.env);
  const now = input.now ?? new Date();
  const { plan } = await buildPlan(now, scope);
  logger.info("retention.scanned", summaryLogContext(buildRetentionSummary({ plan, expiredJobs: 0 })));
  return plan;
}

/**
 * Run the retention sweep.
 *
 * `dryRun` is the default. A dry-run only reads and reports aggregate counts: it
 * never expires jobs, tombstones documents or deletes objects. Apply mode
 * deletes storage first, then tombstones metadata, and refuses any object whose
 * provider/bucket does not match the configured storage scope.
 */
export async function runRetentionCleanup(input: RetentionCleanupInput = {}): Promise<CleanupResult> {
  const now = input.now ?? new Date();
  const dryRun = input.dryRun ?? true;
  const scope = input.scope ?? configuredRetentionScope(process.env);
  const storage = input.storage ?? getStorage();

  const { plan, documents } = await buildPlan(now, scope);
  const result: CleanupResult = {
    scanned: plan.scannedDocuments,
    candidateDocuments: plan.candidateDocuments,
    candidateFiles: plan.candidateFiles,
    deletedObjects: 0,
    deletedDocuments: 0,
    failures: 0,
    blockedObjects: 0,
    dryRun,
  };

  // The summary is aggregate-only and shared by both modes, so a dry-run and an
  // apply run report the same candidate counts.
  const summary = buildRetentionSummary({ plan, expiredJobs: 0 });
  const logContext = summaryLogContext(summary);
  logger.info(dryRun ? "retention.dry_run" : "retention.apply_started", logContext);
  if (dryRun) {
    recordMetric("cleanup_candidates_total", plan.candidateDocuments, "count", { mode: "dry_run" });
    logger.info("retention.dry_run_completed", { ...logContext, deleted: 0 });
    return result;
  }

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
        await storage.deleteObject(object.objectKey);
        await db.storageObject.update({ where: { id: object.storageObjectId }, data: { deletedAt: now } });
        result.deletedObjects += 1;
      } catch (error) {
        complete = false;
        result.failures += 1;
        recordMetric("cleanup_failure_total", 1, "count", { status: "failed" });
        logger.error("retention.storage_delete_failed", { storage_object_id: object.storageObjectId, error_code: error instanceof Error ? error.name : "UNKNOWN" });
      }
    }
    if (!complete) continue;
    await db.document.update({ where: { id: deletion.documentId }, data: { status: "DELETED" } });
    result.deletedDocuments += 1;
  }

  logger.info("retention.completed", {
    scanned: result.scanned,
    deleted_objects: result.deletedObjects,
    deleted_documents: result.deletedDocuments,
    failures: result.failures,
    blocked_objects: result.blockedObjects,
    policy_version: summary.policyVersion,
    retention_days_free: summary.retentionDays.FREE,
    retention_days_pro: summary.retentionDays.PRO,
  });
  return result;
}

export { parseRetentionApply };
export type { RetentionFileSkipReason };
