import type { CleanupResult } from "./service";
import type { QueueDiagnostics } from "./expiry-sweep";
import type { JobExpiryPlan } from "./job-expiry";
import { buildRetentionSummary, type RetentionPlan } from "./safety";

/**
 * Aggregate-only dry-run diagnostics.
 *
 * Everything here is a count, a fixed status string or a policy constant. No
 * document id, file id, object key, filename, owner, email, host, URL or
 * credential can reach this structure, which is what makes it safe to print in a
 * CI job log, store as run evidence and paste into an operations ticket.
 */

export type RetentionCandidateDiagnostics = {
  scanned_documents: number;
  candidate_documents: number;
  candidate_documents_free: number;
  candidate_documents_pro: number;
  candidate_files: number;
  already_deleted_files: number;
  /**
   * The four counters below are incremented once per **skipped document**, not
   * per file, despite the `_files` suffix inherited from the plan type. They are
   * reported unchanged so existing dashboards do not shift; read them as
   * document counts.
   */
  retained_files: number;
  protected_files: number;
  missing_object_files: number;
  scope_blocked_files: number;
  skipped_documents: number;
};

export type RetentionMutationDiagnostics = {
  /** Jobs the sweep would expire. Always 0 writes in a dry-run — this is a plan count. */
  jobs_expired_planned: number;
  jobs_expired_applied: number;
  objects_deleted: number;
  documents_tombstoned: number;
  storage_operations: number;
  metadata_mutations: number;
};

export type RetentionQueueDiagnostics = {
  planned_expiry: number;
  queue_unknown: number;
  within_grace: number;
  running_still_active: number;
  abandoned_running: number;
  stale_queue: number;
};

export type RetentionDryRunReport = {
  mode: "dry_run";
  policy_version: string;
  retention_days: { free: number; pro: number };
  redis: QueueDiagnostics;
  queue: RetentionQueueDiagnostics;
  candidates: RetentionCandidateDiagnostics;
  mutations: RetentionMutationDiagnostics;
  /** True only when every mutating counter is zero. A false value is a failure. */
  zero_mutations: boolean;
  duration_ms: number;
};

/**
 * True only when the sweep demonstrably wrote nothing.
 *
 * This is a self-check, not the proof: the proof is that a dry-run never
 * resolves a storage client, never calls a repository write method and never
 * calls `expireStalledJobs`. If any of those invariants regress, the counters
 * disagree here and the entrypoint aborts instead of reporting a clean run.
 */
export function isZeroMutation(result: CleanupResult, jobsExpiredApplied: number): boolean {
  return (
    result.dryRun === true &&
    result.deletedObjects === 0 &&
    result.deletedDocuments === 0 &&
    result.failures === 0 &&
    result.blockedObjects === 0 &&
    result.storageOperations === 0 &&
    result.metadataMutations === 0 &&
    jobsExpiredApplied === 0
  );
}

export function buildRetentionDryRunReport(input: {
  plan: RetentionPlan;
  expiryPlan: JobExpiryPlan;
  queue: QueueDiagnostics;
  result: CleanupResult;
  jobsExpiredApplied: number;
  durationMs: number;
}): RetentionDryRunReport {
  const summary = buildRetentionSummary({ plan: input.plan, expiredJobs: input.expiryPlan.counts.expired });
  const zeroMutations = isZeroMutation(input.result, input.jobsExpiredApplied);
  return {
    mode: "dry_run",
    policy_version: summary.policyVersion,
    retention_days: { free: summary.retentionDays.FREE, pro: summary.retentionDays.PRO },
    redis: input.queue,
    queue: {
      planned_expiry: input.expiryPlan.counts.expired,
      queue_unknown: input.expiryPlan.counts.queueUnknown,
      within_grace: input.expiryPlan.counts.withinGrace,
      running_still_active: input.expiryPlan.counts.runningStillActive,
      abandoned_running: input.expiryPlan.counts.abandonedRunning,
      stale_queue: input.expiryPlan.counts.staleQueue,
    },
    candidates: {
      scanned_documents: summary.scannedDocuments,
      candidate_documents: summary.candidateDocuments,
      candidate_documents_free: summary.candidateDocumentsByPlan.FREE,
      candidate_documents_pro: summary.candidateDocumentsByPlan.PRO,
      candidate_files: summary.candidateFiles,
      already_deleted_files: summary.alreadyDeletedFiles,
      retained_files: summary.retainedFiles,
      protected_files: summary.protectedFiles,
      missing_object_files: summary.missingObjectFiles,
      scope_blocked_files: summary.scopeBlockedFiles,
      skipped_documents: summary.skippedDocuments,
    },
    mutations: {
      jobs_expired_planned: input.expiryPlan.counts.expired,
      jobs_expired_applied: input.jobsExpiredApplied,
      objects_deleted: input.result.deletedObjects,
      documents_tombstoned: input.result.deletedDocuments,
      storage_operations: input.result.storageOperations,
      metadata_mutations: input.result.metadataMutations,
    },
    zero_mutations: zeroMutations,
    duration_ms: input.durationMs,
  };
}

/** Flat log context for the report. Same aggregate-only guarantees. */
export function reportLogContext(report: RetentionDryRunReport) {
  return {
    mode: report.mode,
    policy_version: report.policy_version,
    retention_days_free: report.retention_days.free,
    retention_days_pro: report.retention_days.pro,
    redis_configured: report.redis.redis_configured,
    redis_unavailable: report.redis.unavailable ?? "none",
    queues_expected: report.redis.queues_expected,
    queues_read: report.redis.queues_read,
    failed_reads: report.redis.failed_reads,
    job_candidates_scanned: report.redis.candidates_scanned,
    job_queue_unknown: report.queue.queue_unknown,
    jobs_expired_planned: report.queue.planned_expiry,
    scanned_documents: report.candidates.scanned_documents,
    candidate_documents: report.candidates.candidate_documents,
    candidate_documents_free: report.candidates.candidate_documents_free,
    candidate_documents_pro: report.candidates.candidate_documents_pro,
    candidate_files: report.candidates.candidate_files,
    retained_documents: report.candidates.retained_files,
    protected_documents: report.candidates.protected_files,
    missing_object_documents: report.candidates.missing_object_files,
    scope_blocked_documents: report.candidates.scope_blocked_files,
    storage_operations: report.mutations.storage_operations,
    metadata_mutations: report.mutations.metadata_mutations,
    objects_deleted: report.mutations.objects_deleted,
    documents_tombstoned: report.mutations.documents_tombstoned,
    zero_mutations: report.zero_mutations,
    duration_ms: report.duration_ms,
  };
}
