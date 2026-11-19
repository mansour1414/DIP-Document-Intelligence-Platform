import { retentionPolicy } from "./config";
import type { PlanCode } from "@/lib/entitlements/policy";

/**
 * Small, dependency-free retention safety primitives.
 *
 * These are deliberately pure so the scheduler's guards can be proven without a
 * database, object store or network. Two rules matter most:
 *   1. Dry-run never mutates, so the planner only ever produces a description.
 *   2. A delete is only issued when the stored object is provably addressable in
 *      the configured storage (same provider, same bucket). Otherwise a delete
 *      would either hit the wrong bucket or "succeed" against a key that lives
 *      somewhere the adapter cannot reach.
 */

const DAY_MS = 86_400_000;

/** Variables that must be configured before the scheduler may run at all. */
export const RETENTION_REQUIRED_CREDENTIALS = [
  "DATABASE_URL",
  "STORAGE_ENDPOINT",
  "STORAGE_BUCKET",
  "STORAGE_ACCESS_KEY",
  "STORAGE_SECRET_KEY",
] as const;

export type RetentionCredential = (typeof RETENTION_REQUIRED_CREDENTIALS)[number];

/** NAMES only. Never include values, so the result is safe to log and report. */
export function missingRetentionCredentials(env: Record<string, string | undefined>): RetentionCredential[] {
  return RETENTION_REQUIRED_CREDENTIALS.filter((name) => !env[name]?.trim());
}

/**
 * Apply is opt-in and strict: only the exact string "1" enables deletions.
 * Anything else (unset, "", "true", "0") resolves to dry-run.
 */
export function parseRetentionApply(value: string | undefined): boolean {
  return value === "1";
}

// The `s3` provider id is fixed by the storage adapter: every S3-compatible
// backend (Neon Object Storage, R2, MinIO, AWS) is registered as `s3` on write.
export const RETENTION_STORAGE_PROVIDER = "s3";

export type RetentionScope = { provider: string; bucket: string };

/** The single storage scope a scheduled delete is allowed to touch. */
export function configuredRetentionScope(env: Record<string, string | undefined>): RetentionScope {
  const bucket = env.STORAGE_BUCKET?.trim();
  if (!bucket) throw new Error("RETENTION_STORAGE_SCOPE_UNCONFIGURED");
  return { provider: RETENTION_STORAGE_PROVIDER, bucket };
}

export type RetentionStorageObject = { provider: string; bucket: string; objectKey: string };
export type RetentionScopeDecision = "match" | "provider_mismatch" | "bucket_mismatch";

export function classifyStorageScope(object: RetentionStorageObject, scope: RetentionScope): RetentionScopeDecision {
  if (object.provider !== scope.provider) return "provider_mismatch";
  if (object.bucket !== scope.bucket) return "bucket_mismatch";
  return "match";
}

export type RetentionFileFacts = {
  fileId: string;
  createdAt: Date;
  storageObject?: {
    id: string;
    provider: string;
    bucket: string;
    objectKey: string;
    deletedAt: Date | null;
  } | null;
};

export type RetentionDocumentFacts = {
  documentId: string;
  /**
   * Plan code governing this document's retention period. Resolved from the
   * user's active subscription before planning; a missing or unknown
   * subscription falls back to FREE.
   */
  plan?: PlanCode;
  files: RetentionFileFacts[];
};

export type RetentionPlanInput = {
  now: Date;
  /**
   * Per-plan retention periods. Each document is evaluated against its own
   * plan, so a PRO document keeps the full PRO period instead of inheriting a
   * shorter FREE period.
   */
  retentionDays: Record<PlanCode, number>;
  scope: RetentionScope;
  /** File ids referenced by QUEUED/RUNNING/RETRYING jobs or their params. */
  protectedFileIds: ReadonlySet<string>;
  documents: RetentionDocumentFacts[];
};

export type RetentionFileSkipReason =
  | "retained"
  | "protected_by_active_job"
  | "missing_storage_object"
  | "provider_mismatch"
  | "bucket_mismatch";

export type PlannedDeletion = {
  documentId: string;
  /** Objects to delete, in order. Empty when every object is already tombstoned. */
  objects: Array<{ storageObjectId: string; objectKey: string }>;
  /** Objects already tombstoned; only metadata needs updating. */
  alreadyDeleted: number;
  /** Number of files covered by this document. Never an id, name or key. */
  fileCount: number;
};

export type RetentionPlan = {
  deletions: PlannedDeletion[];
  /** Retention period applied per plan code, included in the audit summary. */
  retentionDays: Record<PlanCode, number>;
  /** Candidate documents per plan, so a regression in one tier is visible. */
  candidatesByPlan: Record<PlanCode, number>;
  /** Counts only. No titles, filenames or object keys are reported. */
  scannedDocuments: number;
  candidateDocuments: number;
  candidateFiles: number;
  alreadyDeletedFiles: number;
  retainedFiles: number;
  protectedFiles: number;
  missingObjectFiles: number;
  scopeBlockedFiles: number;
  skippedDocuments: number;
  skipReasons: Record<RetentionFileSkipReason, number>;
};

const emptySkipReasons = (): Record<RetentionFileSkipReason, number> => ({
  retained: 0,
  protected_by_active_job: 0,
  missing_storage_object: 0,
  provider_mismatch: 0,
  bucket_mismatch: 0,
});

/**
 * Decide, without touching any dependency, what a sweep would do.
 *
 * A document is a deletion candidate only when every one of its files is past
 * the plan retention cutoff, referenced by no active job, and backed by a
 * storage object inside the configured scope. Anything else skips the document
 * and is counted, which is what makes the dry-run preview trustworthy.
 *
 * An object that is already tombstoned (`deletedAt` set) does not block the
 * document: it is counted as already deleted so a retried sweep can finish the
 * metadata update without issuing a second storage call.
 */
export function planRetention(input: RetentionPlanInput): RetentionPlan {
  // Every plan period must be a positive integer; a bad period is a policy bug,
  // not something to silently clamp.
  for (const days of Object.values(input.retentionDays)) {
    if (!Number.isInteger(days) || days < 1) throw new Error("RETENTION_POLICY_INVALID");
  }
  const nowMs = input.now.getTime();
  const cutoffFor = (code: PlanCode) => nowMs - input.retentionDays[code] * DAY_MS;
  const plan: RetentionPlan = {
    deletions: [],
    retentionDays: { ...input.retentionDays },
    candidatesByPlan: { FREE: 0, PRO: 0 },
    scannedDocuments: input.documents.length,
    candidateDocuments: 0,
    candidateFiles: 0,
    alreadyDeletedFiles: 0,
    retainedFiles: 0,
    protectedFiles: 0,
    missingObjectFiles: 0,
    scopeBlockedFiles: 0,
    skippedDocuments: 0,
    skipReasons: emptySkipReasons(),
  };

  for (const document of input.documents) {
    if (!document.files.length) {
      plan.skippedDocuments += 1;
      continue;
    }

    // The document's own plan decides its cutoff. Defaulting to FREE keeps the
    // historical behaviour for documents whose subscription cannot be resolved.
    const planCode: PlanCode = document.plan ?? "FREE";
    const cutoff = cutoffFor(planCode);

    const objects: PlannedDeletion["objects"] = [];
    let alreadyDeleted = 0;
    let skip: RetentionFileSkipReason | undefined;

    for (const file of document.files) {
      if (file.createdAt.getTime() >= cutoff) skip = "retained";
      else if (input.protectedFileIds.has(file.fileId)) skip = "protected_by_active_job";
      else if (!file.storageObject) skip = "missing_storage_object";
      else {
        const scope = classifyStorageScope(file.storageObject, input.scope);
        if (scope !== "match") skip = scope;
      }
      if (skip) break;

      const object = file.storageObject!;
      if (object.deletedAt) alreadyDeleted += 1;
      else objects.push({ storageObjectId: object.id, objectKey: object.objectKey });
    }

    if (skip) {
      plan.skippedDocuments += 1;
      plan.skipReasons[skip] += 1;
      if (skip === "retained") plan.retainedFiles += 1;
      else if (skip === "protected_by_active_job") plan.protectedFiles += 1;
      else if (skip === "missing_storage_object") plan.missingObjectFiles += 1;
      else plan.scopeBlockedFiles += 1;
      continue;
    }

    plan.candidateDocuments += 1;
    plan.candidatesByPlan[planCode] += 1;
    plan.candidateFiles += document.files.length;
    plan.alreadyDeletedFiles += alreadyDeleted;
    plan.deletions.push({ documentId: document.documentId, objects, alreadyDeleted, fileCount: document.files.length });
  }

  return plan;
}

/** Aggregate, content-free summary. Safe to log and safe to return to a scheduler. */
export type RetentionSummary = {
  policyVersion: string;
  /** Periods the sweep actually applied, per plan. */
  retentionDays: Record<PlanCode, number>;
  scannedDocuments: number;
  candidateDocuments: number;
  candidateDocumentsByPlan: Record<PlanCode, number>;
  candidateFiles: number;
  alreadyDeletedFiles: number;
  retainedFiles: number;
  protectedFiles: number;
  missingObjectFiles: number;
  scopeBlockedFiles: number;
  skippedDocuments: number;
  expiredJobs: number;
};

export function buildRetentionSummary(input: { plan: RetentionPlan; expiredJobs: number }): RetentionSummary {
  return {
    policyVersion: retentionPolicy.version,
    retentionDays: input.plan.retentionDays,
    scannedDocuments: input.plan.scannedDocuments,
    candidateDocuments: input.plan.candidateDocuments,
    candidateDocumentsByPlan: input.plan.candidatesByPlan,
    candidateFiles: input.plan.candidateFiles,
    alreadyDeletedFiles: input.plan.alreadyDeletedFiles,
    retainedFiles: input.plan.retainedFiles,
    protectedFiles: input.plan.protectedFiles,
    missingObjectFiles: input.plan.missingObjectFiles,
    scopeBlockedFiles: input.plan.scopeBlockedFiles,
    skippedDocuments: input.plan.skippedDocuments,
    expiredJobs: input.expiredJobs,
  };
}
