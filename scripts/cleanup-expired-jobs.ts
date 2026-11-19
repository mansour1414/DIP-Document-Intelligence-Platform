import { db } from "@/lib/db";
import { logger } from "@/lib/logging";
import { runRetentionCleanup } from "@/lib/retention/service";
import { configuredRetentionScope, missingRetentionCredentials, parseRetentionApply } from "@/lib/retention/safety";

/** Grace window before an abandoned job is terminally expired. */
export const EXPIRY_CUTOFF_MS = 24 * 60 * 60 * 1000;

/**
 * Terminally expire jobs that never reached a worker.
 *
 * This is a mutation, so it only runs in apply mode. A dry-run must be strictly
 * read-only and must not turn a live job into an EXPIRED one.
 */
export async function expireStalledJobs(now = new Date()): Promise<number> {
  const cutoff = new Date(now.getTime() - EXPIRY_CUTOFF_MS);
  const result = await db.job.updateMany({
    where: { status: { in: ["QUEUED", "RETRYING", "RUNNING"] }, createdAt: { lt: cutoff } },
    data: { status: "EXPIRED", errorCode: "JOB_EXPIRED", completedAt: now },
  });
  logger.info("jobs.expired_cleanup", { count: result.count });
  return result.count;
}

/**
 * Scheduler entrypoint.
 *
 * - Missing credentials fail closed, before Prisma or the object store is used,
 *   and the message lists variable NAMES only.
 * - RETENTION_APPLY=1 is required for apply; anything else is a read-only
 *   dry-run, which is allowed to run and report candidate counts.
 */
async function main() {
  const missing = missingRetentionCredentials(process.env);
  if (missing.length > 0) throw new Error(`RETENTION_CONFIGURATION_MISSING:${missing.join(",")}`);

  const apply = parseRetentionApply(process.env.RETENTION_APPLY);
  const scope = configuredRetentionScope(process.env);
  const expiredJobs = apply ? await expireStalledJobs() : 0;
  logger.info("retention.mode", { apply, bucket_configured: true });

  const result = await runRetentionCleanup({ dryRun: !apply, scope });
  logger.info("retention.scheduler_result", {
    dry_run: result.dryRun,
    scanned: result.scanned,
    candidate_documents: result.candidateDocuments,
    candidate_files: result.candidateFiles,
    deleted_objects: result.deletedObjects,
    deleted_documents: result.deletedDocuments,
    failures: result.failures,
    blocked_objects: result.blockedObjects,
    expired_jobs: expiredJobs,
  });
}

main().catch((error) => {
  // Classify without ever echoing a credential value.
  const prismaCode = (error as { code?: unknown })?.code;
  const message = error instanceof Error ? error.message : "";
  const configurationMissing = message.startsWith("RETENTION_CONFIGURATION_MISSING");
  const safeCode = configurationMissing
    ? "RETENTION_CONFIGURATION_MISSING"
    : typeof prismaCode === "string" && /^P\d{4}$/.test(prismaCode) ? prismaCode : error instanceof Error ? error.name : "UNKNOWN";
  logger.error("retention.scheduler_failed", { error_code: safeCode });
  const missing = configurationMissing ? message.slice("RETENTION_CONFIGURATION_MISSING:".length).split(",") : undefined;
  if (missing) logger.error("retention.missing_configuration", { missing_variables: missing.join(",") });
  process.exitCode = 1;
}).finally(() => db.$disconnect());
