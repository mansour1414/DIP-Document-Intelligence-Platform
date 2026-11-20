import { db } from "@/lib/db";
import { logger } from "@/lib/logging";
import { runRetentionCleanup } from "@/lib/retention/service";
import { configuredRetentionScope, missingRetentionCredentials, parseRetentionApply } from "@/lib/retention/safety";
import { expireStalledJobs, planStalledJobExpiry } from "@/lib/retention/expiry-sweep";

/**
 * Apply-capable retention scheduler.
 *
 * The sweep itself lives in `src/lib/retention/expiry-sweep.ts`; this file is the
 * process entrypoint, the mode switch and the failure classifier. The
 * dry-run-only operator entrypoint is `scripts/retention-dry-run.ts`, which
 * refuses `RETENTION_APPLY=1` outright.
 *
 * - Missing credentials fail closed, before Prisma or the object store is used,
 *   and the message lists variable NAMES only. A dry-run requires only
 *   `DATABASE_URL` and `STORAGE_BUCKET`; apply additionally requires the three
 *   object-storage values because it constructs the storage client.
 * - `RETENTION_APPLY=1` is required for apply; anything else is a read-only
 *   dry-run that reports candidates and writes nothing.
 */

/** Compatibility re-export: the cutoff constant now lives with the sweep. */
export { EXPIRY_CUTOFF_MS } from "@/lib/retention/expiry-sweep";

async function main() {
  const apply = parseRetentionApply(process.env.RETENTION_APPLY);
  const missing = missingRetentionCredentials(process.env, apply ? "apply" : "dry_run");
  if (missing.length > 0) throw new Error(`RETENTION_CONFIGURATION_MISSING:${missing.join(",")}`);

  const scope = configuredRetentionScope(process.env);
  const expiredJobs = apply
    ? await expireStalledJobs({ mode: "apply" })
    : (await planStalledJobExpiry({ mode: "plan" })).plan.counts.expired;
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
    storage_operations: result.storageOperations,
    metadata_mutations: result.metadataMutations,
    // In a dry-run this is the number of jobs that WOULD be expired, not a
    // mutation count. Only `metadata_mutations` and `jobs.expired_cleanup` are
    // authoritative for writes.
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
