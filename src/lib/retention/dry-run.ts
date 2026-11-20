import { logger } from "@/lib/logging";
import {
  assertDryRunAllowed,
  configuredRetentionScope,
  missingRetentionCredentials,
  type RetentionScope,
} from "./safety";
import { runRetentionSweep } from "./service";
import { planStalledJobExpiry, type CandidateRow, type QueueEvidenceProvider } from "./expiry-sweep";
import { prismaRetentionRepository, type RetentionRepository } from "./repository";
import {
  buildRetentionDryRunReport,
  isZeroMutation,
  reportLogContext,
  type RetentionDryRunReport,
} from "./diagnostics";

/**
 * Dry-run-only orchestration.
 *
 * There is deliberately **no** mode parameter: this function cannot be asked to
 * apply. Apply lives behind `expireStalledJobs()` and `runRetentionSweep({ dryRun:
 * false })`, neither of which is imported here.
 *
 * Two independent guards protect the operator from a mistaken environment:
 *
 *   1. `RETENTION_APPLY=1` makes this function throw
 *      `RETENTION_APPLY_FORBIDDEN_IN_DRY_RUN`. It does not silently ignore the
 *      request — an operator who asked for apply must not receive a green
 *      "nothing to do" run.
 *   2. If any mutating counter comes back non-zero the run aborts with
 *      `RETENTION_DRY_RUN_MUTATED` instead of reporting success.
 *
 * Configuration is mode-aware: a dry-run needs `DATABASE_URL` and
 * `STORAGE_BUCKET` only. It never constructs an object-storage client, so it
 * needs no S3 endpoint or key, while storage-scope validation stays enforced
 * against the bucket recorded in PostgreSQL metadata.
 */

export type RetentionDryRunOptions = {
  now?: Date;
  /** Defaults to `process.env`. Tests pass an explicit record. */
  env?: Record<string, string | undefined>;
  /** Configured storage scope; resolved from STORAGE_BUCKET when omitted. */
  scope?: RetentionScope;
  /** Data-access port. Defaults to the Prisma implementation. */
  repository?: RetentionRepository;
  /** Test seam: replaces the Redis-backed queue evidence provider. */
  evidence?: QueueEvidenceProvider;
  /** Test seam: forces the "queue is unusable" path without touching Redis. */
  queueUnavailable?: "not_configured" | "unavailable" | "error" | null;
  /** Test seam: replaces the PostgreSQL job-candidate read. */
  loadCandidates?: (now: Date) => Promise<CandidateRow[]>;
};

/**
 * Run one strictly read-only sweep and return aggregate-only diagnostics.
 *
 * Order matters: the apply refusal and the credential gate both run before any
 * database or Redis access, so a misconfigured dry-run fails without touching a
 * dependency.
 */
export async function runRetentionDryRun(options: RetentionDryRunOptions = {}): Promise<RetentionDryRunReport> {
  const env = options.env ?? process.env;

  // 1. Never run while the environment asks for apply.
  assertDryRunAllowed(env);

  // 2. Fail closed on missing configuration, naming variables only.
  const missing = missingRetentionCredentials(env, "dry_run");
  if (missing.length > 0) throw new Error(`RETENTION_CONFIGURATION_MISSING:${missing.join(",")}`);

  const scope = options.scope ?? configuredRetentionScope(env);
  const now = options.now ?? new Date();
  const startedAt = Date.now();

  // 3. Job expiry: plan only. Nothing on this path can terminate a job.
  const { plan: expiryPlan, queue } = await planStalledJobExpiry({
    now,
    mode: "plan",
    evidence: options.evidence,
    queueUnavailable: options.queueUnavailable,
    loadCandidates: options.loadCandidates,
  });

  // 4. Document retention: `dryRun: true` is a literal, not a variable, and no
  //    object store is supplied or resolved.
  const { plan, result } = await runRetentionSweep({
    now,
    dryRun: true,
    scope,
    repository: options.repository ?? prismaRetentionRepository,
  });

  const report = buildRetentionDryRunReport({
    plan,
    expiryPlan,
    queue,
    result,
    jobsExpiredApplied: 0,
    durationMs: Date.now() - startedAt,
  });

  // 5. Never report success for a run that wrote something.
  if (!isZeroMutation(result, 0) || !report.zero_mutations) {
    logger.error("retention.dry_run_mutated", reportLogContext(report));
    throw new Error("RETENTION_DRY_RUN_MUTATED");
  }

  logger.info("retention.dry_run_summary", reportLogContext(report));
  return report;
}
