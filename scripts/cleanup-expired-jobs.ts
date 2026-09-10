import { db } from "@/lib/db";
import { logger } from "@/lib/logging";
import { runRetentionCleanup } from "@/lib/retention/service";

/** Scheduler entrypoint: terminally expires jobs that never reached a worker. */
async function main() {
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const result = await db.job.updateMany({ where: { status: { in: ["QUEUED", "RETRYING", "RUNNING"] }, createdAt: { lt: cutoff } }, data: { status: "EXPIRED", errorCode: "JOB_EXPIRED", completedAt: new Date() } });
  logger.info("jobs.expired_cleanup", { count: result.count });
  await runRetentionCleanup({ dryRun: process.env.RETENTION_APPLY !== "1" });
}
main().catch((error) => { logger.error("retention.scheduler_failed", { error_code: error instanceof Error ? error.name : "UNKNOWN" }); process.exitCode = 1; }).finally(() => db.$disconnect());
