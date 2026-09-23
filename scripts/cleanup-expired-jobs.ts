import { db } from "@/lib/db";
import { logger } from "@/lib/logging";
import { runRetentionCleanup } from "@/lib/retention/service";

/** Scheduler entrypoint: terminally expires jobs that never reached a worker. */
async function main() {
  if (!process.env.DATABASE_URL) throw new Error("RETENTION_DATABASE_URL_MISSING");
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const result = await db.job.updateMany({ where: { status: { in: ["QUEUED", "RETRYING", "RUNNING"] }, createdAt: { lt: cutoff } }, data: { status: "EXPIRED", errorCode: "JOB_EXPIRED", completedAt: new Date() } });
  logger.info("jobs.expired_cleanup", { count: result.count });
  await runRetentionCleanup({ dryRun: process.env.RETENTION_APPLY !== "1" });
}
main().catch((error) => {
  const prismaCode = (error as { code?: unknown })?.code;
  const safeCode = error instanceof Error && error.message === "RETENTION_DATABASE_URL_MISSING"
    ? error.message
    : typeof prismaCode === "string" && /^P\d{4}$/.test(prismaCode) ? prismaCode : error instanceof Error ? error.name : "UNKNOWN";
  logger.error("retention.scheduler_failed", { error_code: safeCode });
  process.exitCode = 1;
}).finally(() => db.$disconnect());
