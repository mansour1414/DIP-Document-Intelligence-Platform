import { db } from "@/lib/db";
import { logger } from "@/lib/logging";

/** Scheduler entrypoint: terminally expires jobs that never reached a worker. */
async function main() {
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const result = await db.job.updateMany({ where: { status: { in: ["QUEUED", "RETRYING", "RUNNING"] }, createdAt: { lt: cutoff } }, data: { status: "EXPIRED", errorCode: "JOB_EXPIRED", completedAt: new Date() } });
  logger.info("jobs.expired_cleanup", { count: result.count });
}
main().finally(() => db.$disconnect());
