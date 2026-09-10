import { db } from "@/lib/db";
import { pingQueueConnection } from "@/lib/queue";
import { logger } from "@/lib/logging";

export async function checkReadiness() {
  const started = performance.now();
  const [redis, postgres] = await Promise.allSettled([pingQueueConnection(), db.$queryRaw`SELECT 1`]);
  const ready = redis.status === "fulfilled" && postgres.status === "fulfilled";
  if (!ready) logger.warn("readiness.failed", { redis: redis.status, postgres: postgres.status });
  return { ready, durationMs: performance.now() - started };
}
