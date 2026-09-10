import { db } from "@/lib/db";
import { getQueueConnection } from "@/lib/queue";

export async function checkReadiness() {
  const started = performance.now();
  try { await Promise.all([getQueueConnection().ping(), db.$queryRaw`SELECT 1`]); return { ready: true, durationMs: performance.now() - started }; }
  catch { return { ready: false, durationMs: performance.now() - started }; }
}

