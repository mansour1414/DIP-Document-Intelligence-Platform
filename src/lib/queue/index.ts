import Redis from "ioredis";
import { readEnvironment } from "@/lib/env";

export const JOB_QUEUE_NAME = "document-jobs";

export type QueuedJob = { jobId: string; toolId: string; idempotencyKey: string };
let redis: Redis | undefined;

export function getQueueConnection() {
  if (!redis) redis = new Redis(readEnvironment().redisUrl ?? "redis://localhost:6379", { maxRetriesPerRequest: 1 });
  return redis;
}

/** Minimal Redis queue boundary; workers consume this list until BullMQ is introduced in Phase 1. */
export async function enqueueJob(job: QueuedJob) {
  await getQueueConnection().lpush(JOB_QUEUE_NAME, JSON.stringify(job));
}
