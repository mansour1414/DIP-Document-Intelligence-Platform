import { Queue, type JobsOptions } from "bullmq";
import Redis from "ioredis";
import { readEnvironment } from "@/lib/env";

export const JOB_QUEUE_NAME = "dip.document-processing.v1";

export type QueuedJob = { jobId: string; toolId: string; idempotencyKey: string; correlationId: string };
let redis: Redis | undefined;
let queue: Queue<QueuedJob> | undefined;

export function getQueueConnection() {
  if (!redis) redis = new Redis(readEnvironment().redisUrl ?? "redis://localhost:6379", { maxRetriesPerRequest: null });
  return redis;
}
export function getJobQueue() { return queue ??= new Queue<QueuedJob>(JOB_QUEUE_NAME, { connection: getQueueConnection(), defaultJobOptions: { attempts: 3, backoff: { type: "exponential", delay: 1000 }, removeOnComplete: 1000, removeOnFail: 1000 } }); }
export async function enqueueJob(job: QueuedJob, options: JobsOptions = {}) { return getJobQueue().add(job.toolId, job, { ...options, jobId: job.jobId }); }
