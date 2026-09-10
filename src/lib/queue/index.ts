import { Queue, type JobsOptions } from "bullmq";
import Redis from "ioredis";
import { readEnvironment } from "@/lib/env";
import { runtimeLimits } from "@/lib/runtime/config";

export const JOB_QUEUE_NAME = "dip.document-processing.v1";
export const AI_JOB_QUEUE_NAME = "dip.ai-processing.v1";

export type QueuedJob = { jobId: string; toolId: string; idempotencyKey: string; correlationId: string };
let redis: Redis | undefined;
let queue: Queue<QueuedJob> | undefined;
let aiQueue: Queue<QueuedJob> | undefined;

export function getQueueConnection() {
  if (!redis) redis = new Redis(readEnvironment().redisUrl ?? "redis://localhost:6379", { maxRetriesPerRequest: null, connectTimeout: 10_000, commandTimeout: 15_000, enableOfflineQueue: false });
  return redis;
}
const retention = { age: 24 * 60 * 60, count: 1_000 };
export function getJobQueue() { return queue ??= new Queue<QueuedJob>(JOB_QUEUE_NAME, { connection: getQueueConnection(), defaultJobOptions: { attempts: 3, backoff: { type: "exponential", delay: 1000 }, removeOnComplete: retention, removeOnFail: retention } }); }
export function getAiJobQueue() { return aiQueue ??= new Queue<QueuedJob>(AI_JOB_QUEUE_NAME, { connection: getQueueConnection(), defaultJobOptions: { attempts: 3, backoff: { type: "exponential", delay: 2000 }, removeOnComplete: retention, removeOnFail: retention } }); }
export async function queueDepth(queueName: "document" | "ai") { const counts = await (queueName === "ai" ? getAiJobQueue() : getJobQueue()).getJobCounts("wait", "active", "delayed", "failed"); return { ...counts, total: Object.values(counts).reduce((sum, value) => sum + value, 0), configuredConcurrency: queueName === "ai" ? runtimeLimits.aiConcurrency : runtimeLimits.documentConcurrency }; }
export async function enqueueJob(job: QueuedJob, options: JobsOptions = {}) { return getJobQueue().add(job.toolId, job, { ...options, jobId: job.jobId }); }
export async function enqueueAiJob(job: QueuedJob, options: JobsOptions = {}) { return getAiJobQueue().add(job.toolId, job, { ...options, jobId: job.jobId }); }
