import { Queue, type JobsOptions } from "bullmq";
import Redis from "ioredis";
import { readEnvironment } from "@/lib/env";
import { runtimeLimits } from "@/lib/runtime/config";
import { recordMetric } from "@/lib/observability/metrics";

export const JOB_QUEUE_NAME = "dip.document-processing.v1";
export const AI_JOB_QUEUE_NAME = "dip.ai-processing.v1";

export type QueuedJob = { jobId: string; toolId: string; idempotencyKey: string; correlationId: string; userId?: string; workflowRunId?: string };
let redis: Redis | undefined;
let queue: Queue<QueuedJob> | undefined;
let aiQueue: Queue<QueuedJob> | undefined;

export function getQueueConnection() {
  if (!redis || redis.status === "end") redis = new Redis(readEnvironment().redisUrl ?? "redis://localhost:6379", { maxRetriesPerRequest: null, connectTimeout: 10_000, commandTimeout: 15_000, enableOfflineQueue: false });
  return redis;
}
async function waitForRedisReady(connection: Redis, timeoutMs = 10_000) {
  if (connection.status === "ready") return;
  await new Promise<void>((resolve, reject) => {
    const cleanup = () => { clearTimeout(timer); connection.off("ready", onReady); connection.off("error", onError); connection.off("end", onEnd); };
    const onReady = () => { cleanup(); resolve(); };
    const onError = (error: Error) => { cleanup(); reject(error); };
    const onEnd = () => { cleanup(); reject(new Error("Redis connection ended before becoming ready")); };
    const timer = setTimeout(() => { cleanup(); reject(new Error("Redis readiness connection timed out")); }, timeoutMs); timer.unref?.();
    connection.once("ready", onReady); connection.once("error", onError); connection.once("end", onEnd);
    if (connection.status === "wait") void connection.connect().catch(onError);
  });
}
export async function pingQueueConnection() { const connection = getQueueConnection(); await waitForRedisReady(connection); return connection.ping(); }
const retention = { age: 24 * 60 * 60, count: 1_000 };
export function getJobQueue() { return queue ??= new Queue<QueuedJob>(JOB_QUEUE_NAME, { connection: getQueueConnection(), defaultJobOptions: { attempts: 3, backoff: { type: "exponential", delay: 1000 }, removeOnComplete: retention, removeOnFail: retention } }); }
export function getAiJobQueue() { return aiQueue ??= new Queue<QueuedJob>(AI_JOB_QUEUE_NAME, { connection: getQueueConnection(), defaultJobOptions: { attempts: 3, backoff: { type: "exponential", delay: 2000 }, removeOnComplete: retention, removeOnFail: retention } }); }
export async function queueDepth(queueName: "document" | "ai") { const counts = await (queueName === "ai" ? getAiJobQueue() : getJobQueue()).getJobCounts("wait", "active", "delayed", "failed"); const total = Object.values(counts).reduce((sum, value) => sum + value, 0); recordMetric("queue_depth", total, "count", { queue: queueName }); return { ...counts, total, configuredConcurrency: queueName === "ai" ? runtimeLimits.aiConcurrency : runtimeLimits.documentConcurrency }; }
export async function enqueueJob(job: QueuedJob, options: JobsOptions = {}) { return getJobQueue().add(job.toolId, job, { ...options, jobId: job.jobId }); }
export async function enqueueAiJob(job: QueuedJob, options: JobsOptions = {}) { return getAiJobQueue().add(job.toolId, job, { ...options, jobId: job.jobId }); }
export async function closeQueueResources() {
  const documentQueue = queue; const currentAiQueue = aiQueue; const connection = redis;
  queue = undefined; aiQueue = undefined; redis = undefined;
  await Promise.all([documentQueue?.close(), currentAiQueue?.close()]);
  if (connection && connection.status !== "end") await connection.quit();
}
