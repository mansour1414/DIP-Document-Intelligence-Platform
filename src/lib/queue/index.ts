import { Queue, type JobsOptions } from "bullmq";
import Redis from "ioredis";
import { readEnvironment } from "@/lib/env";
import { runtimeLimits } from "@/lib/runtime/config";
import { recordMetric } from "@/lib/observability/metrics";

export const JOB_QUEUE_NAME = "dip.document-processing.v1";
export const AI_JOB_QUEUE_NAME = "dip.ai-processing.v1";

export type QueuedJob = { jobId: string; toolId: string; idempotencyKey: string; correlationId: string; userId: string; workflowRunId?: string };
let redis: Redis | undefined;
let queue: Queue<QueuedJob> | undefined;
let aiQueue: Queue<QueuedJob> | undefined;
const redisReadiness = new WeakMap<Redis, Promise<void>>();

export function getQueueConnection() {
  if (!redis || redis.status === "end") redis = new Redis(readEnvironment().redisUrl ?? "redis://localhost:6379", { maxRetriesPerRequest: null, connectTimeout: 10_000, commandTimeout: 15_000, enableOfflineQueue: false });
  return redis;
}
export function waitForRedisReady(connection: Redis, timeoutMs = 10_000) {
  if (connection.status === "ready") return;
  const existing = redisReadiness.get(connection); if (existing) return existing;
  const readiness = new Promise<void>((resolve, reject) => {
    const cleanup = () => { clearTimeout(timer); connection.off("ready", onReady); connection.off("error", onError); connection.off("end", onEnd); };
    const onReady = () => { cleanup(); resolve(); };
    const onError = (error: Error) => { cleanup(); reject(error); };
    const onEnd = () => { cleanup(); reject(new Error("Redis connection ended before becoming ready")); };
    const timer = setTimeout(() => { cleanup(); reject(new Error("Redis readiness connection timed out")); }, timeoutMs); timer.unref?.();
    connection.once("ready", onReady); connection.once("error", onError); connection.once("end", onEnd);
    if (connection.status === "ready") onReady(); else if (connection.status === "wait") void connection.connect().catch(onError);
  });
  redisReadiness.set(connection, readiness); void readiness.then(() => redisReadiness.delete(connection), () => redisReadiness.delete(connection)); return readiness;
}
export async function getReadyQueueConnection() { const connection = getQueueConnection(); await waitForRedisReady(connection); return connection; }
export async function pingQueueConnection() { return (await getReadyQueueConnection()).ping(); }
const retention = { age: 24 * 60 * 60, count: 1_000 };
export const AI_JOB_RETRY_POLICY = { attempts: 5, backoff: { type: "exponential", delay: 2000, jitter: 0.5 } } satisfies JobsOptions;
export function getJobQueue() { return queue ??= new Queue<QueuedJob>(JOB_QUEUE_NAME, { connection: getQueueConnection(), defaultJobOptions: { attempts: 3, backoff: { type: "exponential", delay: 1000 }, removeOnComplete: retention, removeOnFail: retention } }); }
export function getAiJobQueue() { return aiQueue ??= new Queue<QueuedJob>(AI_JOB_QUEUE_NAME, { connection: getQueueConnection(), defaultJobOptions: { ...AI_JOB_RETRY_POLICY, removeOnComplete: retention, removeOnFail: retention } }); }
export async function queueDepth(queueName: "document" | "ai") { const counts = await (queueName === "ai" ? getAiJobQueue() : getJobQueue()).getJobCounts("wait", "active", "delayed", "failed"); const total = Object.values(counts).reduce((sum, value) => sum + value, 0); recordMetric("queue_depth", total, "count", { queue: queueName }); return { ...counts, total, configuredConcurrency: queueName === "ai" ? runtimeLimits.aiConcurrency : runtimeLimits.documentConcurrency }; }
export async function enqueueJob(job: QueuedJob, options: JobsOptions = {}) { return getJobQueue().add(job.toolId, job, { ...options, jobId: job.jobId }); }
export async function enqueueAiJob(job: QueuedJob, options: JobsOptions = {}) { return getAiJobQueue().add(job.toolId, job, { ...options, jobId: job.jobId }); }
export async function closeQueueResources() {
  const documentQueue = queue; const currentAiQueue = aiQueue; const connection = redis;
  queue = undefined; aiQueue = undefined; redis = undefined;
  await Promise.all([documentQueue?.close(), currentAiQueue?.close()]);
  if (connection && connection.status !== "end") await connection.quit();
}
