import test from "node:test";
import assert from "node:assert/strict";
import { Queue, QueueEvents, Worker } from "bullmq";
import Redis from "ioredis";
import { randomUUID } from "node:crypto";
import { AiGatewayError } from "../src/lib/ai/gateway";
import { toAiQueueError } from "../src/lib/ai/gateway/retry";
import { AI_JOB_RETRY_POLICY } from "../src/lib/queue";

test("real Redis queue reaches terminal states and retry side effects remain idempotent", { skip: !process.env.CI && process.env.REDIS_E2E !== "1", timeout: 20_000 }, async () => {
  const connection = new Redis(process.env.REDIS_URL ?? "redis://localhost:6379", { maxRetriesPerRequest: null, enableOfflineQueue: false });
  const queueName = `dip.phase6.test.${randomUUID()}`;
  const queue = new Queue<{ id: string; failOnce?: boolean; alwaysFail?: boolean }>(queueName, { connection });
  const events = new QueueEvents(queueName, { connection });
  const outputs = new Map<string, string>(); const attempts = new Map<string, number>();
  const worker = new Worker(queueName, async (job) => {
    const count = (attempts.get(job.data.id) ?? 0) + 1; attempts.set(job.data.id, count);
    if (job.data.alwaysFail || (job.data.failOnce && count === 1)) throw Object.assign(new Error("fixture failure"), { code: "FIXTURE_FAILURE" });
    if (!outputs.has(job.data.id)) outputs.set(job.data.id, `output/${job.data.id}`);
    return { outputKey: outputs.get(job.data.id) };
  }, { connection, concurrency: 1 });
  try {
    await Promise.all([queue.waitUntilReady(), events.waitUntilReady(), worker.waitUntilReady()]);
    const waitFor = async (job: Awaited<ReturnType<typeof queue.add>>) => {
      try { return await job.waitUntilFinished(events, 10_000); }
      catch (error) {
        const [state, current] = await Promise.all([job.getState().catch(() => "unknown"), queue.getJob(job.id!).catch(() => undefined)]);
        throw new Error(`${error instanceof Error ? error.message : String(error)}; diagnostics: state=${state}, failedReason=${current?.failedReason ?? "none"}, attemptsMade=${current?.attemptsMade ?? job.attemptsMade}, workerRunning=${worker.isRunning()}, queueEventsReady=true, queueReady=true`);
      }
    };
    const success = await queue.add("merge-pdf", { id: "success" }, { jobId: "success", attempts: 2, removeOnComplete: false });
    assert.deepEqual(await waitFor(success), { outputKey: "output/success" });
    const retry = await queue.add("merge-pdf", { id: "retry", failOnce: true }, { jobId: "retry", attempts: 2, backoff: { type: "fixed", delay: 10 }, removeOnComplete: false });
    assert.deepEqual(await waitFor(retry), { outputKey: "output/retry" });
    const failure = await queue.add("merge-pdf", { id: "failure", alwaysFail: true }, { jobId: "failure", attempts: 1, removeOnFail: false });
    await assert.rejects(() => waitFor(failure), /fixture failure/);
    assert.equal(attempts.get("retry"), 2); assert.equal(outputs.size, 2); assert.equal(outputs.get("retry"), "output/retry");
  } finally {
    await queue.obliterate({ force: true }).catch(() => undefined);
    await Promise.allSettled([worker.close(), events.close(), queue.close()]);
    if (connection.status === "ready") await connection.quit(); else connection.disconnect();
  }
});

test("real Redis honors the AI five-attempt policy without duplicate successful effects", { skip: !process.env.CI && process.env.REDIS_E2E !== "1", timeout: 20_000 }, async () => {
  const connection = new Redis(process.env.REDIS_URL ?? "redis://localhost:6379", { maxRetriesPerRequest: null, enableOfflineQueue: false });
  const queueName = `dip.ai-retry.test.${randomUUID()}`;
  type Fixture = { id: string; transientFailures?: number; permanent?: boolean };
  const queue = new Queue<Fixture>(queueName, { connection });
  const events = new QueueEvents(queueName, { connection });
  const attempts = new Map<string, number>(); const outputs = new Map<string, number>(); const accounting = new Map<string, number>();
  const worker = new Worker<Fixture>(queueName, async (job) => {
    const count = (attempts.get(job.data.id) ?? 0) + 1; attempts.set(job.data.id, count);
    try {
      if (job.data.permanent) throw new AiGatewayError("AI_PROVIDER_AUTH_FAILED", "Permanent provider failure", false);
      if (count <= (job.data.transientFailures ?? 0)) throw new AiGatewayError("AI_PROVIDER_ERROR", "Transient provider failure", true);
      outputs.set(job.data.id, (outputs.get(job.data.id) ?? 0) + 1); accounting.set(job.data.id, (accounting.get(job.data.id) ?? 0) + 1);
      return { outputKey: `output/${job.data.id}` };
    } catch (error) { throw toAiQueueError(error); }
  }, { connection, concurrency: 1 });
  const fastRetryOptions = { attempts: AI_JOB_RETRY_POLICY.attempts, backoff: { type: "fixed", delay: 5 }, removeOnComplete: false, removeOnFail: false } as const;
  try {
    await Promise.all([queue.waitUntilReady(), events.waitUntilReady(), worker.waitUntilReady()]);
    const eventual = await queue.add("summarize-pdf", { id: "eventual", transientFailures: 4 }, { ...fastRetryOptions, jobId: "eventual" });
    assert.deepEqual(await eventual.waitUntilFinished(events, 10_000), { outputKey: "output/eventual" });
    assert.equal(attempts.get("eventual"), 5); assert.equal(outputs.get("eventual"), 1); assert.equal(accounting.get("eventual"), 1);

    const permanent = await queue.add("summarize-pdf", { id: "permanent", permanent: true }, { ...fastRetryOptions, jobId: "permanent" });
    await assert.rejects(() => permanent.waitUntilFinished(events, 10_000), /Permanent provider failure/);
    assert.equal(attempts.get("permanent"), 1); assert.equal(outputs.get("permanent") ?? 0, 0); assert.equal(accounting.get("permanent") ?? 0, 0);

    const exhausted = await queue.add("summarize-pdf", { id: "exhausted", transientFailures: 5 }, { ...fastRetryOptions, jobId: "exhausted" });
    await assert.rejects(() => exhausted.waitUntilFinished(events, 10_000), /Transient provider failure/);
    assert.equal(attempts.get("exhausted"), 5); assert.equal(await exhausted.getState(), "failed"); assert.equal(outputs.get("exhausted") ?? 0, 0); assert.equal(accounting.get("exhausted") ?? 0, 0);
    assert.deepEqual([...outputs], [["eventual", 1]]); assert.deepEqual([...accounting], [["eventual", 1]]);
  } finally {
    await queue.obliterate({ force: true }).catch(() => undefined);
    await Promise.allSettled([worker.close(), events.close(), queue.close()]);
    if (connection.status === "ready") await connection.quit(); else connection.disconnect();
  }
});
