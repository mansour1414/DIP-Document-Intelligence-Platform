import test from "node:test";
import assert from "node:assert/strict";
import { Queue, QueueEvents, Worker } from "bullmq";
import Redis from "ioredis";
import { randomUUID } from "node:crypto";

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
