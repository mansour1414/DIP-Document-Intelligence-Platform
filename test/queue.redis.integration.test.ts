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
    const success = await queue.add("merge-pdf", { id: "success" }, { jobId: "success", attempts: 2, removeOnComplete: false });
    const retry = await queue.add("merge-pdf", { id: "retry", failOnce: true }, { jobId: "retry", attempts: 2, backoff: { type: "fixed", delay: 10 }, removeOnComplete: false });
    const failure = await queue.add("merge-pdf", { id: "failure", alwaysFail: true }, { jobId: "failure", attempts: 1, removeOnFail: false });
    await events.waitUntilReady();
    assert.deepEqual(await success.waitUntilFinished(events, 10_000), { outputKey: "output/success" });
    assert.deepEqual(await retry.waitUntilFinished(events, 10_000), { outputKey: "output/retry" });
    await assert.rejects(() => failure.waitUntilFinished(events, 10_000), /fixture failure/);
    assert.equal(attempts.get("retry"), 2); assert.equal(outputs.size, 2); assert.equal(outputs.get("retry"), "output/retry");
  } finally {
    await queue.obliterate({ force: true }).catch(() => undefined);
    await Promise.allSettled([worker.close(), events.close(), queue.close()]);
    if (connection.status === "ready") await connection.quit(); else connection.disconnect();
  }
});
