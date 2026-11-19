import test from "node:test";
import assert from "node:assert/strict";
import { Queue, Worker } from "bullmq";
import Redis from "ioredis";
import { randomUUID } from "node:crypto";
import { classifyJobExpiry, runningSilenceMs, type JobExpiryFacts } from "../src/lib/retention/job-expiry";
import { createQueueActivityLookup, resolveEvidence } from "../src/lib/retention/queue-activity";

/**
 * Real Redis/BullMQ coverage for the expiry evidence reader.
 *
 * The safety property under test cannot be proven with a fake: it depends on
 * how BullMQ actually lays out its keys and how long it keeps a lock alive. In
 * particular the reported bug was "an old `processedOn` expires a live job", so
 * this drives a genuinely slow BullMQ job past the point where its stored
 * `processedOn` is stale, and asserts the live lock still blocks expiry.
 *
 * Gated exactly like the repository's other Redis integrations: runs in CI
 * (which provides a `redis:7-alpine` service) or when REDIS_E2E=1.
 */

const enabled = Boolean(process.env.CI) || process.env.REDIS_E2E === "1";
const skip = !enabled;
const HOUR = 60 * 60 * 1000;

/** Same shape the worker uses, so the key layout matches production. */
const lockDuration = 2_000;

async function connect(): Promise<Redis> {
  const connection = new Redis(process.env.REDIS_URL ?? "redis://localhost:6379", {
    maxRetriesPerRequest: null,
    enableOfflineQueue: false,
  });
  if (connection.status !== "ready") await connection.connect().catch(() => undefined);
  return connection;
}


/**
 * Bounded teardown.
 *
 * A Worker holding a long job can make `close()` wait; a hung teardown would
 * turn a passing assertion into a timed-out suite. Cleanup is best-effort and
 * time-boxed so a leaked handle is reported, never fatal.
 */
async function settleBounded(tasks: Array<Promise<unknown>>, timeoutMs = 8_000): Promise<void> {
  const settled = Promise.allSettled(tasks);
  let timer: NodeJS.Timeout | undefined;
  const deadline = new Promise<"timeout">((resolve) => {
    timer = setTimeout(() => resolve("timeout"), timeoutMs);
    timer.unref?.();
  });
  try {
    await Promise.race([settled.then(() => "ok" as const), deadline]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function facts(id: string, status: JobExpiryFacts["status"], observedAt: Date, queue: JobExpiryFacts["queue"], ageHours = 48): JobExpiryFacts {
  const stale = new Date(observedAt.getTime() - ageHours * HOUR);
  return {
    id,
    status,
    createdAt: stale,
    startedAt: status === "RUNNING" ? stale : null,
    updatedAt: stale,
    completedAt: null,
    queue,
  };
}

test("a live BullMQ lock blocks expiry even after the stored processedOn goes stale", { skip, timeout: 30_000 }, async () => {
  const connection = await connect();
  const queueName = `dip.retention.live.${randomUUID()}`;
  const queue = new Queue(queueName, { connection });
  const lookup = createQueueActivityLookup({ redis: connection, queueName, now: () => Date.now() });
  const jobId = randomUUID();
  let release: (() => void) | undefined;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const worker = new Worker(queueName, async () => {
    // Hold the job long enough that `processedOn` is well behind "now".
    await held;
    return { ok: true };
  }, { connection, concurrency: 1, lockDuration, lockRenewTime: lockDuration / 3 });

  try {
    await Promise.all([queue.waitUntilReady(), worker.waitUntilReady()]);
    await queue.add("retention-probe", { id: jobId }, { jobId });
    // Wait until the worker is really active on it.
    const started = Date.now();
    while ((await queue.getJobState(jobId)) !== "active" && Date.now() - started < 10_000) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.equal(await queue.getJobState(jobId), "active", "job must be actively processing");

    // Let `processedOn` age past several lock-renewal cycles.
    await new Promise((resolve) => setTimeout(resolve, lockDuration * 3));

    const observedAt = new Date();
    const read = await lookup.read([jobId]);
    assert.equal(read.ok, true);

    const presence = read.present.get(jobId);
    assert.ok(presence, "an active job must be found in the queue");
    assert.equal(presence.leased, true, "BullMQ renews the lock, so it must exist now");
    assert.ok(observedAt.getTime() - presence.lastActivityMs > 0, "processedOn is genuinely in the past");

    // The core regression: old timestamps must not allow expiry while a lock exists.
    const decision = classifyJobExpiry(facts(jobId, "RUNNING", observedAt, { state: "present", ...presence }), observedAt);
    assert.equal(decision.expire, false);
    assert.equal(decision.reason, "running_still_leased");
  } finally {
    release?.();
    await settleBounded([held.catch(() => undefined)], 4_000);
    await queue.obliterate({ force: true }).catch(() => undefined);
    await settleBounded([worker.close(), queue.close()]);
    if (connection.status === "ready") await connection.quit().catch(() => connection.disconnect());
    else connection.disconnect();
  }
});

test("a delayed retry is reported present, so it is never expired mid-backoff", { skip, timeout: 30_000 }, async () => {
  const connection = await connect();
  const queueName = `dip.retention.delayed.${randomUUID()}`;
  const queue = new Queue(queueName, { connection });
  const lookup = createQueueActivityLookup({ redis: connection, queueName, now: () => Date.now() });
  const jobId = randomUUID();
  // A backoff long enough that we can observe the delayed state.
  const worker = new Worker(queueName, async () => {
    throw new Error("fixture failure");
  }, { connection, concurrency: 1 });

  try {
    await Promise.all([queue.waitUntilReady(), worker.waitUntilReady()]);
    await queue.add("retention-probe", { id: jobId }, { jobId, attempts: 3, backoff: { type: "fixed", delay: 15_000 } });

    // Wait until BullMQ has a failed attempt scheduled for retry.
    const started = Date.now();
    let state = "";
    while (Date.now() - started < 15_000) {
      state = await queue.getJobState(jobId);
      if (state === "delayed") break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.equal(state, "delayed", "fixture must reach the delayed retry state");

    const observedAt = new Date();
    const read = await lookup.read([jobId]);
    assert.equal(read.ok, true);
    assert.ok(read.present.has(jobId), "a delayed retry is still tracked by BullMQ");

    // Even with everything else ancient, presence blocks expiry.
    const decision = classifyJobExpiry(facts(jobId, "RETRYING", observedAt, { state: "present", ...read.present.get(jobId)! }, 48), observedAt);
    assert.equal(decision.expire, false);
    assert.equal(decision.reason, "retry_queue_present");
  } finally {
    await queue.obliterate({ force: true }).catch(() => undefined);
    await settleBounded([worker.close(), queue.close()]);
    if (connection.status === "ready") await connection.quit().catch(() => connection.disconnect());
    else connection.disconnect();
  }
});

test("a completed job leaves nothing behind, so absence can be confirmed", { skip, timeout: 30_000 }, async () => {
  const connection = await connect();
  const queueName = `dip.retention.absent.${randomUUID()}`;
  const queue = new Queue(queueName, { connection });
  const lookup = createQueueActivityLookup({ redis: connection, queueName, now: () => Date.now() });

  try {
    await queue.waitUntilReady();
    const observedAt = new Date();
    const read = await lookup.read([randomUUID()]);
    assert.equal(read.ok, true, "an unknown id on a reachable queue is a successful read");
    assert.deepEqual(resolveEvidence("nobody", [read]), { state: "absent" });

    // And with confirmed absence plus a full-silence-window gap, expiry proceeds.
    const gone = new Date(observedAt.getTime() - (runningSilenceMs() + HOUR));
    const decision = classifyJobExpiry({ id: "nobody", status: "RUNNING", createdAt: gone, startedAt: gone, updatedAt: gone, completedAt: null, queue: { state: "absent" } }, observedAt);
    assert.equal(decision.expire, true);
  } finally {
    await queue.obliterate({ force: true }).catch(() => undefined);
    await settleBounded([queue.close()]);
    if (connection.status === "ready") await connection.quit().catch(() => connection.disconnect());
    else connection.disconnect();
  }
});
