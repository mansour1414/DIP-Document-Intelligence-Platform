import type { QueueActivity } from "./job-expiry";

/**
 * Read liveness evidence for an attempt directly from BullMQ's Redis keys.
 *
 * The scheduler deliberately does not import the BullMQ `Queue`/`Job` classes:
 * those are the worker's API and a retention sweep should not be able to mutate
 * queue state. Reading the documented key layout is enough to answer the only
 * question that matters — "is this attempt still leased or actively running?"
 * — and it needs no schema change.
 *
 * Key layout (BullMQ v5+, prefix `bull` by default):
 *   bull:<queue>:<jobId>          hash: timestamp, processedOn, finishedOn, attemptsMade
 *   bull:<queue>:<jobId>:lock     lock token, present iff a worker holds the lease
 */

/** BullMQ stores `lockDuration` in the `stalled-check` interval, not per job. */
const DEFAULT_QUEUE_PREFIX = "bull";

export type QueueActivityLookup = {
  /** Returns per-job liveness evidence, or null when the queue does not know the job. */
  lookup(jobIds: readonly string[]): Promise<Map<string, QueueActivity>>;
};

type MinimalRedis = {
  hmget(key: string, ...fields: string[]): Promise<Array<string | null>>;
  exists(...keys: string[]): Promise<number>;
};

/**
 * Build a lookup backed by a Redis client and a queue name.
 *
 * `now` is injected so the mapping from BullMQ timestamps to "last activity"
 * stays deterministic under test.
 */
export function createQueueActivityLookup(options: {
  redis: MinimalRedis;
  queueName: string;
  now: () => number;
  prefix?: string;
}): QueueActivityLookup {
  const { redis, queueName, now } = options;
  const prefix = options.prefix ?? DEFAULT_QUEUE_PREFIX;
  const hashKey = (jobId: string) => `${prefix}:${queueName}:${jobId}`;
  const lockKey = (jobId: string) => `${prefix}:${queueName}:${jobId}:lock`;

  return {
    async lookup(jobIds) {
      const result = new Map<string, QueueActivity>();
      // Sequential by design: a sweep must stay cheap and predictable rather
      // than opening a wide pipeline against the worker's Redis.
      for (const jobId of jobIds) {
        try {
          const [timestamp, processedOn, finishedOn] = await redis.hmget(hashKey(jobId), "timestamp", "processedOn", "finishedOn");
          if (timestamp === null && processedOn === null && finishedOn === null) continue;
          const leased = (await redis.exists(lockKey(jobId))) === 1;
          const stamps = [timestamp, processedOn, finishedOn]
            .map((value) => (value === null ? Number.NaN : Number(value)))
            .filter((value) => Number.isFinite(value) && value > 0);
          const lastActivityMs = stamps.length ? Math.max(...stamps) : now();
          // A lock is the strongest signal; a fresh `processedOn` with no
          // `finishedOn` is the fallback for an attempt between heartbeats.
          const activelyProcessing = !leased && processedOn !== null && finishedOn === null;
          result.set(jobId, { lastActivityMs, leased, activelyProcessing });
        } catch {
          // A Redis problem must never make the sweep more aggressive: an
          // unreadable attempt is treated as "queue does not know it", and the
          // database-side silence window still has to elapse before expiry.
          continue;
        }
      }
      return result;
    },
  };
}

/** No-op lookup: every job is treated as unknown to the queue. */
export const emptyQueueActivityLookup: QueueActivityLookup = { lookup: async () => new Map() };
