import type { QueueEvidence } from "./job-expiry";

/**
 * Read liveness evidence for an attempt directly from BullMQ's Redis keys.
 *
 * The scheduler deliberately does not import the BullMQ `Queue`/`Job` classes:
 * those are the worker's API and a retention sweep must not be able to mutate
 * queue state. Reading the documented key layout answers the only question that
 * matters — "does BullMQ still hold this attempt?" — and needs no schema change.
 *
 * Key layout, verified against the installed bullmq (6.3.4):
 *   bull:<queue>:<jobId>          hash: timestamp, processedOn, finishedOn, attemptsMade
 *   bull:<queue>:<jobId>:lock     lock token, present iff a worker holds the lease
 *
 * `bull` is `QueueKeys`' default prefix and the worker does not override it, so
 * it is correct here. Both keys are derived in `RedisQueueBackend`
 * (`toKey(jobId) + ':lock'`), and a Worker renews the lock every
 * `lockDuration / 2`, which is what makes lock existence *current* evidence.
 *
 * ## Failure is not absence
 *
 * Absence may only be concluded when **every** queue was read completely
 * successfully. Any error — unreachable Redis, timeout, a single failed command,
 * a partially read batch — yields `unknown`, and `unknown` never permits expiry.
 * {@link QueueReadResult.ok} carries that distinction so a caller cannot
 * accidentally treat a failed read as an empty one.
 */

const DEFAULT_QUEUE_PREFIX = "bull";

/** Presence facts for jobs a queue still tracks. */
export type QueuePresence = {
  lastActivityMs: number;
  leased: boolean;
  activelyProcessing: boolean;
};

/**
 * Result of reading one queue.
 *
 * `ok: false` means the read was incomplete; the caller must treat every job
 * absent from `present` as `unknown`, not `absent`.
 */
export type QueueReadResult = {
  present: Map<string, QueuePresence>;
  ok: boolean;
};

export type QueueActivityLookup = {
  /** Returns per-job presence evidence plus whether the read was complete. */
  read(jobIds: readonly string[]): Promise<QueueReadResult>;
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
    async read(jobIds) {
      const present = new Map<string, QueuePresence>();
      let ok = true;
      // Sequential by design: a sweep must stay cheap and predictable rather
      // than opening a wide pipeline against the worker's Redis.
      for (const jobId of jobIds) {
        try {
          const [timestamp, processedOn, finishedOn] = await redis.hmget(hashKey(jobId), "timestamp", "processedOn", "finishedOn");
          if (timestamp === null && processedOn === null && finishedOn === null) continue;
          // Lock existence is current evidence: the worker refreshes it on a
          // heartbeat, so a held lock means a live holder regardless of how old
          // `processedOn` is.
          const leased = (await redis.exists(lockKey(jobId))) === 1;
          const stamps = [timestamp, processedOn, finishedOn]
            .map((value) => (value === null ? Number.NaN : Number(value)))
            .filter((value) => Number.isFinite(value) && value > 0);
          const lastActivityMs = stamps.length ? Math.max(...stamps) : now();
          // A fresh `processedOn` with no `finishedOn` is the fallback signal for
          // an attempt between heartbeats.
          const activelyProcessing = !leased && processedOn !== null && finishedOn === null;
          present.set(jobId, { lastActivityMs, leased, activelyProcessing });
        } catch {
          // Any error makes the whole read incomplete. Continuing would let the
          // remaining jobs look absent purely because Redis failed.
          ok = false;
          break;
        }
      }
      return { present, ok };
    },
  };
}

/**
 * Combine every queue's evidence into one verdict for a job.
 *
 * Order of precedence:
 *   1. **Presence wins outright.** A queue that knows the job proves it is
 *      tracked, regardless of what the other queues returned.
 *   2. **Completeness is then required.** Absence may only be concluded when
 *      every expected queue produced a successful result. A missing result is
 *      not an empty result: if the caller expected two queues and got one, the
 *      unread queue might have held the job.
 *   3. Only then is the job `absent`.
 *
 * `expectedReads` exists because "I received fewer results than I asked for" is
 * otherwise indistinguishable from "I asked for one queue". Defaulting it to
 * `reads.length` would silently restore the bug for any caller that forgets it,
 * so the scheduler always passes the expected count explicitly.
 */
export function resolveEvidence(
  jobId: string,
  reads: readonly QueueReadResult[],
  expectedReads: number = reads.length,
): QueueEvidence {
  for (const read of reads) {
    const presence = read.present.get(jobId);
    if (presence) return { state: "present", ...presence };
  }
  if (!isCompleteEvidence(reads, expectedReads)) {
    return { state: "unknown", reason: "error" };
  }
  return { state: "absent" };
}

/**
 * True only when every expected queue produced a fully successful result.
 *
 * A short result set, a zero-length set, or any `ok: false` all mean the batch
 * is incomplete, and incomplete evidence can never justify absence.
 */
export function isCompleteEvidence(reads: readonly QueueReadResult[], expectedReads: number): boolean {
  if (expectedReads <= 0) return false;
  if (reads.length < expectedReads) return false;
  return reads.every((read) => read.ok);
}

/** Evidence for a sweep that could not reach Redis at all. */
export function unknownEvidence(reason: Extract<QueueEvidence, { state: "unknown" }>["reason"]): QueueEvidence {
  return { state: "unknown", reason };
}

/** An empty, successful read: useful when a queue name is intentionally unused. */
export const emptyQueueReadResult: QueueReadResult = { present: new Map(), ok: true };
