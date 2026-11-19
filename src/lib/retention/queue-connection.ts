import Redis from "ioredis";
import { readEnvironment } from "@/lib/env";
import { logger } from "@/lib/logging";

/**
 * A short-lived, bounded Redis connection for the retention sweep.
 *
 * The retention workflow (`jobs:cleanup`) does **not** set `REDIS_URL` today.
 * The application's shared queue connection silently falls back to
 * `redis://localhost:6379`, which is wrong for three reasons in a scheduled job:
 *
 *   1. There is no Redis on the runner, so the sweep would attempt a connection
 *      to a service that does not exist and interpret the failure as "unknown".
 *   2. Pointing a retention job at an implicit localhost address is a silent
 *      misconfiguration hazard — if anything *did* listen on 6379 it would be
 *      read as authoritative queue state.
 *   3. The shared connection uses `maxRetriesPerRequest: null` (correct for
 *      workers, which must block forever) which makes a CI sweep hang instead
 *      of degrading to database evidence.
 *
 * This module therefore refuses to connect at all unless `REDIS_URL` is
 * explicitly configured, uses bounded timeouts and a finite retry strategy, and
 * is always closable so a one-shot process leaks nothing.
 */

export type RetentionRedisHandle = {
  /** Present only when `REDIS_URL` was explicitly configured. */
  connection: Redis | null;
  /** Why the queue is unreadable, when `connection` is null. */
  unavailable: "not_configured" | null;
  /** Idempotent: closes the connection if one was opened. */
  close(): Promise<void>;
};

const CONNECT_TIMEOUT_MS = 3_000;
const COMMAND_TIMEOUT_MS = 2_000;

/**
 * Open a bounded connection for one sweep.
 *
 * Never throws: an unconfigured or unreachable Redis degrades to
 * `connection: null`, which the caller must surface as `unknown` evidence
 * (never as absence).
 */
export function openRetentionRedis(): RetentionRedisHandle {
  const url = readEnvironment().redisUrl;
  if (!url || url.trim() === "") {
    // Fail closed on evidence, not on the sweep: the dry-run still reports the
    // candidates it can establish from the database alone.
    logger.warn("retention.redis_not_configured", {
      // Variable NAME only — never a value.
      variable: "REDIS_URL",
      consequence: "queue evidence unknown; automatic job expiry disabled",
    });
    return { connection: null, unavailable: "not_configured", close: async () => {} };
  }

  const connection = new Redis(url, {
    // Bounded: a sweep must degrade, not hang, when Redis is slow or absent.
    connectTimeout: CONNECT_TIMEOUT_MS,
    commandTimeout: COMMAND_TIMEOUT_MS,
    maxRetriesPerRequest: 1,
    enableOfflineQueue: false,
    // A one-shot process gets one attempt; no open-ended reconnect loop.
    retryStrategy: () => null,
    lazyConnect: true,
    // Keep the event loop free even if teardown is delayed.
    autoResubscribe: false,
    autoResendUnfulfilledCommands: false,
  });
  // An unhandled 'error' event would crash the process on a dropped connection.
  connection.on("error", () => undefined);

  let closed = false;
  return {
    connection,
    unavailable: null,
    async close() {
      if (closed) return;
      closed = true;
      // `quit()` waits for a reply that may never come when the server is gone.
      connection.disconnect();
      if (connection.status !== "end") {
        await new Promise<void>((resolve) => {
          const timer = setTimeout(resolve, 1_000);
          timer.unref?.();
          connection.once("end", () => {
            clearTimeout(timer);
            resolve();
          });
        });
      }
    },
  };
}
