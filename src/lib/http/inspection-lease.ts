/**
 * Admission control for PDF inspection (FF-04).
 *
 * ## What was wrong with counters
 *
 * The previous implementation used `INCR` + `EXPIRE` on a per-tenant counter:
 *
 *   - **not atomic**: `INCR` and `EXPIRE` are two round trips, so a process that
 *     died between them left a key with no TTL — a counter that never expires and
 *     permanently wedges the tenant;
 *   - **expiry was not recovery**: the TTL was set once, on the first increment, so
 *     it bounded the *window*, not each *lease*. A lease taken at t=119 s of a
 *     120 s window vanished while the work was still running, and a crash leaked a
 *     slot until the window rolled over — with no way to tell a leak from live work;
 *   - **no ownership**: `DECR` released *some* slot, not *this* slot. A double
 *     release silently raised the ceiling and a late release from an expired
 *     request decremented someone else's window;
 *   - **tenant-only**: there was no global ceiling, so N tenants could each open
 *     their own maximum and exhaust the process together.
 *
 * ## What this does instead
 *
 * Each admitted inspection gets a **unique lease id** and a sorted set scored by
 * expiry. Admission, per-tenant and global counting, and the pruning of expired
 * leases all happen inside one Lua script, so they are atomic with respect to each
 * other and to other processes:
 *
 *   - a lease that outlives its TTL is pruned by the *next* admission, so a crash
 *     recovers in the time it takes the next caller to try rather than waiting for
 *     a window;
 *   - release is `ZREM` of *this* lease id, so it can never free another request's
 *     slot, and a double release is a no-op;
 *   - the global set bounds the whole process independently of the per-tenant set.
 *
 * Redis failures **fail open**: admission is availability-critical and the parser
 * pool already has its own hard concurrency bound in the worker boundary. A Redis
 * outage must not turn inspection into an outage, and the failure is recorded rather
 * than hidden.
 */
import { randomUUID } from "node:crypto";
import { getReadyQueueConnection } from "@/lib/queue";
import { runtimeLimits } from "@/lib/runtime/config";
import { logger } from "@/lib/logging";
import { recordMetric } from "@/lib/observability/metrics";

export type InspectionLease = { release: () => Promise<void> };

/**
 * The minimal Redis surface this module needs.
 *
 * Named as a type so tests can supply an in-memory implementation; the production
 * binding is the shared queue connection.
 */
export type LeaseRedis = { eval(script: string, numKeys: number, ...args: string[]): Promise<unknown> };

let connectionOverride: (() => Promise<LeaseRedis>) | undefined;

/** Replace the connection for tests. Never called from production code. */
export function setLeaseConnectionForTest(factory: (() => Promise<LeaseRedis>) | undefined) {
  connectionOverride = factory;
}

async function connect(): Promise<LeaseRedis> {
  if (connectionOverride) return connectionOverride();
  return (await getReadyQueueConnection()) as unknown as LeaseRedis;
}

export type AdmissionLimits = {
  perMinute: number;
  perTenant: number;
  global: number;
  leaseSeconds: number;
};

export function admissionLimits(overrides: Partial<AdmissionLimits> = {}): AdmissionLimits {
  // Proposed operational defaults, not approved product quotas: every field is
  // overridable through runtime configuration (see `runtime/config.ts`).
  return {
    perMinute: runtimeLimits.formInspectRatePerMinute,
    perTenant: runtimeLimits.formInspectConcurrency,
    global: runtimeLimits.formInspectGlobalConcurrency,
    leaseSeconds: 120,
    ...overrides,
  };
}

const KEY_PREFIX = "dip:fill-forms-inspect:v2";

/**
 * Admission in one atomic step.
 *
 * KEYS[1] rate counter, KEYS[2] tenant leases (zset), KEYS[3] global leases (zset)
 * ARGV[1] now (ms), ARGV[2] lease id, ARGV[3] per-tenant limit, ARGV[4] global
 * limit, ARGV[5] rate limit, ARGV[6] lease TTL (ms), ARGV[7] rate window (ms)
 *
 * Returns `{ ok, reason }` where reason is one of `ADMITTED`, `RATE_LIMITED`,
 * `CONCURRENCY_LIMITED`, `GLOBAL_LIMITED`.
 */
const ADMIT_SCRIPT = `
local now = tonumber(ARGV[1])
local leaseId = ARGV[2]
local tenantLimit = tonumber(ARGV[3])
local globalLimit = tonumber(ARGV[4])
local rateLimit = tonumber(ARGV[5])
local leaseTtl = tonumber(ARGV[6])
local window = tonumber(ARGV[7])

-- Expiry recovery: drop leases whose TTL has passed before counting, so a crashed
-- process frees its slot on the next attempt rather than at the end of a window.
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now)

-- Sliding rate window: prune entries older than one window, then count.
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
local rate = redis.call('ZCARD', KEYS[1])
if rate >= rateLimit then return {0, 'RATE_LIMITED'} end

if redis.call('ZCARD', KEYS[2]) >= tenantLimit then return {0, 'CONCURRENCY_LIMITED'} end
if redis.call('ZCARD', KEYS[3]) >= globalLimit then return {0, 'GLOBAL_LIMITED'} end

local expiresAt = now + leaseTtl
redis.call('ZADD', KEYS[1], now, leaseId)
redis.call('ZADD', KEYS[2], expiresAt, leaseId)
redis.call('ZADD', KEYS[3], expiresAt, leaseId)
-- The sets expire on their own even if nothing ever tries to admit again.
redis.call('PEXPIRE', KEYS[1], window)
redis.call('PEXPIRE', KEYS[2], leaseTtl * 2)
redis.call('PEXPIRE', KEYS[3], leaseTtl * 2)
return {1, 'ADMITTED'}
`;

const RELEASE_SCRIPT = `
redis.call('ZREM', KEYS[1], ARGV[1])
redis.call('ZREM', KEYS[2], ARGV[1])
return 1
`;

export class InspectionBusyError extends Error {
  readonly code = "INSPECTION_BUSY";
  constructor(readonly reason: "RATE_LIMITED" | "CONCURRENCY_LIMITED" | "GLOBAL_LIMITED") {
    super("Too many inspections are running.");
    this.name = "InspectionBusyError";
  }
}

export async function acquireInspectionLease(
  tenantId: string,
  limits: AdmissionLimits = admissionLimits(),
): Promise<InspectionLease> {
  const leaseId = randomUUID();
  const now = Date.now();
  let redis: LeaseRedis;
  try { redis = await connect(); }
  catch {
    // Fail open: a Redis outage must not take inspection down. Recorded, not hidden.
    logger.warn("fill_forms.admission_unavailable", { reason: "REDIS_UNAVAILABLE" });
    recordMetric("fill_forms_admission_fail_open", 1, "count", { reason: "redis" });
    return { release: async () => undefined };
  }
  const keys = [
    `${KEY_PREFIX}:rate:${tenantId}`,
    `${KEY_PREFIX}:open:${tenantId}`,
    `${KEY_PREFIX}:open:global`,
  ];
  let verdict: [number, string];
  try {
    verdict = (await redis.eval(
      ADMIT_SCRIPT, 3, ...keys,
      String(now), leaseId, String(limits.perTenant), String(limits.global),
      String(limits.perMinute), String(limits.leaseSeconds * 1_000), String(60_000),
    )) as [number, string];
  } catch {
    // Same reasoning as above: availability first, and the failure is visible.
    logger.warn("fill_forms.admission_unavailable", { reason: "SCRIPT_FAILED" });
    recordMetric("fill_forms_admission_fail_open", 1, "count", { reason: "script" });
    return { release: async () => undefined };
  }
  if (Number(verdict[0]) !== 1) throw new InspectionBusyError(String(verdict[1]) as InspectionBusyError["reason"]);
  let released = false;
  return {
    async release() {
      // Idempotent and uniquely owned: removing *this* id can never free
      // another request's slot, and a second call is a no-op.
      if (released) return;
      released = true;
      await redis.eval(RELEASE_SCRIPT, 2, keys[1], keys[2], leaseId).catch(() => undefined);
    },
  };
}
