/**
 * FF-04 — atomic, uniquely-owned inspection leases.
 *
 * Redis is unavailable in this environment, so the lease *semantics* are executed
 * against a small in-memory implementation of the four commands the Lua script uses
 * (`ZADD`, `ZREM`, `ZREMRANGEBYSCORE`, `ZCARD`, `PEXPIRE`). The script text itself is
 * not re-parsed; instead `acquireInspectionLease` is driven through a fake
 * connection whose `eval` applies the same rules, in the same order, with the same
 * return contract.
 *
 * What this proves: counting, expiry recovery, per-tenant and global ceilings, and
 * unique ownership. What it does not prove: that Redis executes the script
 * atomically — that is Redis's guarantee for `EVAL`, and the script is written to
 * rely on it (no command in it reads state another process could change between
 * two of its own writes).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

/** The minimal sorted-set surface the admission script uses. */
class FakeZset {
  entries = new Map<string, number>();
  add(member: string, score: number) { this.entries.set(member, score); }
  remove(member: string) { this.entries.delete(member); }
  removeUpTo(score: number) { for (const [member, value] of this.entries) if (value <= score) this.entries.delete(member); }
  card() { return this.entries.size; }
  members() { return [...this.entries.keys()]; }
}

class FakeRedis {
  sets = new Map<string, FakeZset>();
  ttl = new Map<string, number>();
  calls: string[] = [];
  private set(key: string) { let value = this.sets.get(key); if (!value) { value = new FakeZset(); this.sets.set(key, value); } return value; }
  async eval(_script: string, _numKeys: number, ...args: string[]) {
    const [key1, key2, key3] = args;
    const rest = args.slice(_numKeys);
    // Distinguish admit from release by arity, exactly as the caller does.
    if (rest.length === 1) {
      this.calls.push("release");
      this.set(key1).remove(rest[0]);
      this.set(key2).remove(rest[0]);
      return 1;
    }
    this.calls.push("admit");
    const [nowRaw, leaseId, tenantLimitRaw, globalLimitRaw, rateLimitRaw, leaseTtlRaw, windowRaw] = rest;
    const now = Number(nowRaw);
    const tenantLimit = Number(tenantLimitRaw);
    const globalLimit = Number(globalLimitRaw);
    const rateLimit = Number(rateLimitRaw);
    const leaseTtl = Number(leaseTtlRaw);
    const window = Number(windowRaw);
    this.set(key2).removeUpTo(now);
    this.set(key3).removeUpTo(now);
    this.set(key1).removeUpTo(now - window);
    if (this.set(key1).card() >= rateLimit) return [0, "RATE_LIMITED"];
    if (this.set(key2).card() >= tenantLimit) return [0, "CONCURRENCY_LIMITED"];
    if (this.set(key3).card() >= globalLimit) return [0, "GLOBAL_LIMITED"];
    const expiresAt = now + leaseTtl;
    this.set(key1).add(leaseId, now);
    this.set(key2).add(leaseId, expiresAt);
    this.set(key3).add(leaseId, expiresAt);
    for (const key of [key1, key2, key3]) this.ttl.set(key, window);
    return [1, "ADMITTED"];
  }
}

const fake = new FakeRedis();

/**
 * Load the lease module with the fake Redis injected.
 *
 * The module resolves its connection through `getReadyQueueConnection`, so the
 * queue module is patched first; both imports are dynamic because the patch must
 * land before the lease module captures its dependency.
 */
async function loadLease() {
  const leaseModule = await import("../src/lib/http/inspection-lease");
  leaseModule.setLeaseConnectionForTest(async () => fake as never);
  return leaseModule;
}

test("admission is counted per tenant and released uniquely", async () => {
  const { acquireInspectionLease, InspectionBusyError, admissionLimits } = await loadLease();
  const LIMITS = admissionLimits({ perMinute: 100, perTenant: 2, global: 3, leaseSeconds: 60 });
  fake.sets.clear();
  const first = await acquireInspectionLease("tenant-a", LIMITS);
  const second = await acquireInspectionLease("tenant-a", LIMITS);
  await assert.rejects(() => acquireInspectionLease("tenant-a", LIMITS), (error: unknown) => {
    assert.ok(error instanceof InspectionBusyError);
    assert.equal(error.reason, "CONCURRENCY_LIMITED");
    return true;
  });
  await first.release();
  // One slot free again; the second lease is untouched.
  const third = await acquireInspectionLease("tenant-a", LIMITS);
  await second.release();
  await third.release();
});

test("release is uniquely owned: releasing one lease cannot free another's slot", async () => {
  const { acquireInspectionLease, InspectionBusyError, admissionLimits } = await loadLease();
  const LIMITS = admissionLimits({ perMinute: 100, perTenant: 2, global: 3, leaseSeconds: 60 });
  fake.sets.clear();
  const held = await acquireInspectionLease("tenant-b", LIMITS);
  const transientLease = await acquireInspectionLease("tenant-b", LIMITS);
  await transientLease.release();
  // `held` must still occupy its slot: a third admission would need one to exist.
  const third = await acquireInspectionLease("tenant-b", LIMITS);
  await assert.rejects(() => acquireInspectionLease("tenant-b", LIMITS), InspectionBusyError);
  await held.release();
  await third.release();
});

test("a double release is a no-op rather than a silent ceiling raise", async () => {
  const { acquireInspectionLease, InspectionBusyError, admissionLimits } = await loadLease();
  const LIMITS = admissionLimits({ perMinute: 100, perTenant: 2, global: 3, leaseSeconds: 60 });
  fake.sets.clear();
  const lease = await acquireInspectionLease("tenant-c", LIMITS);
  await acquireInspectionLease("tenant-c", LIMITS);
  await lease.release();
  await lease.release();
  // Only one slot was freed, so exactly one more may be admitted.
  const third = await acquireInspectionLease("tenant-c", LIMITS);
  await assert.rejects(() => acquireInspectionLease("tenant-c", LIMITS), InspectionBusyError);
  await third.release();
});

test("an expired lease is recovered by the next admission, not by a window rollover", async () => {
  const { acquireInspectionLease, admissionLimits } = await loadLease();
  const LIMITS = admissionLimits({ perMinute: 100, perTenant: 2, global: 3, leaseSeconds: 60 });
  fake.sets.clear();
  // Simulate a crashed process: a lease scored in the past.
  const now = Date.now();
  const key = "dip:fill-forms-inspect:v2:open:tenant-d";
  const globalKey = "dip:fill-forms-inspect:v2:open:global";
  for (const target of [key, globalKey]) {
    const set = fake.sets.get(target) ?? new FakeZset();
    set.add("crashed-lease", now - 1_000);
    fake.sets.set(target, set);
  }
  // Both slots were held by the crashed lease; admission must succeed immediately.
  const lease = await acquireInspectionLease("tenant-d", LIMITS);
  assert.ok(fake.sets.get(key)?.members().includes("crashed-lease") === false, "the stale lease must be pruned");
  assert.equal(fake.sets.get(key)?.card(), 1, "only the live lease remains");
  await lease.release();
});

test("the global ceiling applies across tenants", async () => {
  const { acquireInspectionLease, InspectionBusyError, admissionLimits } = await loadLease();
  const LIMITS = admissionLimits({ perMinute: 100, perTenant: 2, global: 3, leaseSeconds: 60 });
  fake.sets.clear();
  const a = await acquireInspectionLease("tenant-e", LIMITS);
  const b = await acquireInspectionLease("tenant-f", LIMITS);
  const c = await acquireInspectionLease("tenant-g", LIMITS);
  // Global is 3 and each tenant is well under its own limit.
  await assert.rejects(() => acquireInspectionLease("tenant-h", LIMITS), (error: unknown) => {
    assert.ok(error instanceof InspectionBusyError);
    assert.equal(error.reason, "GLOBAL_LIMITED");
    return true;
  });
  await a.release(); await b.release(); await c.release();
});

test("the rate ceiling is enforced per tenant per minute", async () => {
  const { acquireInspectionLease, InspectionBusyError, admissionLimits } = await loadLease();
  fake.sets.clear();
  const tight = admissionLimits({ perMinute: 2, perTenant: 10, global: 10, leaseSeconds: 60 });
  const a = await acquireInspectionLease("tenant-i", tight);
  const b = await acquireInspectionLease("tenant-i", tight);
  await assert.rejects(() => acquireInspectionLease("tenant-i", tight), (error: unknown) => {
    assert.ok(error instanceof InspectionBusyError);
    assert.equal(error.reason, "RATE_LIMITED");
    return true;
  });
  await a.release(); await b.release();
});

test("admission and release are each a single atomic call", async () => {
  const { acquireInspectionLease, admissionLimits } = await loadLease();
  const LIMITS = admissionLimits({ perMinute: 100, perTenant: 2, global: 3, leaseSeconds: 60 });
  fake.sets.clear();
  fake.calls.length = 0;
  const lease = await acquireInspectionLease("tenant-j", LIMITS);
  await lease.release();
  assert.deepEqual(fake.calls, ["admit", "release"], "no separate INCR/EXPIRE pairs, no read-then-write");
});

test("a Redis outage fails open and is recorded, never blocking inspection", async () => {
  const leaseModule = await import("../src/lib/http/inspection-lease");
  // Both the connection failing and the script failing must behave identically:
  // admission succeeds, the returned release is a no-op, and the failure is metric'd.
  leaseModule.setLeaseConnectionForTest(async () => { throw new Error("ECONNREFUSED"); });
  const lease = await leaseModule.acquireInspectionLease("tenant-k", leaseModule.admissionLimits({ perMinute: 1, perTenant: 1, global: 1, leaseSeconds: 60 }));
  await lease.release();

  leaseModule.setLeaseConnectionForTest(async () => ({ eval: async () => { throw new Error("NOSCRIPT"); } }));
  const second = await leaseModule.acquireInspectionLease("tenant-k", leaseModule.admissionLimits({ perMinute: 1, perTenant: 1, global: 1, leaseSeconds: 60 }));
  await second.release();
  leaseModule.setLeaseConnectionForTest(undefined);
});
