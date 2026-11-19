import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { applyExpiryPlan, EXPIRABLE_STATUSES, type ExpiryWritePort } from "../src/lib/retention/expiry-write";

/**
 * Race between queue-liveness verification and the expiry write.
 *
 * The planner reads the queue, then writes. A job can be claimed in between. The
 * write is therefore an optimistic compare-and-set on `updatedAt`, which Prisma
 * bumps on every row write (including the claim that sets RUNNING).
 */

const HOUR = 60 * 60 * 1000;
const sweepStartedAt = new Date("2026-09-10T12:00:00Z");
const stale = new Date(sweepStartedAt.getTime() - 48 * HOUR);

type Row = { id: string; status: string; updatedAt: Date };

/** An in-memory stand-in for `job.updateMany` that honours the same predicate. */
function fakePort(rows: Row[]) {
  const calls: Array<{ where: unknown; data: unknown }> = [];
  const port: ExpiryWritePort = {
    async updateMany(args) {
      calls.push({ where: args.where, data: args.data });
      let count = 0;
      for (const row of rows) {
        if (!args.where.id.in.includes(row.id)) continue;
        if (!args.where.status.in.includes(row.status)) continue;
        // The optimistic guard under test.
        if (row.updatedAt.getTime() > args.where.updatedAt.lte.getTime()) continue;
        row.status = "EXPIRED";
        row.updatedAt = args.data.completedAt;
        count += 1;
      }
      return { count };
    },
  };
  return { port, rows, calls };
}

test("a job claimed mid-sweep is not expired even though its status is still expirable", async () => {
  // Planned as RETRYING with stale evidence; a worker claims it after planning.
  const claimed: Row = { id: "claimed", status: "RUNNING", updatedAt: new Date(sweepStartedAt.getTime() + 1_000) };
  const abandoned: Row = { id: "abandoned", status: "RETRYING", updatedAt: stale };
  const { port } = fakePort([claimed, abandoned]);

  const expired = await applyExpiryPlan(port, { expireIds: ["claimed", "abandoned"], sweepStartedAt, completedAt: sweepStartedAt });

  assert.equal(expired, 1, "only the genuinely abandoned job may be expired");
  assert.equal(claimed.status, "RUNNING", "a job claimed mid-sweep must survive");
  assert.equal(abandoned.status, "EXPIRED", "an untouched abandoned job is still reclaimed");
});

test("the old status-only guard would have expired the claimed job", async () => {
  // Demonstrate the bug this replaces: RUNNING is an expirable status, so a
  // status-only predicate matches a freshly claimed job.
  assert.ok((EXPIRABLE_STATUSES as readonly string[]).includes("RUNNING"), "RUNNING must remain expirable for genuinely abandoned work");
  const claimed: Row = { id: "claimed", status: "RUNNING", updatedAt: new Date(sweepStartedAt.getTime() + 1_000) };
  // Predicate *without* the updatedAt guard, mirroring the previous code.
  const statusOnlyMatches = claimed.status === "RUNNING" && (EXPIRABLE_STATUSES as readonly string[]).includes(claimed.status);
  assert.equal(statusOnlyMatches, true, "status alone admits a live job — hence the timestamp guard");

  const { port } = fakePort([claimed]);
  const expired = await applyExpiryPlan(port, { expireIds: ["claimed"], sweepStartedAt, completedAt: sweepStartedAt });
  assert.equal(expired, 0, "the timestamp guard must reject it");
});

test("a job that completed mid-sweep is not overwritten", async () => {
  const done: Row = { id: "done", status: "SUCCEEDED", updatedAt: new Date(sweepStartedAt.getTime() + 500) };
  const { port } = fakePort([done]);
  assert.equal(await applyExpiryPlan(port, { expireIds: ["done"], sweepStartedAt, completedAt: sweepStartedAt }), 0);
  assert.equal(done.status, "SUCCEEDED", "a terminal row must never be rewritten");
});

test("a cancelled-mid-sweep job is not overwritten", async () => {
  const cancelled: Row = { id: "cancelled", status: "CANCELLED", updatedAt: stale };
  const { port } = fakePort([cancelled]);
  assert.equal(await applyExpiryPlan(port, { expireIds: ["cancelled"], sweepStartedAt, completedAt: sweepStartedAt }), 0);
  assert.equal(cancelled.status, "CANCELLED");
});

test("the write is a single statement carrying all three guards", async () => {
  const { port, calls } = fakePort([]);
  await applyExpiryPlan(port, { expireIds: ["a", "b"], sweepStartedAt, completedAt: sweepStartedAt });
  assert.equal(calls.length, 1, "expiry must be one atomic updateMany, not a read-modify-write loop");
  const where = calls[0].where as { id: { in: string[] }; status: { in: string[] }; updatedAt: { lte: Date } };
  assert.deepEqual(where.id.in, ["a", "b"]);
  assert.deepEqual(where.status.in, [...EXPIRABLE_STATUSES]);
  assert.equal(where.updatedAt.lte.getTime(), sweepStartedAt.getTime());
});

test("no write is issued for an empty plan", async () => {
  const { port, calls } = fakePort([]);
  assert.equal(await applyExpiryPlan(port, { expireIds: [], sweepStartedAt, completedAt: sweepStartedAt }), 0);
  assert.equal(calls.length, 0, "an empty plan must not touch the database");
});

test("the sweep timestamp is captured before planning, not after", async () => {
  const source = await readFile(new URL("../scripts/cleanup-expired-jobs.ts", import.meta.url), "utf8");
  const start = source.indexOf("export async function expireStalledJobs");
  const end = source.indexOf("/**", start + 10);
  const body = source.slice(start, end);
  const sweepIndex = body.indexOf("const sweepStartedAt = now;");
  const planIndex = body.indexOf("await planStalledJobExpiry(");
  assert.ok(sweepIndex > 0, "the sweep must capture its start time");
  assert.ok(sweepIndex < planIndex, "the timestamp must predate planning, or a claim during planning would be admitted");
  assert.match(body, /applyExpiryPlan\(/);
  // The only database write must be the one inside the guarded port adapter;
  // there must be no second, unguarded mutation.
  const directWrites = (body.match(/await db\.job\.updateMany/g) ?? []).length;
  assert.equal(directWrites, 0, "the scheduler must not issue an unguarded updateMany itself");
  const adapterWrites = (body.match(/updateMany: \(args\) => db\.job\.updateMany/g) ?? []).length;
  assert.equal(adapterWrites, 1, "exactly one guarded adapter may exist");
});

test("the guarded write is unreachable from the dry-run path", async () => {
  const source = await readFile(new URL("../scripts/cleanup-expired-jobs.ts", import.meta.url), "utf8");
  const planFn = source.slice(source.indexOf("export async function planStalledJobExpiry"), source.indexOf("export async function expireStalledJobs"));
  for (const write of ["updateMany", "applyExpiryPlan", "create(", "delete("]) {
    assert.equal(planFn.includes(write), false, `planning must not call ${write}`);
  }
});
