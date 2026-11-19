import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  abandonedGraceMs,
  classifyJobExpiry,
  planJobExpiry,
  runningSilenceMs,
  type JobExpiryFacts,
  type JobLifecycleState,
} from "../src/lib/retention/job-expiry";

const now = new Date("2026-09-10T12:00:00Z");
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

function job(overrides: Partial<JobExpiryFacts> & { status?: JobLifecycleState } = {}): JobExpiryFacts {
  const createdAt = overrides.createdAt ?? new Date(now.getTime() - 30 * HOUR);
  return {
    id: overrides.id ?? `job-${Math.random().toString(36).slice(2)}`,
    status: overrides.status ?? "QUEUED",
    createdAt,
    startedAt: overrides.startedAt ?? null,
    updatedAt: overrides.updatedAt ?? createdAt,
    completedAt: overrides.completedAt ?? null,
    queue: overrides.queue ?? null,
  };
}

// ---------------------------------------------------------------------------
// The reported risk: a live RUNNING job must never expire on age alone
// ---------------------------------------------------------------------------

test("a RUNNING job with a live queue lease is never expired, however old", () => {
  const running = job({
    status: "RUNNING",
    createdAt: new Date(now.getTime() - 72 * HOUR),
    startedAt: new Date(now.getTime() - 72 * HOUR),
    updatedAt: new Date(now.getTime() - 5 * HOUR),
    queue: { lastActivityMs: now.getTime() - MINUTE, leased: true, activelyProcessing: true },
  });
  const decision = classifyJobExpiry(running, now);
  assert.equal(decision.expire, false);
  assert.equal(decision.reason, "running_still_leased");
});

test("a RUNNING job that is actively processing without a lock is not expired", () => {
  const running = job({
    status: "RUNNING",
    createdAt: new Date(now.getTime() - 30 * HOUR),
    startedAt: new Date(now.getTime() - 30 * HOUR),
    updatedAt: new Date(now.getTime() - 3 * HOUR),
    queue: { lastActivityMs: now.getTime() - 2 * MINUTE, leased: false, activelyProcessing: true },
  });
  assert.equal(classifyJobExpiry(running, now).expire, false);
});

test("a RUNNING job inside the silence window is not expired even with no queue evidence", () => {
  // This is the exact shape the old rule got wrong: created >24h ago, but the
  // current attempt is recent, so the row has been silent for less than one
  // plausible attempt.
  const running = job({
    status: "RUNNING",
    createdAt: new Date(now.getTime() - 26 * HOUR),
    startedAt: new Date(now.getTime() - 26 * HOUR),
    updatedAt: new Date(now.getTime() - 5 * MINUTE),
  });
  const decision = classifyJobExpiry(running, now);
  assert.equal(decision.expire, false);
  assert.equal(decision.reason, "running_recent_activity");
});

test("the old age-only rule would have expired this live RUNNING job", () => {
  const running = job({
    status: "RUNNING",
    createdAt: new Date(now.getTime() - 25 * HOUR),
    startedAt: new Date(now.getTime() - 25 * HOUR),
    updatedAt: new Date(now.getTime() - MINUTE),
  });
  // Old behaviour: createdAt < now - 24h  ->  expired. New behaviour: retained.
  assert.equal(running.createdAt.getTime() < now.getTime() - 24 * HOUR, true);
  assert.equal(classifyJobExpiry(running, now).expire, false);
});

test("a genuinely abandoned RUNNING job is expired once silence exceeds one attempt", () => {
  const running = job({
    status: "RUNNING",
    createdAt: new Date(now.getTime() - 30 * HOUR),
    startedAt: new Date(now.getTime() - 30 * HOUR),
    updatedAt: new Date(now.getTime() - (runningSilenceMs() + MINUTE)),
    queue: { lastActivityMs: now.getTime() - (runningSilenceMs() + MINUTE), leased: false, activelyProcessing: false },
  });
  const decision = classifyJobExpiry(running, now);
  assert.equal(decision.expire, true);
  assert.equal(decision.reason, "abandoned_running");
});

test("a RUNNING job whose queue attempt vanished and whose row is stale is expired", () => {
  const running = job({
    status: "RUNNING",
    createdAt: new Date(now.getTime() - 40 * HOUR),
    startedAt: new Date(now.getTime() - 40 * HOUR),
    updatedAt: new Date(now.getTime() - (runningSilenceMs() + HOUR)),
    queue: null,
  });
  assert.equal(classifyJobExpiry(running, now).expire, true);
});

// ---------------------------------------------------------------------------
// QUEUED / RETRYING / terminal states
// ---------------------------------------------------------------------------

test("a QUEUED job is retained inside the grace window", () => {
  const queued = job({ status: "QUEUED", createdAt: new Date(now.getTime() - HOUR), updatedAt: new Date(now.getTime() - HOUR) });
  const decision = classifyJobExpiry(queued, now);
  assert.equal(decision.expire, false);
  assert.equal(decision.reason, "queued_within_grace");
});

test("a QUEUED job past the grace window with no queue presence is expired", () => {
  const stale = new Date(now.getTime() - (abandonedGraceMs() + HOUR));
  const queued = job({ status: "QUEUED", createdAt: stale, updatedAt: stale, queue: null });
  const decision = classifyJobExpiry(queued, now);
  assert.equal(decision.expire, true);
  assert.equal(decision.reason, "stale_queue");
});

test("a RETRYING job inside the grace window is retained", () => {
  const retrying = job({ status: "RETRYING", createdAt: new Date(now.getTime() - 2 * HOUR), updatedAt: new Date(now.getTime() - MINUTE) });
  const decision = classifyJobExpiry(retrying, now);
  assert.equal(decision.expire, false);
  assert.equal(decision.reason, "retrying_within_grace");
});

test("a RETRYING job past grace but still tracked in the queue is retained", () => {
  const stale = new Date(now.getTime() - (abandonedGraceMs() + HOUR));
  const retrying = job({
    status: "RETRYING",
    createdAt: stale,
    updatedAt: stale,
    // Delayed for exponential backoff and gone quiet: still owned by BullMQ,
    // even though every timestamp on the row is older than the grace window.
    queue: { lastActivityMs: stale.getTime(), leased: false, activelyProcessing: false },
  });
  const decision = classifyJobExpiry(retrying, now);
  assert.equal(decision.expire, false);
  assert.equal(decision.reason, "retrying_active_queue");
});

test("a stale RETRYING job with no queue presence is expired", () => {
  const stale = new Date(now.getTime() - (abandonedGraceMs() + HOUR));
  const retrying = job({ status: "RETRYING", createdAt: stale, updatedAt: stale, queue: null });
  assert.equal(classifyJobExpiry(retrying, now).expire, true);
});

test("terminal jobs are never re-expired, even when ancient", () => {
  const ancient = new Date(now.getTime() - 365 * 24 * HOUR);
  for (const status of ["SUCCEEDED", "FAILED", "CANCELLED", "EXPIRED"] as const) {
    const terminal = job({ status, createdAt: ancient, updatedAt: ancient });
    const decision = classifyJobExpiry(terminal, now);
    assert.equal(decision.expire, false, `${status} must never expire`);
    assert.equal(decision.reason, "terminal");
  }
});

test("a job with completedAt set is treated as terminal regardless of status", () => {
  const odd = job({ status: "RUNNING", createdAt: new Date(now.getTime() - 40 * HOUR), updatedAt: new Date(now.getTime() - 40 * HOUR), completedAt: new Date(now.getTime() - 30 * HOUR) });
  assert.equal(classifyJobExpiry(odd, now).reason, "terminal");
});

// ---------------------------------------------------------------------------
// Batch planning and aggregate reporting
// ---------------------------------------------------------------------------

test("a mixed batch expires only the genuinely abandoned jobs", () => {
  const staleQueued = new Date(now.getTime() - (abandonedGraceMs() + HOUR));
  const jobs: JobExpiryFacts[] = [
    job({ id: "live-running", status: "RUNNING", createdAt: new Date(now.getTime() - 30 * HOUR), startedAt: new Date(now.getTime() - 30 * HOUR), updatedAt: new Date(now.getTime() - MINUTE), queue: { lastActivityMs: now.getTime(), leased: true, activelyProcessing: true } }),
    job({ id: "quiet-running", status: "RUNNING", createdAt: new Date(now.getTime() - 30 * HOUR), startedAt: new Date(now.getTime() - 30 * HOUR), updatedAt: new Date(now.getTime() - 2 * MINUTE) }),
    job({ id: "abandoned-running", status: "RUNNING", createdAt: new Date(now.getTime() - 40 * HOUR), startedAt: new Date(now.getTime() - 40 * HOUR), updatedAt: new Date(now.getTime() - (runningSilenceMs() + HOUR)), queue: null }),
    job({ id: "fresh-queued", status: "QUEUED", createdAt: new Date(now.getTime() - HOUR), updatedAt: new Date(now.getTime() - HOUR) }),
    job({ id: "stale-queued", status: "QUEUED", createdAt: staleQueued, updatedAt: staleQueued, queue: null }),
    job({ id: "retrying-active", status: "RETRYING", createdAt: staleQueued, updatedAt: staleQueued, queue: { lastActivityMs: now.getTime(), leased: false, activelyProcessing: false } }),
    job({ id: "done", status: "SUCCEEDED", createdAt: staleQueued, updatedAt: staleQueued }),
  ];

  const plan = planJobExpiry(jobs, now);
  assert.deepEqual(plan.expireIds, ["abandoned-running", "stale-queued"]);
  assert.deepEqual(plan.counts, {
    scanned: 7,
    expired: 2,
    abandonedRunning: 1,
    staleQueue: 1,
    runningStillActive: 2,
    withinGrace: 2,
  });
});

test("planning is deterministic and reports the bounds it applied", () => {
  const jobs = [job({ id: "a" }), job({ id: "b", status: "SUCCEEDED" })];
  assert.deepEqual(planJobExpiry(jobs, now), planJobExpiry(jobs, now));
  const plan = planJobExpiry(jobs, now);
  assert.deepEqual(plan.policy, { abandonedGraceMs: abandonedGraceMs(), runningSilenceMs: runningSilenceMs() });
});

test("the RUNNING silence window is strictly longer than the longest attempt", () => {
  // A row is legitimately quiet for the whole duration of a single attempt, so
  // the silence window must exceed the job timeout, or live work would expire.
  assert.ok(runningSilenceMs() > 30 * MINUTE, "silence window must exceed the maximum JOB_TIMEOUT_MS");
});

// ---------------------------------------------------------------------------
// Scheduler wiring guards
// ---------------------------------------------------------------------------

test("the scheduler never writes job state in dry-run mode", async () => {
  const source = await readFile(new URL("../scripts/cleanup-expired-jobs.ts", import.meta.url), "utf8");
  const planFn = source.slice(source.indexOf("export async function planStalledJobExpiry"), source.indexOf("export async function expireStalledJobs"));
  for (const write of ["updateMany", "update(", "create(", "delete("]) {
    assert.equal(planFn.includes(write), false, `planning must not call ${write}`);
  }
  // The mutation is gated on apply mode and guarded by a repeated status check.
  assert.match(source, /if \(mode !== "apply" \|\| plan\.expireIds\.length === 0\) return 0;/);
  assert.match(source, /status: \{ in: \["QUEUED", "RETRYING", "RUNNING"\] \}/);
});

test("dry-run reports expiry candidates without terminating them", async () => {
  const source = await readFile(new URL("../scripts/cleanup-expired-jobs.ts", import.meta.url), "utf8");
  // Dry-run must reach the plan-only path and report its candidate count.
  assert.match(source, /const expiredJobs = apply\s*\n?\s*\? await expireStalledJobs\(\{ mode: "apply" \}\)/);
  assert.match(source, /planStalledJobExpiry\(\{ mode: "plan" \}\)\)\.plan\.counts\.expired/);
});

test("expiry no longer selects jobs by createdAt age alone", async () => {
  const source = await readFile(new URL("../scripts/cleanup-expired-jobs.ts", import.meta.url), "utf8");
  // The old single window was created/lt on createdAt for every status.
  assert.equal(/status: \{ in: \["QUEUED", "RETRYING", "RUNNING"\] \}, createdAt: \{ lt: cutoff \}/.test(source), false);
  // RUNNING is selected on startedAt/updatedAt silence, not raw age.
  assert.match(source, /status: "RUNNING"[\s\S]*?startedAt: \{ lt: silenceFloor \}/);
});

test("an unreadable queue degrades to database evidence instead of expiring live work", async () => {
  const source = await readFile(new URL("../src/lib/retention/queue-activity.ts", import.meta.url), "utf8");
  // A Redis failure must skip the job (treat as unknown), not mark it leased=false aggressively.
  assert.match(source, /catch \{[\s\S]*?continue;/);
  const scheduler = await readFile(new URL("../scripts/cleanup-expired-jobs.ts", import.meta.url), "utf8");
  assert.match(scheduler, /catch \{\s*\/\/ Without Redis the sweep still runs, but every job looks queue-unknown/);
});
