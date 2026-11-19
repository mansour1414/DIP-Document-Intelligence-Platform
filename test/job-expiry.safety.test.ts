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
  type QueueEvidence,
} from "../src/lib/retention/job-expiry";
import { resolveEvidence, type QueueReadResult } from "../src/lib/retention/queue-activity";

const now = new Date("2026-09-10T12:00:00Z");
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

const ABSENT: QueueEvidence = { state: "absent" };
const UNKNOWN: QueueEvidence = { state: "unknown", reason: "error" };

/** Evidence for a job BullMQ still holds a live lock on. */
function leased(lastActivityMs: number): QueueEvidence {
  return { state: "present", lastActivityMs, leased: true, activelyProcessing: true };
}
/** Evidence for a job BullMQ tracks but is not currently processing. */
function tracked(lastActivityMs: number, activelyProcessing = false): QueueEvidence {
  return { state: "present", lastActivityMs, leased: false, activelyProcessing };
}

function job(overrides: Partial<JobExpiryFacts> & { status?: JobLifecycleState } = {}): JobExpiryFacts {
  const createdAt = overrides.createdAt ?? new Date(now.getTime() - 30 * HOUR);
  return {
    id: overrides.id ?? `job-${Math.random().toString(36).slice(2)}`,
    status: overrides.status ?? "QUEUED",
    createdAt,
    startedAt: overrides.startedAt ?? null,
    updatedAt: overrides.updatedAt ?? createdAt,
    completedAt: overrides.completedAt ?? null,
    queue: overrides.queue ?? ABSENT,
  };
}

// ---------------------------------------------------------------------------
// 1. A live lock always prevents expiry
// ---------------------------------------------------------------------------

test("a live lock prevents expiry even when processedOn is ancient", () => {
  // The exact bug: an old `processedOn` must not outrank a lock that exists now.
  const ancient = now.getTime() - 96 * HOUR;
  const running = job({
    status: "RUNNING",
    createdAt: new Date(ancient),
    startedAt: new Date(ancient),
    updatedAt: new Date(ancient),
    queue: leased(ancient),
  });
  const decision = classifyJobExpiry(running, now);
  assert.equal(decision.expire, false);
  assert.equal(decision.reason, "running_still_leased");
});

test("a lock prevents expiry at any age, with no time horizon applied to it", () => {
  for (const ageHours of [1, 6, 23, 25, 48, 24 * 30]) {
    const stamp = now.getTime() - ageHours * HOUR;
    const running = job({ status: "RUNNING", createdAt: new Date(stamp), startedAt: new Date(stamp), updatedAt: new Date(stamp), queue: leased(stamp) });
    assert.equal(classifyJobExpiry(running, now).expire, false, `lock must hold at ${ageHours}h`);
  }
});

test("a renewed lock keeps a long-lived job alive even when the row is stale", () => {
  // Worker heartbeats the lock while the row stays quiet for a >24h attempt.
  const started = new Date(now.getTime() - 30 * HOUR);
  const running = job({ status: "RUNNING", createdAt: started, startedAt: started, updatedAt: started, queue: leased(now.getTime() - 5_000) });
  const decision = classifyJobExpiry(running, now);
  assert.equal(decision.expire, false);
  assert.equal(decision.reason, "running_still_leased");
});

test("an active attempt without a lock is still not expired", () => {
  const running = job({ status: "RUNNING", createdAt: new Date(now.getTime() - 30 * HOUR), startedAt: new Date(now.getTime() - 30 * HOUR), updatedAt: new Date(now.getTime() - 3 * HOUR), queue: tracked(now.getTime() - 2 * MINUTE, true) });
  const decision = classifyJobExpiry(running, now);
  assert.equal(decision.expire, false);
  assert.equal(decision.reason, "running_active_attempt");
});

test("a RUNNING job whose attempt is waiting on the queue is not expired", () => {
  const old = new Date(now.getTime() - 40 * HOUR);
  const running = job({ status: "RUNNING", createdAt: old, startedAt: old, updatedAt: old, queue: tracked(old.getTime()) });
  assert.equal(classifyJobExpiry(running, now).expire, false);
});

// ---------------------------------------------------------------------------
// 2. Unknown never permits expiry
// ---------------------------------------------------------------------------

test("UNKNOWN queue state prevents expiry for every non-terminal status", () => {
  const old = new Date(now.getTime() - 30 * 24 * HOUR);
  for (const status of ["QUEUED", "RUNNING", "RETRYING"] as const) {
    const subject = job({ status, createdAt: old, startedAt: status === "RUNNING" ? old : null, updatedAt: old, queue: UNKNOWN });
    const decision = classifyJobExpiry(subject, now);
    assert.equal(decision.expire, false, `${status} must not expire while queue state is unknown`);
    assert.equal(decision.reason === "running_queue_unknown" || decision.reason === "retry_queue_unknown", true);
  }
});

test("every unknown reason prevents expiry", () => {
  const old = new Date(now.getTime() - 30 * 24 * HOUR);
  for (const reason of ["not_configured", "unavailable", "error"] as const) {
    const running = job({ status: "RUNNING", createdAt: old, startedAt: old, updatedAt: old, queue: { state: "unknown", reason } });
    assert.equal(classifyJobExpiry(running, now).expire, false, `reason=${reason}`);
  }
});

test("a partial queue read makes every unlisted job unknown, not absent", () => {
  // Queue A was read completely; queue B errored. A job found in neither must be
  // unknown, because B might have held it.
  const reads: QueueReadResult[] = [
    { present: new Map([["known", { lastActivityMs: now.getTime(), leased: true, activelyProcessing: true }]]), ok: true },
    { present: new Map(), ok: false },
  ];
  assert.deepEqual(resolveEvidence("known", reads), { state: "present", lastActivityMs: now.getTime(), leased: true, activelyProcessing: true });
  assert.deepEqual(resolveEvidence("missing", reads), { state: "unknown", reason: "error" });
});

test("confirmed absence requires every queue to be read successfully", () => {
  const allOk: QueueReadResult[] = [
    { present: new Map(), ok: true },
    { present: new Map(), ok: true },
  ];
  assert.deepEqual(resolveEvidence("missing", allOk), { state: "absent" });
  // One failed queue downgrades absence to unknown.
  assert.deepEqual(resolveEvidence("missing", [...allOk, { present: new Map(), ok: false }]), { state: "unknown", reason: "error" });
});

test("an empty read set is unknown, never absent", () => {
  assert.deepEqual(resolveEvidence("missing", []), { state: "unknown", reason: "error" });
});

// ---------------------------------------------------------------------------
// 3. Confirmed absence still allows cleanup
// ---------------------------------------------------------------------------

test("a genuinely abandoned RUNNING job with confirmed absence is expired", () => {
  const old = new Date(now.getTime() - (runningSilenceMs() + HOUR));
  const running = job({ status: "RUNNING", createdAt: old, startedAt: old, updatedAt: old, queue: ABSENT });
  const decision = classifyJobExpiry(running, now);
  assert.equal(decision.expire, true);
  assert.equal(decision.reason, "abandoned_running");
});

test("a RUNNING job inside the silence window is retained even with confirmed absence", () => {
  const running = job({ status: "RUNNING", createdAt: new Date(now.getTime() - 26 * HOUR), startedAt: new Date(now.getTime() - 26 * HOUR), updatedAt: new Date(now.getTime() - 5 * MINUTE), queue: ABSENT });
  const decision = classifyJobExpiry(running, now);
  assert.equal(decision.expire, false);
  assert.equal(decision.reason, "running_recent_activity");
});

test("a stale QUEUED job with confirmed absence is expired", () => {
  const old = new Date(now.getTime() - (abandonedGraceMs() + HOUR));
  const queued = job({ status: "QUEUED", createdAt: old, updatedAt: old, queue: ABSENT });
  const decision = classifyJobExpiry(queued, now);
  assert.equal(decision.expire, true);
  assert.equal(decision.reason, "stale_queue");
});

test("a QUEUED job inside the grace window is retained", () => {
  const queued = job({ status: "QUEUED", createdAt: new Date(now.getTime() - HOUR), updatedAt: new Date(now.getTime() - HOUR) });
  const decision = classifyJobExpiry(queued, now);
  assert.equal(decision.expire, false);
  assert.equal(decision.reason, "queued_within_grace");
});

// ---------------------------------------------------------------------------
// Delayed retries
// ---------------------------------------------------------------------------

test("a delayed retry past grace is retained while BullMQ still tracks it", () => {
  const old = new Date(now.getTime() - (abandonedGraceMs() + 6 * HOUR));
  const retrying = job({ status: "RETRYING", createdAt: old, updatedAt: old, queue: tracked(old.getTime()) });
  const decision = classifyJobExpiry(retrying, now);
  assert.equal(decision.expire, false);
  assert.equal(decision.reason, "retry_queue_present");
});

test("a delayed retry is retained even when the queue read is incomplete", () => {
  const old = new Date(now.getTime() - (abandonedGraceMs() + HOUR));
  const retrying = job({ status: "RETRYING", createdAt: old, updatedAt: old, queue: UNKNOWN });
  const decision = classifyJobExpiry(retrying, now);
  assert.equal(decision.expire, false);
  assert.equal(decision.reason, "retry_queue_unknown");
});

test("a RETRYING job with confirmed absence past grace is expired", () => {
  const old = new Date(now.getTime() - (abandonedGraceMs() + HOUR));
  const retrying = job({ status: "RETRYING", createdAt: old, updatedAt: old, queue: ABSENT });
  assert.equal(classifyJobExpiry(retrying, now).expire, true);
});

// ---------------------------------------------------------------------------
// Terminal states
// ---------------------------------------------------------------------------

test("terminal jobs are never re-expired, even when ancient", () => {
  const ancient = new Date(now.getTime() - 365 * 24 * HOUR);
  for (const status of ["SUCCEEDED", "FAILED", "CANCELLED", "EXPIRED"] as const) {
    const terminal = job({ status, createdAt: ancient, updatedAt: ancient, queue: UNKNOWN });
    const decision = classifyJobExpiry(terminal, now);
    assert.equal(decision.expire, false, `${status} must never expire`);
    assert.equal(decision.reason, "terminal");
  }
});

test("completedAt forces the terminal branch regardless of status", () => {
  const old = new Date(now.getTime() - 40 * HOUR);
  const odd = job({ status: "RUNNING", createdAt: old, updatedAt: old, completedAt: new Date(now.getTime() - 30 * HOUR) });
  assert.equal(classifyJobExpiry(odd, now).reason, "terminal");
});

// ---------------------------------------------------------------------------
// 4. The 24h RUNNING boundary is preserved
// ---------------------------------------------------------------------------

test("the RUNNING silence window is never shorter than the previous 24h boundary", () => {
  assert.ok(runningSilenceMs() >= 24 * HOUR, "must not shorten the approved 24h RUNNING boundary");
});

test("the RUNNING silence window exceeds one full attempt", () => {
  assert.ok(runningSilenceMs() > 30 * MINUTE, "must exceed the maximum JOB_TIMEOUT_MS");
});

test("a RUNNING job just under 24h silent is retained, and just over is expired", () => {
  const under = new Date(now.getTime() - (runningSilenceMs() - HOUR));
  const over = new Date(now.getTime() - (runningSilenceMs() + HOUR));
  assert.equal(classifyJobExpiry(job({ status: "RUNNING", createdAt: under, startedAt: under, updatedAt: under, queue: ABSENT }), now).expire, false);
  assert.equal(classifyJobExpiry(job({ status: "RUNNING", createdAt: over, startedAt: over, updatedAt: over, queue: ABSENT }), now).expire, true);
});

// ---------------------------------------------------------------------------
// Batch planning
// ---------------------------------------------------------------------------

test("a mixed batch expires only confirmed-absent jobs", () => {
  const graceOld = new Date(now.getTime() - (abandonedGraceMs() + HOUR));
  const silenceOld = new Date(now.getTime() - (runningSilenceMs() + HOUR));
  const jobs: JobExpiryFacts[] = [
    job({ id: "leased-running", status: "RUNNING", createdAt: silenceOld, startedAt: silenceOld, updatedAt: silenceOld, queue: leased(silenceOld.getTime()) }),
    job({ id: "unknown-running", status: "RUNNING", createdAt: silenceOld, startedAt: silenceOld, updatedAt: silenceOld, queue: UNKNOWN }),
    job({ id: "abandoned-running", status: "RUNNING", createdAt: silenceOld, startedAt: silenceOld, updatedAt: silenceOld, queue: ABSENT }),
    job({ id: "fresh-queued", status: "QUEUED", createdAt: new Date(now.getTime() - HOUR), updatedAt: new Date(now.getTime() - HOUR) }),
    job({ id: "stale-queued", status: "QUEUED", createdAt: graceOld, updatedAt: graceOld, queue: ABSENT }),
    job({ id: "delayed-retry", status: "RETRYING", createdAt: graceOld, updatedAt: graceOld, queue: tracked(graceOld.getTime()) }),
    job({ id: "unknown-retry", status: "RETRYING", createdAt: graceOld, updatedAt: graceOld, queue: UNKNOWN }),
    job({ id: "done", status: "SUCCEEDED", createdAt: graceOld, updatedAt: graceOld }),
  ];

  const plan = planJobExpiry(jobs, now);
  assert.deepEqual(plan.expireIds, ["abandoned-running", "stale-queued"]);
  assert.deepEqual(plan.counts, {
    scanned: 8,
    expired: 2,
    abandonedRunning: 1,
    staleQueue: 1,
    runningStillActive: 1,
    withinGrace: 2,
    queueUnknown: 2,
  });
});

test("planning is deterministic and reports the bounds it applied", () => {
  const jobs = [job({ id: "a" }), job({ id: "b", status: "SUCCEEDED" })];
  assert.deepEqual(planJobExpiry(jobs, now), planJobExpiry(jobs, now));
  assert.deepEqual(planJobExpiry(jobs, now).policy, { abandonedGraceMs: abandonedGraceMs(), runningSilenceMs: runningSilenceMs() });
});

test("an entirely unknown batch expires nothing", () => {
  const old = new Date(now.getTime() - 90 * 24 * HOUR);
  const jobs = (["QUEUED", "RUNNING", "RETRYING"] as const).map((status) => job({ status, createdAt: old, startedAt: status === "RUNNING" ? old : null, updatedAt: old, queue: UNKNOWN }));
  const plan = planJobExpiry(jobs, now);
  assert.deepEqual(plan.expireIds, []);
  assert.equal(plan.counts.queueUnknown, 3);
});

// ---------------------------------------------------------------------------
// 5. Scheduler wiring guards
// ---------------------------------------------------------------------------

test("the scheduler never writes job state while planning", async () => {
  const source = await readFile(new URL("../scripts/cleanup-expired-jobs.ts", import.meta.url), "utf8");
  const planFn = source.slice(source.indexOf("export async function planStalledJobExpiry"), source.indexOf("export async function expireStalledJobs"));
  for (const write of ["updateMany", "update(", "create(", "delete(", "applyExpiryPlan"]) {
    assert.equal(planFn.includes(write), false, `planning must not call ${write}`);
  }
  assert.match(source, /if \(mode !== "apply" \|\| plan\.expireIds\.length === 0\) return 0;/);
  // The status guard now lives in the guarded write port alongside the
  // optimistic `updatedAt` bound.
  assert.match(source, /applyExpiryPlan\(/);
  const writePort = await readFile(new URL("../src/lib/retention/expiry-write.ts", import.meta.url), "utf8");
  assert.match(writePort, /status: { in: EXPIRABLE_STATUSES }/);
  assert.match(writePort, /updatedAt: { lte: input\.sweepStartedAt }/);
});

test("dry-run reports candidates without terminating them", async () => {
  const source = await readFile(new URL("../scripts/cleanup-expired-jobs.ts", import.meta.url), "utf8");
  assert.match(source, /const expiredJobs = apply\s*\n?\s*\? await expireStalledJobs\(\{ mode: "apply" \}\)/);
  assert.match(source, /planStalledJobExpiry\(\{ mode: "plan" \}\)\)\.plan\.counts\.expired/);
});

test("expiry no longer selects jobs by createdAt age alone", async () => {
  const source = await readFile(new URL("../scripts/cleanup-expired-jobs.ts", import.meta.url), "utf8");
  assert.equal(/status: \{ in: \["QUEUED", "RETRYING", "RUNNING"\] \}, createdAt: \{ lt: cutoff \}/.test(source), false);
  assert.match(source, /status: "RUNNING"[\s\S]*?startedAt: \{ lt: silenceFloor \}/);
});

test("the scheduler closes the Redis connection on every path", async () => {
  const source = await readFile(new URL("../scripts/cleanup-expired-jobs.ts", import.meta.url), "utf8");
  assert.match(source, /finally \{[\s\S]*?await provider\.close\(\)/);
  assert.match(source, /if \(ownsProvider\) await provider\.close\(\)/);
});

test("a provider that reads zero queues yields unknown, never absent", async () => {
  const source = await readFile(new URL("../scripts/cleanup-expired-jobs.ts", import.meta.url), "utf8");
  // "No queues were read" is not evidence of absence.
  assert.match(source, /if \(reads\.length === 0\) return jobs\.map\(\(job\) => \(\{ \.\.\.job, queue: unknownEvidence\("error"\) \}\)\);/);
});

test("an unconfigured queue provider reports unknown, never absent", async () => {
  const source = await readFile(new URL("../scripts/cleanup-expired-jobs.ts", import.meta.url), "utf8");
  assert.match(source, /unavailable: "not_configured"/);
  assert.match(source, /options\.queueUnavailable \?\? provider\.unavailable/);
});
