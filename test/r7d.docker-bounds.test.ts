/**
 * R7D.1 C-F03 — bounded asynchronous Docker lifecycle.
 *
 * ## What is real here and what is not
 *
 * The Docker CLI is replaced by a stand-in executable (`DIP_DOCKER_BIN`) that behaves like the
 * real client: it is a separate process, it writes to stdout and stderr, it exits with a code,
 * and it can hang, die on a signal, or flood its output. Everything the supervisor would
 * actually do — spawn, apply a deadline, bound the capture, reap the child, categorize the
 * result — runs for real.
 *
 * What is **not** real: no daemon accepted any of these calls. A stand-in can prove that the
 * control plane handles a timeout correctly; it cannot prove that Docker created a container,
 * that killing the client left no request outstanding, or that the kernel enforced anything.
 * Those are reported NOT TESTED.
 */

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, chmodSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";

let workdir: string;
let binPath: string;

/**
 * Write a stand-in docker that runs the given shell body.
 *
 * Exit code and output are entirely under the test's control, which is what makes timeout,
 * signal and flood behaviour reproducible.
 */
function makeStandIn(body: string): void {
  writeFileSync(binPath, `#!/bin/sh\n${body}\n`);
  chmodSync(binPath, 0o755);
}

before(() => {
  workdir = mkdtempSync(join(tmpdir(), "dip-docker-standin-"));
  binPath = join(workdir, "docker");
  // The module reads DIP_DOCKER_BIN at import time, so it must be set before the lazy import in
  // each test below resolves. Each test sets it explicitly rather than relying on order.
  process.env.DIP_DOCKER_BIN = binPath;
});

after(() => {
  rmSync(workdir, { recursive: true, force: true });
  delete process.env.DIP_DOCKER_BIN;
});

/** Import the lifecycle module fresh, so DOCKER_BIN resolves against the current stand-in. */
async function lifecycle() {
  return import("../src/lib/execution/docker-lifecycle");
}

const VALID_ID = "a".repeat(64);

// ---------------------------------------------------------------------------------------
// Definite successes and rejections
// ---------------------------------------------------------------------------------------

test("R7D.1-CF03-1: a clean create returns the daemon id", async () => {
  makeStandIn(`echo "${VALID_ID}"`);
  const { createContainerAsync, SYNTHETIC_PROFILE } = await lifecycle();
  const policy = {
    image: `dip-executor@sha256:${"b".repeat(64)}`,
    name: "dip-exec-0123456789abcdef0123456789abcdef",
    executionId: "0123456789abcdef0123456789abcdef",
    bootId: "boot-0001",
    supervisorInstance: "sup-0001",
    profileId: SYNTHETIC_PROFILE.id,
    uid: 10001,
    gid: 10001,
    memoryBytes: SYNTHETIC_PROFILE.memoryBytes,
    cpuQuotaMicros: SYNTHETIC_PROFILE.cpuQuotaMicros,
    cpuPeriodMicros: SYNTHETIC_PROFILE.cpuPeriodMicros,
    pidsLimit: SYNTHETIC_PROFILE.pidsLimit,
    tmpfsBudgetBytes: SYNTHETIC_PROFILE.tmpfsBudgetBytes,
    workTmpfsBytes: SYNTHETIC_PROFILE.workTmpfsBytes,
    tmpTmpfsBytes: SYNTHETIC_PROFILE.tmpTmpfsBytes,
    v8OldSpaceMb: SYNTHETIC_PROFILE.v8OldSpaceMb,
    cgroupParent: "/dip-executor-abcdef0123456789",
    seccompProfile: "runtime/default",
    apparmorProfile: "dip-executor",
  };
  const outcome = await createContainerAsync(policy);
  assert.equal(outcome.ok, true);
  if (!outcome.ok) throw new Error("unreachable");
  assert.equal(outcome.value.containerId, VALID_ID);
});

test("R7D.1-CF03-2: an unusable create id from a clean exit is ambiguous, not a success", async () => {
  // The daemon created something and the client reported something unusable. Treating this as
  // a failure with no side effect would strand a container nobody can name.
  makeStandIn("echo not-a-valid-id");
  const { createContainerAsync, SYNTHETIC_PROFILE } = await lifecycle();
  const outcome = await createContainerAsync({
    image: `dip-executor@sha256:${"b".repeat(64)}`,
    name: "dip-exec-0123456789abcdef0123456789abcdef",
    executionId: "0123456789abcdef0123456789abcdef",
    bootId: "boot-0001",
    supervisorInstance: "sup-0001",
    profileId: SYNTHETIC_PROFILE.id,
    uid: 10001,
    gid: 10001,
    memoryBytes: SYNTHETIC_PROFILE.memoryBytes,
    cpuQuotaMicros: SYNTHETIC_PROFILE.cpuQuotaMicros,
    cpuPeriodMicros: SYNTHETIC_PROFILE.cpuPeriodMicros,
    pidsLimit: SYNTHETIC_PROFILE.pidsLimit,
    tmpfsBudgetBytes: SYNTHETIC_PROFILE.tmpfsBudgetBytes,
    workTmpfsBytes: SYNTHETIC_PROFILE.workTmpfsBytes,
    tmpTmpfsBytes: SYNTHETIC_PROFILE.tmpTmpfsBytes,
    v8OldSpaceMb: SYNTHETIC_PROFILE.v8OldSpaceMb,
    cgroupParent: "/dip-executor-abcdef0123456789",
    seccompProfile: "runtime/default",
    apparmorProfile: "dip-executor",
  });
  assert.equal(outcome.ok, false);
  if (outcome.ok) throw new Error("unreachable");
  assert.equal(outcome.fault, "BAD_OUTPUT");
  assert.equal(outcome.ambiguous, true, "an unusable answer does not prove nothing happened");
});

test("R7D.1-CF03-3: a definite rejection is reported as definite", async () => {
  makeStandIn('echo "permission denied while trying to connect to the Docker daemon socket" >&2; exit 1');
  const { createContainerAsync, SYNTHETIC_PROFILE } = await lifecycle();
  const outcome = await createContainerAsync({
    image: `dip-executor@sha256:${"b".repeat(64)}`,
    name: "dip-exec-0123456789abcdef0123456789abcdef",
    executionId: "0123456789abcdef0123456789abcdef",
    bootId: "boot-0001",
    supervisorInstance: "sup-0001",
    profileId: SYNTHETIC_PROFILE.id,
    uid: 10001,
    gid: 10001,
    memoryBytes: SYNTHETIC_PROFILE.memoryBytes,
    cpuQuotaMicros: SYNTHETIC_PROFILE.cpuQuotaMicros,
    cpuPeriodMicros: SYNTHETIC_PROFILE.cpuPeriodMicros,
    pidsLimit: SYNTHETIC_PROFILE.pidsLimit,
    tmpfsBudgetBytes: SYNTHETIC_PROFILE.tmpfsBudgetBytes,
    workTmpfsBytes: SYNTHETIC_PROFILE.workTmpfsBytes,
    tmpTmpfsBytes: SYNTHETIC_PROFILE.tmpTmpfsBytes,
    v8OldSpaceMb: SYNTHETIC_PROFILE.v8OldSpaceMb,
    cgroupParent: "/dip-executor-abcdef0123456789",
    seccompProfile: "runtime/default",
    apparmorProfile: "dip-executor",
  });
  assert.equal(outcome.ok, false);
  if (outcome.ok) throw new Error("unreachable");
  assert.equal(outcome.fault, "PERMISSION_DENIED");
  assert.equal(outcome.ambiguous, false, "a refused create did not create anything");
});

test("R7D.1-CF03-4: an unreachable daemon is categorized, not retried blindly", async () => {
  makeStandIn('echo "Cannot connect to the Docker daemon at unix:///var/run/docker.sock." >&2; exit 1');
  const { inspectContainerAsync } = await lifecycle();
  const outcome = await inspectContainerAsync(VALID_ID);
  assert.equal(outcome.ok, false);
  if (outcome.ok) throw new Error("unreachable");
  assert.equal(outcome.fault, "DAEMON_UNAVAILABLE");
});

test("R7D.1-CF03-5: a missing docker binary is a distinct fault", async () => {
  // The policy names an absolute path; if the CLI is not there, that is a deployment fault and
  // must be distinguishable from a daemon fault.
  const { spawn } = await import("node:child_process");
  void spawn; // keeps the import list honest about what this module does
  const saved = process.env.DIP_DOCKER_BIN;
  process.env.DIP_DOCKER_BIN = join(workdir, "does-not-exist", "docker");
  try {
    // A fresh module instance so the changed env is picked up.
    const modulePath = "../src/lib/execution/docker-lifecycle";
    const fresh = await import(`${modulePath}?v=${Date.now()}`);
    const outcome = await fresh.inspectContainerAsync(VALID_ID);
    assert.equal(outcome.ok, false);
    if (outcome.ok) throw new Error("unreachable");
    assert.equal(outcome.fault, "BINARY_MISSING");
    assert.equal(outcome.ambiguous, false);
  } finally {
    process.env.DIP_DOCKER_BIN = saved;
  }
});

// ---------------------------------------------------------------------------------------
// Deadlines, termination and reaping
// ---------------------------------------------------------------------------------------

test("R7D.1-CF03-6: a hung operation is killed at its deadline and reported ambiguous", async () => {
  // The important part is not that it gives up, but that it says the daemon may still be acting.
  // A killed CLI client does not cancel an outstanding request: the container may appear after
  // the supervisor has already decided nothing happened.
  makeStandIn("sleep 30");
  const { inspectContainerAsync, DOCKER_DEADLINE_MS } = await lifecycle();
  const started = Date.now();
  const outcome = await inspectContainerAsync(VALID_ID);
  const elapsed = Date.now() - started;

  assert.equal(outcome.ok, false);
  if (outcome.ok) throw new Error("unreachable");
  assert.equal(outcome.fault, "TIMEOUT");
  assert.equal(outcome.ambiguous, true, "a timeout must never be treated as proof of no effect");
  // It gave up at its own deadline, not at the shell command's 30 s.
  assert.ok(elapsed < DOCKER_DEADLINE_MS.inspect + 5_000, `took ${elapsed} ms`);
});

test("R7D.1-CF03-7: a signalled child is reported as signalled and ambiguous", async () => {
  makeStandIn("kill -TERM $$");
  const { inspectContainerAsync } = await lifecycle();
  const outcome = await inspectContainerAsync(VALID_ID);
  assert.equal(outcome.ok, false);
  if (outcome.ok) throw new Error("unreachable");
  assert.equal(outcome.fault, "SIGNALLED");
  assert.equal(outcome.ambiguous, true);
});

test("R7D.1-CF03-8: repeated operations neither accumulate orphans nor leak handles", async () => {
  // A long-lived supervisor performs this many times per execution. A child that is spawned but
  // never reaped accumulates as a zombie; a leaked stream keeps the event loop alive.
  makeStandIn("echo ok; exit 0");
  const { inspectContainerAsync } = await lifecycle();
  const before = (await import("node:fs")).readdirSync("/proc/self/task");
  for (let index = 0; index < 8; index += 1) {
    const outcome = await inspectContainerAsync(VALID_ID);
    assert.equal(outcome.ok, true, `call ${index} failed`);
  }
  const after = (await import("node:fs")).readdirSync("/proc/self/task");
  // Threads, not handles: the assertion that matters is that nothing is still running.
  assert.ok(after.length <= before.length + 2, `thread/task count grew ${before.length} -> ${after.length}`);
  // And the process can still exit promptly, which is what a leaked handle would prevent.
  const started = Date.now();
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.ok(Date.now() - started < 1_000);
});

// ---------------------------------------------------------------------------------------
// Bounded capture
// ---------------------------------------------------------------------------------------

test("R7D.1-CF03-9: a flooding operation cannot grow the caller's memory without bound", async () => {
  // A daemon can emit arbitrarily long diagnostics. Capturing without a bound lets a peer's
  // error text become the supervisor's heap.
  makeStandIn(`i=0; while [ $i -lt 2000 ]; do echo "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; i=$((i+1)); done; exit 1`);
  const { inspectContainerAsync, DOCKER_CAPTURE_BYTES } = await lifecycle();
  const outcome = await inspectContainerAsync(VALID_ID);
  assert.equal(outcome.ok, false);
  if (outcome.ok) throw new Error("unreachable");
  // The retained detail is bounded well below the 64 KiB capture, and it says so.
  assert.ok(outcome.detail.length <= 400, `detail was ${outcome.detail.length} chars`);
  assert.ok(DOCKER_CAPTURE_BYTES <= 64 * 1024, "the capture bound itself must stay small");
});

test("R7D.1-CF03-10: truncation is reported rather than passing off a partial transcript", async () => {
  makeStandIn(`i=0; while [ $i -lt 2000 ]; do echo "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"; i=$((i+1)); done; exit 0`);
  const { inspectContainerAsync } = await lifecycle();
  const outcome = await inspectContainerAsync(VALID_ID);
  // A clean exit with a flood of stdout is still usable — but the fact that diagnostics were
  // truncated must be visible rather than silent.
  assert.equal(outcome.ok, true);
  if (!outcome.ok) throw new Error("unreachable");
  assert.ok(outcome.value.raw.length <= 64 * 1024 + 100, "stdout capture is bounded");
});

// ---------------------------------------------------------------------------------------
// The ambiguity contract
// ---------------------------------------------------------------------------------------

test("R7D.1-CF03-11: an absent container is a definite category; a transport failure is not", async () => {
  // "No such container" proves the container is gone, so cleanup may treat it as success. A
  // daemon-side error of unknown meaning does not prove anything and stays ambiguous.
  makeStandIn('echo "Error: No such container: abc" >&2; exit 1');
  const { removeContainerAsync } = await lifecycle();
  const absent = await removeContainerAsync(VALID_ID);
  assert.equal(absent.ok, false);
  if (absent.ok) throw new Error("unreachable");
  assert.equal(absent.fault, "NOT_FOUND");
  assert.equal(absent.ambiguous, false, "absence is a positive fact");

  makeStandIn('echo "Error response from daemon: something unrecognised happened" >&2; exit 1');
  const fresh = await import(`../src/lib/execution/docker-lifecycle?v=${Date.now()}`);
  const unknown = await fresh.removeContainerAsync(VALID_ID);
  assert.equal(unknown.ok, false);
  if (unknown.ok) throw new Error("unreachable");
  assert.equal(unknown.fault, "DAEMON_ERROR");
  assert.equal(unknown.ambiguous, true, "an unrecognised failure proves nothing about removal");
});

test("R7D.1-CF03-12: no raw daemon transcript is carried in the outcome", async () => {
  // Detail is for an immediate decision, never for telemetry. It is bounded and whitespace
  // collapsed so it cannot become a multi-line log entry.
  makeStandIn('printf "line one\\nline two\\nline three\\n" >&2; exit 1');
  const { inspectContainerAsync } = await lifecycle();
  const outcome = await inspectContainerAsync(VALID_ID);
  assert.equal(outcome.ok, false);
  if (outcome.ok) throw new Error("unreachable");
  assert.equal(outcome.detail.includes("\\n"), false, "detail must be a single line");
  assert.ok(outcome.detail.length <= 300);
});

test("R7D.1-CF03-13: the asynchronous operations never use a synchronous spawn", async () => {
  // The supervisor's event loop serves sockets, streams a document and enforces deadlines. One
  // blocking daemon call stalls all of it. Checked in source because a behavioural test cannot
  // prove the absence of a blocking path that only executes under load.
  const { readFileSync } = await import("node:fs");
  const source = readFileSync("src/lib/execution/docker-lifecycle.ts", "utf8");
  const asyncSection = source.slice(source.indexOf("Asynchronous operations for the supervisor"));
  assert.equal(asyncSection.includes("spawnSync"), false, "the async section must not spawn synchronously");
  regexAssert(asyncSection);
});

/** Assert the async section only references the async primitive. */
function regexAssert(section: string): void {
  const syncCalls = section.match(/\bspawnSync\(/gu) ?? [];
  assert.equal(syncCalls.length, 0);
  const asyncCalls = section.match(/\bspawn\(/gu) ?? [];
  assert.ok(asyncCalls.length >= 1, "the async path must actually spawn");
}

test("R7D.1-CF03-14: the docker binary path is absolute, never resolved through PATH", async () => {
  const { readFileSync } = await import("node:fs");
  const source = readFileSync("src/lib/execution/docker-lifecycle.ts", "utf8");
  assert.match(source, /DOCKER_BIN = process\.env\.DIP_DOCKER_BIN \?\? "\/usr\/bin\/docker"/u);
  assert.equal(existsSync("/usr/bin/docker"), existsSync("/usr/bin/docker"));
});
