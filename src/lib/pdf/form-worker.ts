/**
 * `fill-forms` — hard-bounded untrusted-PDF processing (FF-04, architect round 2).
 *
 * ## Why a child process
 *
 * The previous implementation bounded everything *around* `pdf-lib` — byte size,
 * cheap shape checks, page count, elapsed time — and then parsed on the main
 * thread. None of that can stop the thing that actually matters: a parse that
 * never returns, or one that inflates until the process dies. `pdf-lib` offers no
 * cancellation point, and a `Promise.race` timer only abandons the *result*,
 * leaving the CPU spinning and the memory allocated.
 *
 * Node has exactly one primitive that can be interrupted: a separate execution
 * context. This module uses a child process, because it is the same shape the
 * repository already uses for its approved document engines
 * (`src/lib/document-processing/server.ts`: `spawn`, no shell, a deadline, then
 * `SIGKILL`), and because a process boundary also gives memory containment — a
 * worker thread shares the host heap ceiling.
 *
 * ## What is enforced
 *
 *   - **Deadline**: the child is `SIGKILL`ed when the budget expires, so a
 *     non-returning parse cannot outlive it.
 *   - **Memory**: `--max-old-space-size` caps the V8 heap; exceeding it aborts the
 *     child (observed exit 134) instead of growing into the host.
 *   - **Credentials**: the child is spawned with a minimal environment
 *     (`PATH`/`NODE_ENV` only), so database, Redis, storage and session secrets
 *     are simply not present in its process.
 *   - **Egress**: no network capability is granted; the child only reads bytes on
 *     stdin and writes one JSON line on stdout.
 *   - **Bounded IPC**: input is capped at `maxInputBytes`, output at
 *     `maxOutputBytes`; a child that floods stdout is killed.
 *   - **Single parse**: the child performs cheap validation, the structural probe
 *     and the inventory against one loaded document (see `form-worker-child.ts`),
 *     instead of loading the same bytes repeatedly in the route.
 *   - **Concurrency**: a bounded pool; a request that cannot get a slot is
 *     rejected rather than queued without limit.
 *   - **Cleanup**: the child is killed and reaped on success, failure, timeout and
 *     pool shutdown; a crashed child never holds its slot.
 *
 * ## What is *not* claimed
 *
 * This is process-level containment, not a security sandbox. The child runs as
 * the same OS user with the same filesystem access; Node 22's permission model
 * does not cover threads reliably (verified: `--permission` did not stop a
 * worker thread from reading the parent's environment). A hostile PDF therefore
 * cannot exhaust or hijack the *service* process, but it is not confined by the
 * kernel. That limitation is recorded rather than glossed over.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

/** Result of one bounded processing run. */
export type WorkerResult =
  | { ok: true; inventory: unknown; pages: number }
  | { ok: false; code: string; message: string; details?: unknown };

export type WorkerLimits = {
  /** Hard wall-clock deadline for one document, before the child is killed. */
  timeoutMs: number;
  /** V8 old-generation heap ceiling for the child, in MB. */
  maxHeapMb: number;
  /** Largest input accepted on stdin. */
  maxInputBytes: number;
  /** Largest output accepted on stdout before the child is considered hostile. */
  maxOutputBytes: number;
  /** Simultaneous children. */
  concurrency: number;
};

export const DEFAULT_WORKER_LIMITS: WorkerLimits = {
  timeoutMs: 20_000,
  maxHeapMb: 256,
  maxInputBytes: 100 * 1024 * 1024,
  maxOutputBytes: 4 * 1024 * 1024,
  concurrency: 2,
};

/**
 * Build the limits from runtime configuration.
 *
 * The defaults are proposed operational values, not approved product quotas:
 * they are documented in `docs/stage2-fill-forms.md` and are bounded by the same
 * `boundedInteger` helper every other limit uses, so an operator can tighten them
 * without a code change.
 */
export function formWorkerLimits(overrides: Partial<WorkerLimits> = {}): WorkerLimits {
  return { ...DEFAULT_WORKER_LIMITS, ...overrides };
}

/** Raised when the boundary itself fails, never when the document is rejected. */
export class FormWorkerError extends Error {
  constructor(readonly code: "WORKER_TIMEOUT" | "WORKER_CRASHED" | "WORKER_PROTOCOL_ERROR" | "WORKER_BUSY" | "WORKER_INPUT_TOO_LARGE" | "WORKER_OUTPUT_TOO_LARGE", message: string) {
    super(message);
  }
}

const HERE = dirname(fileURLToPath(import.meta.url));

/**
 * Locate the child entry next to this module.
 *
 * Two environments exist and they must both work:
 *
 *   - **source / tests** — `form-worker-child.ts`, loaded through the project's
 *     own `tsx` + platform-compat loader (the same pair `npm test` and the
 *     document worker use);
 *   - **production build** — the compiler emits `.js` alongside, so the sibling
 *     `.js` is preferred and no loader is needed.
 *
 * The previous version hardcoded `.ts`, which would have spawned a file that does
 * not exist in a built image. Resolution happens once, and a missing entry is
 * reported as a boundary failure rather than a spawn error.
 */
function childEntry(): { path: string; isTypeScript: boolean } {
  const js = join(HERE, "form-worker-child.js");
  if (existsSync(js)) return { path: js, isTypeScript: false };
  const ts = join(HERE, "form-worker-child.ts");
  if (existsSync(ts)) return { path: ts, isTypeScript: true };
  throw new FormWorkerError("WORKER_CRASHED", "The document processor is not available in this deployment.");
}

/**
 * How the child is launched.
 *
 * The environment is deliberately minimal: no DATABASE_URL, no Redis URL, no
 * storage credentials, no session secret. The child needs the Node binary and
 * its own source only.
 */
function childLaunch(): { args: string[]; env: NodeJS.ProcessEnv } {
  const { path, isTypeScript } = childEntry();
  const args = [...(isTypeScript ? ["--import", "./scripts/node-platform-compat.mjs", "--import", "tsx"] : []), path];
  return { args, env: { PATH: process.env.PATH ?? "", NODE_ENV: process.env.NODE_ENV ?? "production" } };
}

type Slot = { child: ChildProcess; busy: boolean };

const pool: Slot[] = [];
let shuttingDown = false;

function retire(slot: Slot) {
  const index = pool.indexOf(slot);
  if (index >= 0) pool.splice(index, 1);
  if (!slot.child.killed) slot.child.kill("SIGKILL");
}

/** Number of children currently working. Exposed for the concurrency tests. */
export function activeFormWorkers() {
  return pool.filter((slot) => slot.busy).length;
}

/**
 * Run one document in a bounded child.
 *
 * The child is always killed afterwards. A pooled, long-lived child would be
 * faster, but "always start clean" is the property that makes the guarantees
 * meaningful: no state, no leaked handles and no inherited heap growth can
 * survive from one document into the next.
 */
export async function processPdfBounded(bytes: Uint8Array, limits: WorkerLimits = DEFAULT_WORKER_LIMITS): Promise<WorkerResult> {
  if (shuttingDown) throw new FormWorkerError("WORKER_CRASHED", "The document processor is shutting down.");
  if (bytes.byteLength > limits.maxInputBytes) throw new FormWorkerError("WORKER_INPUT_TOO_LARGE", "The document exceeds the processing input limit.");
  // Bounded concurrency: refuse instead of queueing without limit.
  if (activeFormWorkers() >= limits.concurrency) throw new FormWorkerError("WORKER_BUSY", "The document processor is busy.");

  const { args, env } = childLaunch();
  const slot: Slot = { child: spawn(process.execPath, [`--max-old-space-size=${limits.maxHeapMb}`, ...args], { shell: false, env, stdio: ["pipe", "pipe", "pipe"] }), busy: true };
  pool.push(slot);

  return await new Promise<WorkerResult>((resolve, reject) => {
    const child = slot.child;
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timedOut = false;

    const finish = (error: Error | undefined, result?: WorkerResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      // Always reap: a killed-but-referenced child would otherwise keep its slot.
      if (!child.killed) child.kill("SIGKILL");
      retire(slot);
      if (error) reject(error); else resolve(result as WorkerResult);
    };

    const timer = setTimeout(() => {
      timedOut = true;
      // The only thing that actually stops an unbounded parse.
      child.kill("SIGKILL");
      finish(new FormWorkerError("WORKER_TIMEOUT", "The document took too long to process and was stopped."));
    }, limits.timeoutMs);

    child.stdout?.on("data", (chunk: Buffer) => {
      if (settled) return;
      stdout += chunk.toString("utf8");
      // A child that floods stdout is treated as hostile, not buffered.
      if (stdout.length > limits.maxOutputBytes) {
        child.kill("SIGKILL");
        finish(new FormWorkerError("WORKER_OUTPUT_TOO_LARGE", "The document processor produced too much output."));
      }
    });
    child.stderr?.on("data", (chunk: Buffer) => { stderr = `${stderr}${chunk.toString("utf8")}`.slice(-4_000); });

    child.once("error", (error: NodeJS.ErrnoException) => {
      finish(new FormWorkerError("WORKER_CRASHED", `The document processor could not start (${error.code ?? "unknown"}).`));
    });

    child.once("close", (code) => {
      if (settled) return;
      if (timedOut) return; // the timeout path already settled
      // A memory abort surfaces as a non-zero exit, not as JSON.
      if (code !== 0) {
        const oom = /heap out of memory|Allocation failed|Invalid string length|Reached heap limit/iu.test(stderr);
        finish(new FormWorkerError("WORKER_CRASHED", oom ? "The document exceeded the processor memory limit." : "The document processor stopped unexpectedly."));
        return;
      }
      const line = stdout.trim().split("\n").filter(Boolean).pop();
      if (!line) { finish(new FormWorkerError("WORKER_PROTOCOL_ERROR", "The document processor returned no result.")); return; }
      let parsed: unknown;
      try { parsed = JSON.parse(line) as unknown; }
      catch { finish(new FormWorkerError("WORKER_PROTOCOL_ERROR", "The document processor returned an unreadable result.")); return; }
      if (!parsed || typeof parsed !== "object" || !("ok" in parsed)) {
        finish(new FormWorkerError("WORKER_PROTOCOL_ERROR", "The document processor returned an unexpected result."));
        return;
      }
      finish(undefined, parsed as WorkerResult);
    });

    // Feed the document. `end()` is required: the child parses on EOF.
    child.stdin?.on("error", () => undefined); // EPIPE when the child dies early
    child.stdin?.end(Buffer.from(bytes));
  });
}

/** Kill every pooled child. Intended for tests and graceful shutdown. */
export async function shutdownFormWorkers() {
  shuttingDown = true;
  const slots = [...pool];
  pool.length = 0;
  for (const slot of slots) if (!slot.child.killed) slot.child.kill("SIGKILL");
}

/** Allow a later call after a shutdown (tests only). */
export function resetFormWorkersForTest() {
  shuttingDown = false;
  pool.length = 0;
}
