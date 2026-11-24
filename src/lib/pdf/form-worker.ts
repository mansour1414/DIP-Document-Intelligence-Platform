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
import { FormFillError } from "@/lib/pdf/form-validation";
import { FORM_ERROR_MESSAGES, isFormFillErrorCode, type FormInventory } from "@/lib/pdf/form-types";
import {
  WORKER_LIMITS,
  setExpectedOp,
  WORKER_PROTOCOL_VERSION,
  decodeResult,
  encodeControl,
  type Frame,
  type WorkerControl,
} from "@/lib/pdf/worker-protocol";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

/** Result of one bounded processing run. */
export type WorkerResult =
  // `inventory` is typed, not `unknown`: `parseMeta` proves the full `FormInventory`
  // shape before this value exists, so callers do not have to re-cast it to find out
  // whether `fields` is an array. When it is already known to be an array, the
  // defensive `Array.isArray((result.inventory as {fields?: unknown}).fields)` checks
  // at the call sites are dead weight — they survive only where a value arrives from
  // somewhere the protocol did not produce.
  | { ok: true; inventory: FormInventory | undefined; pages: number }
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
 * Locate the child entry.
 *
 * ## Why a sibling of this module is not enough
 *
 * `next.config.ts` sets `output: "standalone"`. Under that build this module is
 * inlined into a server chunk, so `import.meta.url` points at
 * `.next/server/.../chunk.js` — a directory the child was never emitted into. The
 * previous version looked only for a *sibling* `form-worker-child.js` and would have
 * thrown `WORKER_CRASHED` on the first inspection in a deployed image, while passing
 * every test in the repository. Both the source tree and the traced output are
 * therefore searched, and a miss is a loud, typed failure rather than a spawn error.
 *
 * `FORM_WORKER_ENTRY` is the operator escape hatch: an image that stages the child
 * somewhere else (a worker image, a custom layer) sets it explicitly, and that path
 * is used verbatim.
 *
 * The genuinely correct fix for a standalone image is for the build to copy the
 * entry next to the chunk; `next.config.ts` declares it through
 * `outputFileTracingIncludes` and the deployment check in
 * `docs/stage2-fill-forms.md` describes what to verify. Until an image is built and
 * exercised here, this is a **release blocker**, not a closed gate.
 */
function childEntry(): { path: string; isTypeScript: boolean } {
  const override = process.env.FORM_WORKER_ENTRY;
  if (override) {
    if (!existsSync(override)) throw new FormWorkerError("WORKER_CRASHED", "The configured document processor entry does not exist.");
    return { path: override, isTypeScript: /\.ts$/u.test(override) };
  }
  // Candidate directories: beside this module (source + tests), the project root
  // (standalone images that copy the entry), and the traced source path.
  const roots = [
    HERE,
    join(HERE, "../../../../src/lib/pdf"),
    join(process.cwd(), "src/lib/pdf"),
    join(process.cwd(), ".next/standalone/src/lib/pdf"),
  ];
  for (const root of roots) {
    for (const [name, isTypeScript] of [["form-worker-child.js", false], ["form-worker-child.ts", true]] as const) {
      const candidate = join(root, name);
      if (existsSync(candidate)) return { path: candidate, isTypeScript };
    }
  }
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

/**
 * Fail at boot, not per job.
 *
 * The child is launched with `--import ./scripts/node-platform-compat.mjs`. That file
 * lives under `scripts/`, which the worker image had to be told to copy — for a while
 * it was not, and the only symptom was `WORKER_CRASHED` on every Fill Forms job in
 * production, because every test ran from a checkout that happened to contain it.
 * A missing launch input is a deployment defect, so it is detected once, eagerly, with
 * a message that names the missing file.
 */
const childLaunchChecked = (() => {
  let verified = false;
  return () => {
    // The flag is set only *after* a successful check. The previous version set it
    // first, so the first call that detected a missing file threw once and then every
    // later call believed the launch inputs were fine — a false negative that outlived
    // the condition it was meant to report.
    if (verified) return;
    const { path, isTypeScript } = childEntryChecked();
    if (!existsSync(path)) throw new FormWorkerError("WORKER_CRASHED", "The document processor entry is missing from this deployment.");
    if (isTypeScript && !existsSync("./scripts/node-platform-compat.mjs")) {
      throw new FormWorkerError("WORKER_CRASHED", "The document processor preload is missing from this deployment.");
    }
    verified = true;
  };
})();

/** `childEntry()` with launch-input validation, used by the startup boundary. */
function childEntryChecked(): { path: string; isTypeScript: boolean } {
  const entry = childEntry();
  if (!existsSync(entry.path)) throw new FormWorkerError("WORKER_CRASHED", "The document processor entry is missing from this deployment.");
  return entry;
}

/**
 * Verify at process start that this deployment can run the child at all.
 *
 * The check previously ran lazily, inside `runBounded()` — that is, on the first job
 * rather than at startup. A misbuilt image therefore accepted traffic, reported the
 * problem as a per-request `WORKER_CRASHED`, and gave no single signal that the whole
 * capability was absent. Callers that own a process lifecycle (the worker entrypoint)
 * call this once at boot so the failure is immediate and attributable.
 *
 * Returns a result instead of throwing so a caller can decide whether a missing child
 * is fatal for *its* process: the worker cannot do Fill Forms without it, while an app
 * server that merely offers the route can still serve everything else.
 */
export function verifyFormWorkerStartup(): { ok: true } | { ok: false; reason: string } {
  try {
    childLaunchChecked();
    return { ok: true };
  } catch (error) {
    // A sanitized reason: this string may be logged, and the paths it would otherwise
    // contain describe the deployment's layout.
    return { ok: false, reason: error instanceof FormWorkerError ? error.message : "The document processor could not be verified." };
  }
}

type Slot = { child: ChildProcess; busy: boolean };

const pool: Slot[] = [];
let shuttingDown = false;

/**
 * Retire a slot and, crucially, keep it counted until the process is gone.
 *
 * `child.kill("SIGKILL")` only *sends* the signal; the process survives until the
 * kernel reaps it, and it holds its heap until then. Removing the slot from the pool
 * immediately let a new child start while a killed one was still resident, so the
 * configured concurrency was not a real bound on simultaneous processes — and on a
 * memory-bound host the overshoot is exactly what matters. The slot stays in the pool
 * (`busy` cleared only once the process has exited) and is removed on `exit`.
 */
function retire(slot: Slot) {
  slot.busy = false;
  if (!slot.child.killed) slot.child.kill("SIGKILL");
  // `exit` fires when the process has terminated but before stdio closes; `close`
  // fires after both. Either is proof the kernel has reaped it.
  const drop = () => {
    const index = pool.indexOf(slot);
    if (index >= 0) pool.splice(index, 1);
  };
  if (slot.child.exitCode !== null || slot.child.signalCode !== null) drop();
  else slot.child.once("exit", drop);
}

/**
 * Number of child processes that exist or may still exist.
 *
 * Counts retired-but-not-yet-exited slots too: a killed child still holds its
 * memory until the kernel reaps it, so admitting a replacement before that happens
 * would exceed the configured bound.
 */
export function activeFormWorkers() {
  return pool.length;
}

/**
 * Run one operation in a bounded child.
 *
 * The child is always killed afterwards. A pooled, long-lived child would be
 * faster, but "always start clean" is the property that makes the guarantees
 * meaningful: no state, no leaked handles and no inherited heap growth can
 * survive from one document into the next.
 *
 * ## Wire protocol
 *
 * Control + PDF go in on stdin; the result comes back on **fd 3** as one framed
 * envelope (`worker-protocol.ts`). stdout and stderr are diagnostics only. This
 * replaces "parse the last non-empty line of stdout as JSON", which had no frame
 * boundary and could not carry a binary PDF back at all.
 *
 * ## What the parent still does not trust
 *
 * A well-framed reply proves the bytes arrived as declared, not that the child is
 * honest. Output bytes are re-verified independently (`sha256` over what actually
 * arrived, magic bytes, length, page preservation) by the caller; the checksum in
 * the metadata is consistency evidence, never a substitute.
 */
async function runBounded(control: WorkerControl, pdf: Uint8Array, limits: WorkerLimits): Promise<Frame> {
  if (shuttingDown) throw new FormWorkerError("WORKER_CRASHED", "The document processor is shutting down.");
  if (pdf.byteLength > limits.maxInputBytes) throw new FormWorkerError("WORKER_INPUT_TOO_LARGE", "The document exceeds the processing input limit.");
  // Bounded concurrency: refuse instead of queueing without limit.
  if (activeFormWorkers() >= limits.concurrency) throw new FormWorkerError("WORKER_BUSY", "The document processor is busy.");

  let frame: Buffer;
  try { frame = encodeControl(control, pdf); }
  catch (error) { throw new FormWorkerError("WORKER_INPUT_TOO_LARGE", error instanceof Error ? error.message : "The request exceeds the transport limit."); }

  childLaunchChecked();
  const { args, env } = childLaunch();
  // fd 3 is a dedicated result pipe. `stdio[3]` is a built-in Node capability, so
  // this needs no dependency and keeps the authoritative channel free of any
  // library output on stdout.
  const slot: Slot = { child: spawn(process.execPath, [`--max-old-space-size=${limits.maxHeapMb}`, ...args], { shell: false, env, stdio: ["pipe", "pipe", "pipe", "pipe"] }), busy: true };
  pool.push(slot);
  // The reply is matched against the request at the one place it is decoded.
  setExpectedOp(control.op);

  return await new Promise<Frame>((resolve, reject) => {
    const child = slot.child;
    const resultPipe = child.stdio[3] as NodeJS.ReadableStream | null;
    const chunks: Buffer[] = [];
    let receivedBytes = 0;
    let stderr = "";
    let settled = false;
    let timedOut = false;

    const finish = (error: Error | undefined, result?: Frame) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      setExpectedOp(null);
      // Always reap: a killed-but-referenced child would otherwise keep its slot.
      if (!child.killed) child.kill("SIGKILL");
      retire(slot);
      if (error) reject(error); else resolve(result as Frame);
    };

    const timer = setTimeout(() => {
      timedOut = true;
      // The only thing that actually stops an unbounded, non-returning parse.
      child.kill("SIGKILL");
      finish(new FormWorkerError("WORKER_TIMEOUT", "The document took too long to process and was stopped."));
    }, limits.timeoutMs);

    resultPipe?.on("data", (chunk: Buffer) => {
      if (settled) return;
      // Bound the **bytes** as they arrive, before buffering, so a child that
      // floods the result pipe is stopped rather than accumulated.
      receivedBytes += chunk.byteLength;
      if (receivedBytes > limits.maxOutputBytes + WORKER_LIMITS.metaBytes) {
        chunks.length = 0;
        child.kill("SIGKILL");
        finish(new FormWorkerError("WORKER_OUTPUT_TOO_LARGE", "The document processor produced too much output."));
        return;
      }
      chunks.push(chunk);
    });
    child.stderr?.on("data", (chunk: Buffer) => { stderr = `${stderr}${chunk.toString("utf8")}`.slice(-WORKER_LIMITS.stderrTailBytes); });

    child.once("error", (error: NodeJS.ErrnoException) => {
      finish(new FormWorkerError("WORKER_CRASHED", `The document processor could not start (${error.code ?? "unknown"}).`));
    });

    child.once("close", (code) => {
      if (settled) return;
      if (timedOut) return; // the timeout path already settled
      // A memory abort or a crash surfaces as a non-zero exit, never as a frame.
      if (code !== 0) {
        const oom = /heap out of memory|Allocation failed|Invalid string length|Reached heap limit/iu.test(stderr);
        finish(new FormWorkerError("WORKER_CRASHED", oom ? "The document exceeded the processor memory limit." : "The document processor stopped unexpectedly."));
        return;
      }
      if (!chunks.length) { finish(new FormWorkerError("WORKER_PROTOCOL_ERROR", "The document processor returned no result.")); return; }
      // Defer parsing to a later tick so a frame written and then followed by an
      // abnormal exit is still rejected by the `code !== 0` branch above: the exit
      // status is the authority on whether the run completed.
      let parsed: Frame;
      try { parsed = decodeResult(Buffer.concat(chunks), limits.maxOutputBytes); }
      catch (error) {
        finish(new FormWorkerError("WORKER_PROTOCOL_ERROR", error instanceof Error ? error.message : "The document processor returned an unreadable result."));
        return;
      }
      finish(undefined, parsed);
    });

    // D6: stdout is diagnostics, and it must be *consumed* even though it is never
    // authoritative. An unread pipe fills (64 KiB on Linux) and the child then blocks
    // in `write()`, so a chatty engine turned into a timeout that looked like a slow
    // document. The bytes are counted and discarded: nothing from stdout is parsed,
    // logged or forwarded, so no diagnostic text can reach a log sink.
    let stdoutBytes = 0;
    child.stdout?.on("data", (chunk: Buffer) => {
      stdoutBytes = Math.min(stdoutBytes + chunk.byteLength, Number.MAX_SAFE_INTEGER);
      if (stdoutBytes > WORKER_LIMITS.stdoutCeilingBytes) {
        // Excessively noisy is a fault in its own right, not something to absorb.
        child.kill("SIGKILL");
        finish(new FormWorkerError("WORKER_PROTOCOL_ERROR", "The document processor produced unexpected diagnostic output."));
      }
    });
    child.stdout?.on("error", () => undefined);
    child.stderr?.on("error", () => undefined);

    // Feed the request. `end()` is required: the child parses on EOF.
    child.stdin?.on("error", () => undefined); // EPIPE when the child dies early
    child.stdin?.end(frame);
  });
}

/** Map a child-side refusal onto the existing coded result shape. */
function toResult(frame: Frame): WorkerResult {
  if (frame.meta.ok) return { ok: true, inventory: frame.meta.op === "inspect" ? frame.meta.inventory : undefined, pages: frame.meta.pages };
  return { ok: false, code: frame.meta.code, message: FORM_ERROR_MESSAGES.FORM_UNSUPPORTED, ...(frame.meta.details === undefined ? {} : { details: frame.meta.details }) };
}

/** Inspect one document in a bounded child. */
export async function processPdfBounded(bytes: Uint8Array, limits: WorkerLimits = DEFAULT_WORKER_LIMITS): Promise<WorkerResult> {
  try {
    const frame = await runBounded({ v: WORKER_PROTOCOL_VERSION, op: "inspect" }, bytes, limits);
    if (frame.meta.ok && frame.meta.op !== "inspect") throw new FormWorkerError("WORKER_PROTOCOL_ERROR", "The document processor answered a different operation.");
    return toResult(frame);
  } catch (error) {
    if (error instanceof FormWorkerError) throw error;
    throw new FormWorkerError("WORKER_PROTOCOL_ERROR", "The document processor returned an unreadable result.");
  }
}

/** The verified fill result, as received from the bounded child. */
export type BoundedFillResult = {
  bytes: Uint8Array;
  pages: number;
  checksum: string;
  /** The child's claim about flattening, carried through for the parent to check. */
  flatten: boolean;
  report: { filled: number; untouched: number; rasterAppearances: number; flatten: boolean };
};

/**
 * Fill one document in a bounded child.
 *
 * The engine, the native Arabic canvas and the reopen/verification parse all run
 * inside the child. The parent receives bytes plus metadata and re-verifies them
 * independently — it does not parse the PDF and it does not take the child's word
 * for the page count.
 */
export async function fillPdfBounded(bytes: Uint8Array, fields: Record<string, string | boolean | string[]>, options: { flatten: boolean }, limits: WorkerLimits = DEFAULT_WORKER_LIMITS): Promise<BoundedFillResult> {
  const frame = await runBounded({ v: WORKER_PROTOCOL_VERSION, op: "fill", flatten: options.flatten, fields }, bytes, limits);
  if (!frame.meta.ok) {
    // A fill refusal is a coded domain error, not a boundary failure.
    const code = isFormFillErrorCode(frame.meta.code) ? frame.meta.code : "FORM_FILL_FAILED";
    throw new FormFillError(code, FORM_ERROR_MESSAGES[code], frame.meta.details && typeof frame.meta.details === "object" ? frame.meta.details as Record<string, unknown> : undefined);
  }
  if (frame.meta.op !== "fill") throw new FormWorkerError("WORKER_PROTOCOL_ERROR", "The document processor answered a different operation.");
  if (!frame.output || frame.output.byteLength === 0) throw new FormWorkerError("WORKER_PROTOCOL_ERROR", "The document processor returned no output.");
  return { bytes: frame.output, pages: frame.meta.pages, checksum: frame.meta.checksum, flatten: frame.meta.report.flatten, report: frame.meta.report };
}

/** Kill every pooled child. Intended for tests and graceful shutdown. */
/**
 * Stop accepting work and wait for the children to actually exit.
 *
 * The previous version emptied the pool immediately after sending SIGKILL. That made
 * `activeFormWorkers()` report zero while every killed child was still resident, so
 * the number the concurrency bound is built on was wrong at exactly the moment
 * (shutdown, redeploy) when overshoot is most likely. Slots are removed by the same
 * `retire()` path used everywhere else — on real `exit` — and this awaits that.
 */
export async function shutdownFormWorkers() {
  shuttingDown = true;
  const slots = [...pool];
  for (const slot of slots) if (!slot.child.killed) slot.child.kill("SIGKILL");
  await Promise.all(slots.map((slot) => new Promise<void>((resolve) => {
    if (slot.child.exitCode !== null || slot.child.signalCode !== null) { resolve(); return; }
    slot.child.once("exit", () => resolve());
  })));
}

/** Allow a later call after a shutdown (tests only). */
export function resetFormWorkersForTest() {
  shuttingDown = false;
  pool.length = 0;
}
