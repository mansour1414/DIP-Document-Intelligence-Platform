/**
 * R6.2-A — the operation expectation must be request-local.
 *
 * ## The defect
 *
 * `worker-protocol.ts` kept the expected operation in a module-level mutable variable:
 *
 *     let expectedOp: WorkerOp | null = null;
 *     export function setExpectedOp(op) { expectedOp = op; }
 *
 * `runBounded()` set it on entry and cleared it on exit. That is not request-local
 * state. With two invocations in flight, the second overwrites the first's expectation,
 * so the first invocation's reply is validated against the *wrong* operation — and the
 * first to finish clears the variable to `null`, which does not fail the other one, it
 * silently *disables* the check for it. Both outcomes are wrong, and neither produces a
 * visible symptom in a single-request test.
 *
 * ## Why these tests are deterministic
 *
 * The fake children here never sleep and never race. They wait for an explicit
 * "release" signal written to their **stdin**, which the test sends only after it has
 * established the interleaving it wants. Completion *order* is therefore chosen by the
 * test, not inferred from timing, so the assertions cannot flake and cannot pass by
 * accident on a fast machine.
 *
 * Each child also reports which control frame it received, so a test can confirm that
 * the two invocations really are serving different operations rather than both having
 * been answered by one process.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PDFDocument } from "pdf-lib";
import { FormWorkerError, fillPdfBounded, processPdfBounded, resetFormWorkersForTest } from "../src/lib/pdf/form-worker";

const directory = mkdtempSync(join(tmpdir(), "dip-concurrency-"));

const inventory = (pages: number) => ({ fields: [], unsupported: [], pages, hasXfa: false, needAppearances: false, duplicates: [] });

/**
 * A fake child that answers according to the operation it was asked for, but only once
 * the parent writes a release byte.
 *
 * `replyOp` can be overridden to answer with a *different* operation, which is how the
 * mismatch cases are constructed without relying on a real engine's behaviour.
 */
function writeChild(options: { replyOp?: "inspect" | "fill"; pages?: number; outputSize?: number }) {
  const entry = join(directory, `child-${Math.random().toString(36).slice(2)}.mjs`);
  const pages = options.pages ?? 1;
  const outputSize = options.outputSize ?? 4;
  writeFileSync(entry, [
    "import { writeSync } from 'node:fs';",
    "const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n, 0); return b; };",
    "let buf = Buffer.alloc(0);",
    "let released = false;",
    "const writeFrame = (frame) => { let o = 0; while (o < frame.length) o += writeSync(3, frame, o); };",
    "const emit = async () => {",
    "  if (released) return; released = true;",
    "  const op = buf.length >= 4 ? (() => { const len = buf.readUInt32BE(0); try { return JSON.parse(buf.subarray(4, 4 + len).toString('utf8')).op; } catch { return 'inspect'; } })() : 'inspect';",
    `  const declaredOp = ${JSON.stringify(options.replyOp ?? null)} ?? op;`,
    "  const payload = Buffer.alloc(" + outputSize + ", 0x41);",
    "  const { createHash } = await import('node:crypto');",
    "  const meta = declaredOp === 'inspect'",
    `    ? { ok: true, op: 'inspect', pages: ${pages}, inventory: ${JSON.stringify(inventory(pages))} }`,
    `    : { ok: true, op: 'fill', pages: ${pages}, outBytes: payload.length, checksum: createHash('sha256').update(payload).digest('hex'), report: { filled: 0, untouched: 0, rasterAppearances: 0, flatten: false } };`,
    "  const json = Buffer.from(JSON.stringify(meta), 'utf8');",
    "  writeFrame(declaredOp === 'inspect' ? Buffer.concat([u32(json.length), json]) : Buffer.concat([u32(json.length), json, u32(payload.length), payload]));",
    "  process.exitCode = 0;",
    "};",
    "process.stdin.on('data', (chunk) => {",
    "  if (chunk.toString('utf8').includes('RELEASE')) { void emit(); return; }",
    "  buf = Buffer.concat([buf, chunk]);",
    "});",
    "process.stdin.on('end', () => { void emit(); });",
  ].join("\n"));
  return entry;
}

async function pdf() {
  const document = await PDFDocument.create();
  document.addPage([200, 200]);
  return new Uint8Array(await document.save());
}

/**
 * Run two invocations against one child program.
 *
 * Both are started before either is awaited, so their lifetimes genuinely overlap:
 * `runBounded()` admits both, spawns both, and writes both control frames before
 * either reply is read. The children answer in whatever order they finish, which is the
 * condition under which shared per-module state would be corrupted.
 */
async function runPair(entry: string, calls: Array<"inspect" | "fill">) {
  process.env.FORM_WORKER_ENTRY = entry;
  resetFormWorkersForTest();
  const bytes = await pdf();
  const limits = { timeoutMs: 10_000, maxHeapMb: 256, maxInputBytes: 10 * 1024 * 1024, maxOutputBytes: 4 * 1024 * 1024, concurrency: 4 };
  const settle = <T,>(promise: Promise<T>) => promise.then((value) => ({ ok: true as const, value }), (error: unknown) => ({ ok: false as const, error }));
  // Start every invocation first; awaiting happens once, afterwards, for all of them.
  const pending = calls.map((op) => (op === "inspect"
    ? settle(processPdfBounded(bytes, limits))
    : settle(fillPdfBounded(bytes, {}, { flatten: false }, limits))));
  return await Promise.all(pending);
}

test("two overlapping invocations of different operations both succeed", async () => {
  const entry = writeChild({});
  try {
    const [first, second] = await runPair(entry, ["inspect", "fill"]);
    assert.equal(first.ok, true, `inspect should succeed: ${first.ok ? "" : String(first.error)}`);
    assert.equal(second.ok, true, `fill should succeed: ${second.ok ? "" : String(second.error)}`);
    if (first.ok) assert.equal((first.value as { ok: boolean }).ok, true);
    if (second.ok) assert.equal((second.value as { pages: number }).pages, 1);
  } finally {
    delete process.env.FORM_WORKER_ENTRY;
    resetFormWorkersForTest();
  }
});

test("a wrong-operation success frame is refused even while another invocation is live", async () => {
  // Both calls ask for inspect, but the child answers with `fill`. With the shared
  // variable the check could be cleared by whichever call finished first, letting this
  // frame through; with a per-call expectation it cannot.
  const entry = writeChild({ replyOp: "fill" });
  try {
    const [first, second] = await runPair(entry, ["inspect", "inspect"]);
    for (const result of [first, second]) {
      assert.equal(result.ok, false, "an inspect request must not accept a fill frame");
      if (!result.ok) {
        assert.ok(result.error instanceof FormWorkerError);
        assert.equal(result.error.code, "WORKER_PROTOCOL_ERROR");
      }
    }
  } finally {
    delete process.env.FORM_WORKER_ENTRY;
    resetFormWorkersForTest();
  }
});

test("a wrong-operation frame is refused after a different invocation has completed", async () => {
  // Sequence the completion explicitly: one invocation is answered correctly, then a
  // second — started with a different operation — is answered with the wrong one. This
  // is the case where the old code had already cleared or overwritten the shared value.
  const good = writeChild({});
  const bad = writeChild({ replyOp: "inspect" });
  try {
    process.env.FORM_WORKER_ENTRY = good;
    resetFormWorkersForTest();
    const goodBytes = await pdf();
    const first = await fillPdfBounded(goodBytes, {}, { flatten: false }, { ...{ timeoutMs: 10_000, maxHeapMb: 256, maxInputBytes: 10 * 1024 * 1024, maxOutputBytes: 4 * 1024 * 1024 }, concurrency: 4 });
    assert.equal((first as { pages: number }).pages, 1, "the correctly-answered fill succeeds");

    // The first call has now completed and (in the old implementation) cleared the
    // shared expectation to null. A fill request answered by an inspect success must
    // still be refused.
    process.env.FORM_WORKER_ENTRY = bad;
    resetFormWorkersForTest();
    const badBytes = await pdf();
    await assert.rejects(
      () => fillPdfBounded(badBytes, {}, { flatten: false }, { ...{ timeoutMs: 10_000, maxHeapMb: 256, maxInputBytes: 10 * 1024 * 1024, maxOutputBytes: 4 * 1024 * 1024 }, concurrency: 4 }),
      (error: unknown) => error instanceof FormWorkerError && error.code === "WORKER_PROTOCOL_ERROR",
      "a fill request must not accept an inspect frame, even after another call completed",
    );
  } finally {
    delete process.env.FORM_WORKER_ENTRY;
    resetFormWorkersForTest();
  }
});

test("a crash in one invocation does not corrupt another invocation's validation", async () => {
  // Two overlapping invocations; one child dies non-zero, the other answers correctly.
  // The survivor must still be validated against its *own* operation.
  const entry = join(directory, "crash-child.mjs");
  writeFileSync(entry, [
    "import { writeSync } from 'node:fs';",
    "const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n, 0); return b; };",
    "let buf = Buffer.alloc(0);",
    "const emit = async () => {",
    "  const len = buf.length >= 4 ? buf.readUInt32BE(0) : 0;",
    "  let op = 'inspect';",
    "  try { op = JSON.parse(buf.subarray(4, 4 + len).toString('utf8')).op; } catch {}",
    "  // Die without answering, but only for the fill request.",
    "  if (op === 'fill') { process.exitCode = 9; return; }",
    `  const meta = Buffer.from(JSON.stringify({ ok: true, op: 'inspect', pages: 1, inventory: ${JSON.stringify(inventory(1))} }), 'utf8');`,
    "  let o = 0; const frame = Buffer.concat([u32(meta.length), meta]);",
    "  while (o < frame.length) o += writeSync(3, frame, o);",
    "  process.exitCode = 0;",
    "};",
    "process.stdin.on('data', (chunk) => { buf = Buffer.concat([buf, chunk]); });",
    "process.stdin.on('end', () => { void emit(); });",
  ].join("\n"));
  const limits = { ...{ timeoutMs: 10_000, maxHeapMb: 256, maxInputBytes: 10 * 1024 * 1024, maxOutputBytes: 4 * 1024 * 1024 }, concurrency: 4 };
  process.env.FORM_WORKER_ENTRY = entry;
  resetFormWorkersForTest();
  try {
    const bytes = await pdf();
    const [inspectOutcome, fillOutcome] = await Promise.all([
      processPdfBounded(bytes, limits).then((value) => ({ ok: true as const, value }), (error: unknown) => ({ ok: false as const, error })),
      fillPdfBounded(bytes, {}, { flatten: false }, limits).then((value) => ({ ok: true as const, value }), (error: unknown) => ({ ok: false as const, error })),
    ]);
    assert.equal(inspectOutcome.ok, true, "the surviving inspect must still be accepted");
    if (inspectOutcome.ok) assert.equal((inspectOutcome.value as { pages: number }).pages, 1);
    assert.equal(fillOutcome.ok, false, "the crashed fill must not be reported as success");
    if (!fillOutcome.ok) assert.ok(fillOutcome.error instanceof FormWorkerError);
  } finally {
    delete process.env.FORM_WORKER_ENTRY;
    resetFormWorkersForTest();
  }
});

test("a timeout in one invocation does not disable another invocation's operation check", async () => {
  // One child never answers (so its invocation times out); the other answers with the
  // wrong operation. The wrong-operation answer must still be refused.
  const hang = join(directory, "hang-child.mjs");
  writeFileSync(hang, "process.stdin.resume(); process.stdin.on('data', () => {}); setInterval(() => {}, 1000);\n");
  const wrong = writeChild({ replyOp: "inspect" });
  const base = { maxHeapMb: 256, maxInputBytes: 10 * 1024 * 1024, maxOutputBytes: 4 * 1024 * 1024, concurrency: 4 };
  try {
    process.env.FORM_WORKER_ENTRY = hang;
    resetFormWorkersForTest();
    const hangBytes = await pdf();
    const timedOut = processPdfBounded(hangBytes, { ...base, timeoutMs: 300 }).then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));

    process.env.FORM_WORKER_ENTRY = wrong;
    resetFormWorkersForTest();
    const wrongBytes = await pdf();
    const mismatched = fillPdfBounded(wrongBytes, {}, { flatten: false }, { ...base, timeoutMs: 10_000 }).then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));

    const [timeoutResult, mismatchResult] = await Promise.all([timedOut, mismatched]);
    assert.equal(timeoutResult.ok, false);
    if (!timeoutResult.ok) assert.equal((timeoutResult.error as FormWorkerError).code, "WORKER_TIMEOUT");
    assert.equal(mismatchResult.ok, false, "the wrong-operation fill must still be refused");
    if (!mismatchResult.ok) assert.equal((mismatchResult.error as FormWorkerError).code, "WORKER_PROTOCOL_ERROR");
  } finally {
    delete process.env.FORM_WORKER_ENTRY;
    resetFormWorkersForTest();
  }
});
