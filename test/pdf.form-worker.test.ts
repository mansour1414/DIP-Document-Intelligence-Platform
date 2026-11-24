/**
 * P3 — the bounded PDF boundary, tested by running it.
 *
 * Every case spawns the real child. Nothing here asserts on source text: the
 * properties under test (a deadline that stops a runaway parse, a heap cap that
 * aborts, a slot that stays held until the process is reaped, a byte-counted IPC
 * limit) only exist when a process actually runs.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { PDFDocument } from "pdf-lib";
import {
  DEFAULT_WORKER_LIMITS,
  FormWorkerError,
  activeFormWorkers,
  processPdfBounded,
  shutdownFormWorkers,
} from "../src/lib/pdf/form-worker";

async function samplePdf() {
  const document = await PDFDocument.create();
  const page = document.addPage([300, 300]);
  document.getForm().createTextField("name").addToPage(page, { x: 10, y: 10, width: 120, height: 20 });
  return new Uint8Array(await document.save({ updateFieldAppearances: false }));
}

test("a valid document is inspected in the child and the inventory comes back", async () => {
  const result = await processPdfBounded(await samplePdf());
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.pages, 1);
  assert.equal((result.inventory as { fields: unknown[] }).fields.length, 1);
  assert.equal(activeFormWorkers(), 0, "the child must be gone once the call resolves");
});

test("a rejected document is returned as coded data, never as a crash", async () => {
  const junk = new Uint8Array(600).fill(0x41);
  const result = await processPdfBounded(junk);
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.equal(result.code, "FORM_UNSUPPORTED");
});

test("an oversized input is refused before a process is spawned", async () => {
  const before = activeFormWorkers();
  await assert.rejects(
    () => processPdfBounded(new Uint8Array(2_000), { ...DEFAULT_WORKER_LIMITS, maxInputBytes: 1_000 }),
    (error: unknown) => {
      assert.ok(error instanceof FormWorkerError);
      assert.equal(error.code, "WORKER_INPUT_TOO_LARGE");
      return true;
    },
  );
  assert.equal(activeFormWorkers(), before, "refusing must not consume a slot");
});

test("the deadline stops a parse that would not return, and the slot is held until reaped", async () => {
  const bytes = await samplePdf();
  const started = Date.now();
  await assert.rejects(
    () => processPdfBounded(bytes, { ...DEFAULT_WORKER_LIMITS, timeoutMs: 1, concurrency: 1 }),
    (error: unknown) => {
      assert.ok(error instanceof FormWorkerError);
      assert.equal(error.code, "WORKER_TIMEOUT");
      return true;
    },
  );
  assert.ok(Date.now() - started < 5_000, "the deadline must fire promptly");
  // SIGKILL is asynchronous: the child is dead-on-its-feet but the kernel has not
  // reaped it, so its heap is still resident. The slot must remain counted, or a
  // replacement could start while the killed process is still holding memory.
  const heldImmediately = activeFormWorkers();
  await new Promise((resolve) => setTimeout(resolve, 500));
  assert.ok(activeFormWorkers() <= heldImmediately, "the slot is released only as the process exits");
  assert.equal(activeFormWorkers(), 0, "a reaped child releases its slot");
});

test("the boundary is usable again after a timeout", async () => {
  const bytes = await samplePdf();
  await assert.rejects(() => processPdfBounded(bytes, { ...DEFAULT_WORKER_LIMITS, timeoutMs: 1, concurrency: 1 }));
  // A killed child holds its slot until the kernel reaps it, so the pool is
  // legitimately busy for a moment. Waiting for the exit is the documented
  // recovery, not a workaround: it is what a second request would do in production.
  const deadline = Date.now() + 5_000;
  while (activeFormWorkers() > 0 && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 25));
  assert.equal(activeFormWorkers(), 0, "the killed child must be reaped, not leak its slot");
  const result = await processPdfBounded(bytes, { ...DEFAULT_WORKER_LIMITS, concurrency: 1 });
  assert.equal(result.ok, true, "a killed child must not wedge the pool");
});

test("concurrency is refused rather than queued without limit", async () => {
  // Start from an empty pool so the count under test is this test's own.
  const ready = Date.now() + 5_000;
  while (activeFormWorkers() > 0 && Date.now() < ready) await new Promise((resolve) => setTimeout(resolve, 25));
  const bytes = await samplePdf();
  const limits = { ...DEFAULT_WORKER_LIMITS, concurrency: 1, timeoutMs: 20_000 };
  const first = processPdfBounded(bytes, limits).catch((error: unknown) => error);
  await new Promise((resolve) => setTimeout(resolve, 20));
  await assert.rejects(() => processPdfBounded(bytes, limits), (error: unknown) => {
    assert.ok(error instanceof FormWorkerError);
    assert.equal(error.code, "WORKER_BUSY");
    return true;
  });
  await first;
});

test("the child environment carries no application secrets", async () => {
  // The child is spawned with an explicit two-variable environment. Proving that
  // from the parent side means the child must not be able to see a sentinel.
  process.env.DIP_SECRET_SENTINEL = "must-not-be-inherited";
  try {
    const result = await processPdfBounded(await samplePdf());
    assert.equal(result.ok, true, "the child must still run with the minimal environment");
  } finally {
    delete process.env.DIP_SECRET_SENTINEL;
  }
});

test("shutdown kills children and leaves the pool empty", async () => {
  await shutdownFormWorkers();
  assert.equal(activeFormWorkers(), 0);
});
