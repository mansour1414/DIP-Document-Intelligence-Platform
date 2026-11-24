/**
 * Task C2/C3: runtime bounds and lifecycle.
 *
 * These use the real `form-worker` module and real subprocesses. The fake children here
 * are deliberately *dumb* about limits: they only report what they actually received, so
 * the assertions describe the transport rather than a test double's opinion of it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

const directory = mkdtempSync(join(tmpdir(), "dip-worker-bounds-"));

/**
 * A child that echoes, over fd 3, the size of the document it received and the bound it
 * was told about. Both numbers come from the frame, so a mismatch between what the parent
 * enforced and what the child believed is directly observable.
 */
function echoChild(reportPath: string) {
  const entry = join(directory, `echo-${Math.random().toString(36).slice(2)}.mjs`);
  writeFileSync(entry, [
    "import { writeSync, writeFileSync } from 'node:fs';",
    "const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n, 0); return b; };",
    "const writeFrame = (frame) => { let o = 0; while (o < frame.length) o += writeSync(3, frame, o); };",
    "const chunks = [];",
    "process.stdin.on('data', (c) => chunks.push(c));",
    "process.stdin.on('end', () => {",
    "  const buf = Buffer.concat(chunks);",
    "  const controlLen = buf.readUInt32BE(0);",
    "  const control = JSON.parse(buf.subarray(4, 4 + controlLen).toString('utf8'));",
    "  const pdfBytes = buf.length - 4 - controlLen;",
    // Observe out-of-band: the parent's meta sanitizer drops unknown keys (by design),
    // so the child's view of the bound is recorded where the test can read it.
    `  writeFileSync(${JSON.stringify(reportPath)}, JSON.stringify({ declaredBound: control.maxInputBytes, pdfBytes }));`,
    "  const meta = { ok: true, op: 'inspect', pages: pdfBytes, inventory: { fields: [], unsupported: [], pages: pdfBytes, hasXfa: false, needAppearances: false, duplicates: [] }, declaredBound: control.maxInputBytes };",
    "  const json = Buffer.from(JSON.stringify(meta), 'utf8');",
    "  writeFrame(Buffer.concat([u32(json.length), json]));",
    "  process.exitCode = 0;",
    "});",
  ].join("\n"));
  return entry;
}

/** A child that dies immediately without ever reading its input. */
function crashChild() {
  const entry = join(directory, `crash-${Math.random().toString(36).slice(2)}.mjs`);
  writeFileSync(entry, "process.exit(3);\n");
  return entry;
}

// Extensionless: the repo's tsconfig does not enable `allowImportingTsExtensions`,
// and tsx resolves the `.ts` source either way.
async function loadWorker() {
  return import("../src/lib/pdf/form-worker");
}

const pdf = () => {
  const objects = [
    "1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj",
    "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj",
    `3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 300 300]>>endobj`,
  ];
  const body = ["%PDF-1.4", ...objects].join("\n");
  const offsets: number[] = [];
  let cursor = 0;
  for (const line of ["%PDF-1.4", ...objects]) { offsets.push(cursor); cursor += Buffer.byteLength(line) + 1; }
  const xref = [`xref`, `0 ${objects.length + 1}`, "0000000000 65535 f ", ...offsets.slice(1).map((o) => `${String(o).padStart(10, "0")} 00000 n `)];
  const tail = ["trailer", `<</Size ${objects.length + 1}/Root 1 0 R>>`, "startxref", String(cursor), "%%EOF"].join("\n");
  return Buffer.from([...body.split("\n"), ...xref, tail].join("\n"));
};

test("C2: the declared input bound reaches the child and governs what it accepts", async () => {
  const worker = await loadWorker();
  const previous = process.env.FORM_WORKER_ENTRY;
  const report = join(directory, `report-${Math.random().toString(36).slice(2)}.json`);
  process.env.FORM_WORKER_ENTRY = echoChild(report);
  try {
    worker.resetFormWorkersForTest();
    // A limit that is *not* the compiled default. If the child read its own environment
    // it would see nothing and fall back to ~100 MiB; the number it reports must instead
    // be the one this call passed.
    const limits = { ...worker.DEFAULT_WORKER_LIMITS, maxInputBytes: 4096, concurrency: 1 };
    const result = await worker.processPdfBounded(pdf(), limits);
    assert.equal(result.ok, true);
    const observed = JSON.parse(readFileSync(report, "utf8")) as { declaredBound: number; pdfBytes: number };
    assert.equal(observed.declaredBound, 4096,
      "the child must see the parent's limit, not its own compiled default");
    assert.ok(observed.pdfBytes > 0);
  } finally {
    worker.resetFormWorkersForTest();
    if (previous === undefined) delete process.env.FORM_WORKER_ENTRY;
    else process.env.FORM_WORKER_ENTRY = previous;
  }
});

test("C2: a document larger than the declared bound is refused before it reaches the child", async () => {
  const worker = await loadWorker();
  const previous = process.env.FORM_WORKER_ENTRY;
  process.env.FORM_WORKER_ENTRY = echoChild(join(directory, "unused.json"));
  try {
    worker.resetFormWorkersForTest();
    const limits = { ...worker.DEFAULT_WORKER_LIMITS, maxInputBytes: 64, concurrency: 1 };
    await assert.rejects(() => worker.processPdfBounded(pdf(), limits), (error: Error & { code?: string }) => {
      assert.equal(error.code, "WORKER_INPUT_TOO_LARGE");
      return true;
    });
  } finally {
    worker.resetFormWorkersForTest();
    if (previous === undefined) delete process.env.FORM_WORKER_ENTRY;
    else process.env.FORM_WORKER_ENTRY = previous;
  }
});

/**
 * Run `body` with `process.execPath` pointed at a binary that does not exist, so that
 * `spawn()` itself fails. This is the real shape of the bug: Node emits `error` and then
 * `close`, but never `exit`, because no process ever existed. Pointing `execPath` at a
 * missing file is the only way to reach that path without adding a test-only hook to the
 * launcher; `execPath` is a writable own property of `process` and is restored here.
 */
async function withFailedSpawn<T>(body: () => Promise<T>): Promise<T> {
  const original = process.execPath;
  const previousEntry = process.env.FORM_WORKER_ENTRY;
  (process as { execPath: string }).execPath = join(directory, "no-such-node-binary");
  try {
    return await body();
  } finally {
    (process as { execPath: string }).execPath = original;
    if (previousEntry === undefined) delete process.env.FORM_WORKER_ENTRY;
    else process.env.FORM_WORKER_ENTRY = previousEntry;
  }
}

test("C3: a failed spawn frees its slot instead of stranding it", async () => {
  const worker = await loadWorker();
  process.env.FORM_WORKER_ENTRY = crashChild();
  try {
    worker.resetFormWorkersForTest();
    const limits = { ...worker.DEFAULT_WORKER_LIMITS, concurrency: 1 };
    await withFailedSpawn(async () => {
      await assert.rejects(() => worker.processPdfBounded(pdf(), limits));
    });
    // Concurrency is 1. If the dead slot had stayed in the pool, `activeFormWorkers()`
    // would remain 1 and every later call would be refused as WORKER_BUSY forever.
    assert.equal(worker.activeFormWorkers(), 0, "a spawn failure must not occupy a slot");
    // And a normal call must work again afterwards.
    process.env.FORM_WORKER_ENTRY = crashChild();
    await assert.rejects(() => worker.processPdfBounded(pdf(), limits), (error: Error & { code?: string }) => {
      assert.notEqual(error.code, "WORKER_BUSY", "the pool must have recovered");
      return true;
    });
  } finally {
    worker.resetFormWorkersForTest();
  }
});

test("C3: slot release does not depend on `exit` firing for a failed spawn", async () => {
  const worker = await loadWorker();
  process.env.FORM_WORKER_ENTRY = crashChild();
  try {
    worker.resetFormWorkersForTest();
    const limits = { ...worker.DEFAULT_WORKER_LIMITS, concurrency: 1 };
    // The guarantee under test: once the promise settles, the slot is already gone.
    // `retire()` drops synchronously when `exitCode` is set (the current Node ordering)
    // and otherwise waits for `exit`/`close`; either way the pool must be empty by the
    // time the caller sees the rejection, so no request can observe a phantom occupant.
    await withFailedSpawn(async () => {
      await assert.rejects(() => worker.processPdfBounded(pdf(), limits));
      assert.equal(worker.activeFormWorkers(), 0, "the slot must be released before the error surfaces");
    });
  } finally {
    worker.resetFormWorkersForTest();
  }
});

test("C3: a failed spawn cannot hang shutdown", async () => {
  const worker = await loadWorker();
  process.env.FORM_WORKER_ENTRY = crashChild();
  try {
    worker.resetFormWorkersForTest();
    const limits = { ...worker.DEFAULT_WORKER_LIMITS, concurrency: 1 };
    await withFailedSpawn(async () => {
      await assert.rejects(() => worker.processPdfBounded(pdf(), limits));
    });
    await assert.doesNotReject(
      () => Promise.race([
        worker.shutdownFormWorkers(),
        new Promise((_, reject) => setTimeout(() => reject(new Error("shutdown hung on a process that never started")), 5000)),
      ]),
    );
    assert.equal(worker.activeFormWorkers(), 0);
  } finally {
    worker.resetFormWorkersForTest();
  }
});

/**
 * Drive the real child directly, bypassing the parent, so the child's *own* enforcement
 * is what is measured. The parent already refuses an oversized document before writing
 * anything, which means a parent-only test cannot distinguish "the child enforced the
 * bound" from "the child never received too much".
 */
function runChildDirectly(declaredBound: number, pdfSize: number): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [
      "--import", "./scripts/node-platform-compat.mjs", "--import", "tsx",
      join(process.cwd(), "src/lib/pdf/form-worker-child.ts"),
    ], { shell: false, env: { PATH: process.env.PATH ?? "", NODE_ENV: "test" }, stdio: ["pipe", "pipe", "pipe", "pipe"] });
    const u32 = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32BE(n, 0); return b; };
    const control = Buffer.from(JSON.stringify({ v: 1, op: "inspect", maxInputBytes: declaredBound }), "utf8");
    const frame = Buffer.concat([u32(control.length), control, Buffer.alloc(pdfSize, 0x20)]);
    const collected: Buffer[] = [];
    child.stdio[3]?.on("data", (chunk: Buffer) => collected.push(chunk));
    child.stdin.on("error", () => {});
    child.on("close", () => {
      const buffer = Buffer.concat(collected);
      if (buffer.length < 4) { resolve({}); return; }
      const length = buffer.readUInt32BE(0);
      const parsed = JSON.parse(buffer.subarray(4, 4 + length).toString("utf8")) as Record<string, unknown>;
      resolve(parsed);
    });
    child.stdin.end(frame);
  });
}

test("C2: the child enforces the declared bound on its own, not just the parent", async () => {
  const refused = await runChildDirectly(1024, 4096);
  assert.equal(refused.ok, false);
  assert.equal((refused.details as { reason?: string } | undefined)?.reason, "PDF_TOO_LARGE",
    "a document over the declared bound must be refused by the child");

  // The same document, under a bound large enough to accept it: proves the refusal above
  // was caused by the bound and not by the payload being unparseable.
  const accepted = await runChildDirectly(1024 * 1024, 4096);
  assert.notEqual((accepted.details as { reason?: string } | undefined)?.reason, "PDF_TOO_LARGE",
    "the same payload under a larger bound must not be refused for size");
});

/**
 * A child that answers with a chosen failure code, so the parent's *rendering* of a
 * trusted rejection can be observed per code.
 */
function failingChild(code: string, details?: Record<string, unknown>) {
  const entry = join(directory, `fail-${Math.random().toString(36).slice(2)}.mjs`);
  writeFileSync(entry, [
    "import { writeSync } from 'node:fs';",
    "const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n, 0); return b; };",
    "const writeFrame = (frame) => { let o = 0; while (o < frame.length) o += writeSync(3, frame, o); };",
    "process.stdin.resume();",
    "process.stdin.on('end', () => {",
    `  const meta = { ok: false, op: 'inspect', code: ${JSON.stringify(code)}, ...(${JSON.stringify(details ?? null)} === null ? {} : { details: ${JSON.stringify(details ?? null)} }) };`,
    "  const json = Buffer.from(JSON.stringify(meta), 'utf8');",
    "  writeFrame(Buffer.concat([u32(json.length), json]));",
    "  process.exitCode = 0;",
    "});",
  ].join("\n"));
  return entry;
}

test("C1: each trusted rejection carries the message for *its own* code", async () => {
  const worker = await loadWorker();
  const previous = process.env.FORM_WORKER_ENTRY;
  // The message was previously pinned to FORM_UNSUPPORTED's text, so a restricted
  // document told the user it "uses a form feature that is not supported". Both the code
  // and the sentence must now identify the same reason.
  const cases: Array<{ code: string }> = [
    { code: "FORM_RESTRICTED" },
    { code: "FORM_NOT_FOUND" },
    { code: "FORM_VALUE_INVALID" },
    { code: "FORM_FILL_FAILED" },
    { code: "FORM_OUTPUT_UNVERIFIED" },
    { code: "FORM_UNSUPPORTED" },
  ];
  try {
    const seen = new Map<string, string>();
    for (const item of cases) {
      process.env.FORM_WORKER_ENTRY = failingChild(item.code);
      worker.resetFormWorkersForTest();
      const result = await worker.processPdfBounded(pdf(), { ...worker.DEFAULT_WORKER_LIMITS, concurrency: 1 });
      assert.equal(result.ok, false);
      const refusal = result as { code: string; message: string };
      assert.equal(refusal.code, item.code);
      assert.ok(refusal.message && refusal.message.length > 0, `${item.code} produced no message`);
      seen.set(refusal.code, refusal.message);
    }
    // The decisive assertion: the sentences are distinct per code. A shared fallback
    // would collapse them, which is exactly the defect this replaced.
    assert.equal(new Set(seen.values()).size, cases.length,
      `messages collapsed: ${JSON.stringify([...seen])}`);
  } finally {
    worker.resetFormWorkersForTest();
    if (previous === undefined) delete process.env.FORM_WORKER_ENTRY;
    else process.env.FORM_WORKER_ENTRY = previous;
  }
});

test("C1: a failure detail outside the allowlists is dropped, not forwarded", async () => {
  const worker = await loadWorker();
  const previous = process.env.FORM_WORKER_ENTRY;
  // A "code-shaped" token is not the same as a content-free one: a hostile or buggy
  // child could otherwise echo document text back through a plausible-looking field.
  process.env.FORM_WORKER_ENTRY = failingChild("FORM_VALUE_INVALID", {
    shape: "SOMETHING_THE_PARENT_DOES_NOT_RECOGNISE",
    reason: "leaked document text",
    field: "applicant.name",
    // An `issues` entry that is not a known code must be filtered, not just the
    // top-level keys: the list is the one place free text could masquerade as a code.
    issues: ["UNKNOWN_FIELD", "CUSTOMER_IBAN_DE893704"],
  });
  try {
    worker.resetFormWorkersForTest();
    const result = await worker.processPdfBounded(pdf(), { ...worker.DEFAULT_WORKER_LIMITS, concurrency: 1 });
    const refusal = result as { code: string; details?: Record<string, unknown> };
    assert.equal(refusal.code, "FORM_VALUE_INVALID");
    // The real key is `issues` (a list of code-shaped codes), not a singular `issue`.
    assert.deepEqual(refusal.details?.issues, ["UNKNOWN_FIELD"],
      "allowlisted issue codes survive and unrecognised ones are filtered out");
    assert.equal("shape" in (refusal.details ?? {}), false, "an unrecognised shape must be dropped");
    assert.equal("reason" in (refusal.details ?? {}), false, "a free-text reason must be dropped");
    // `field` was never on any allowlist, so it must not appear either.
    assert.equal("field" in (refusal.details ?? {}), false);
  } finally {
    worker.resetFormWorkersForTest();
    if (previous === undefined) delete process.env.FORM_WORKER_ENTRY;
    else process.env.FORM_WORKER_ENTRY = previous;
  }
});
