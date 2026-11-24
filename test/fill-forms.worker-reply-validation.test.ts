/**
 * B31-01 — the isolated child's reply is validated before it is trusted.
 *
 * Fill Forms now takes its *authoritative* page count from this reply, and that
 * number is fed to plan enforcement and persisted on the file row. That makes the
 * reply a trust boundary: a child (or a staged entry) that returns `{ok:true}` with
 * no usable `pages` must be a boundary failure, because `undefined` would silently
 * satisfy a `> maxPages` comparison and a negative or fractional value would slip
 * through it.
 *
 * These tests run a *real* child process via the operator escape hatch
 * (`FORM_WORKER_ENTRY`), so the spawn, the read loop, the reply parsing and the
 * rejection all execute for real. Only the child's program is substituted.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FormWorkerError, processPdfBounded, resetFormWorkersForTest } from "../src/lib/pdf/form-worker";

/**
 * The child's *program* is what the test controls. Its environment is not:
 * `childLaunch()` passes only `PATH` and `NODE_ENV` on purpose (no database URL, no
 * Redis URL, no storage credentials, no session secret). An earlier version of this
 * file tried to smuggle the reply through an environment variable and got
 * `"undefined"` back — the minimal environment was doing its job, so the fixture, not
 * the worker, was wrong. The reply is baked into the generated script instead.
 */
const directory = mkdtempSync(join(tmpdir(), "dip-fake-child-"));
const entry = join(directory, "child.mjs");

function writeChild(reply: string) {
  writeFileSync(entry, [
    "process.stdin.resume();",
    "process.stdin.on('data', () => {});",
    "process.stdin.on('end', () => {",
    `  process.stdout.write(${JSON.stringify(`${reply}\n`)});`,
    "  process.exitCode = 0;",
    "});",
  ].join("\n"));
}

const bytes = new TextEncoder().encode("%PDF-1.7\nx");

async function withReply(reply: string, run: () => Promise<void>) {
  writeChild(reply);
  process.env.FORM_WORKER_ENTRY = entry;
  resetFormWorkersForTest();
  try { await run(); }
  finally { delete process.env.FORM_WORKER_ENTRY; resetFormWorkersForTest(); }
}

test("a well-formed reply is accepted and its page count is used", async () => {
  await withReply(JSON.stringify({ ok: true, inventory: { fields: [] }, pages: 4 }), async () => {
    const result = await processPdfBounded(bytes);
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.equal(result.pages, 4);
  });
});

test("a successful reply without a usable page count is a boundary failure, not a pass", async () => {
  const malformed = [
    JSON.stringify({ ok: true, inventory: { fields: [] } }),                     // missing
    JSON.stringify({ ok: true, inventory: { fields: [] }, pages: "7" }),         // string
    JSON.stringify({ ok: true, inventory: { fields: [] }, pages: null }),        // null
    JSON.stringify({ ok: true, inventory: { fields: [] }, pages: 2.5 }),         // fractional
    JSON.stringify({ ok: true, inventory: { fields: [] }, pages: -3 }),          // negative
  ];
  for (const reply of malformed) {
    await withReply(reply, async () => {
      await assert.rejects(
        () => processPdfBounded(bytes),
        (error: unknown) => error instanceof FormWorkerError && error.code === "WORKER_PROTOCOL_ERROR",
        `reply ${reply} must be refused`,
      );
    });
  }
});

test("a zero-page reply is accepted as a number (validity, not policy, is decided here)", async () => {
  // 0 is a legitimate, integer count. Whether a zero-page document is *acceptable*
  // belongs to the Fill Forms contract, not to the transport validator.
  await withReply(JSON.stringify({ ok: true, inventory: { fields: [] }, pages: 0 }), async () => {
    const result = await processPdfBounded(bytes);
    assert.equal(result.ok, true);
    if (result.ok) assert.equal(result.pages, 0);
  });
});

test("an unreadable reply is still a protocol error", async () => {
  await withReply("not json at all", async () => {
    await assert.rejects(
      () => processPdfBounded(bytes),
      (error: unknown) => error instanceof FormWorkerError && error.code === "WORKER_PROTOCOL_ERROR",
    );
  });
});
