/**
 * B31-01 / R6-F — the isolated child's reply is validated before it is trusted.
 *
 * Fill Forms takes its *authoritative* page count from this reply, and that number
 * is fed to plan enforcement and persisted on the file row. That makes the reply a
 * trust boundary: a child (or a staged entry) that returns `{ok:true}` with no
 * usable `pages` must be a boundary failure, because `undefined` would silently
 * saturate a `> maxPages` comparison, and a negative or fractional value would slip
 * through it.
 *
 * ## What changed in R6
 *
 * The reply used to be a JSON line on stdout. It is now a framed record on fd 3:
 * `[u32 metaLen][JSON][u32 outLen][pdf]`. Stdout is no longer authoritative, so a
 * fake child that writes its answer to stdout is *ignored* rather than believed —
 * that is asserted below, because it is the property that stops an engine's own
 * logging from being mistaken for a result.
 *
 * These tests run a *real* child process via the operator escape hatch
 * (`FORM_WORKER_ENTRY`), so the spawn, the framing, the read loop and the rejection
 * all execute for real. Only the child's program is substituted.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FormWorkerError, processPdfBounded, resetFormWorkersForTest } from "../src/lib/pdf/form-worker";

const directory = mkdtempSync(join(tmpdir(), "dip-fake-child-"));
const entry = join(directory, "child.mjs");

/**
 * A fake child that emits `meta` and `outBytes` on fd 3 in the real wire format.
 *
 * The helper does the framing, so each test states only the metadata it wants to
 * test. `raw` bypasses framing entirely for the malformed-transport cases.
 */
function writeChild(options: { meta?: string; output?: string; raw?: string }) {
  // Build the frame *here*, where `options` exists, and hand the child a hex string.
  // An earlier version interpolated into the generated script and leaked `options`
  // into a scope the child does not have — every test then failed at once, which is
  // the loud version of the same mistake as writing the protocol wrong.
  let frame: Buffer;
  if (options.raw !== undefined) {
    frame = Buffer.from(options.raw, "binary");
  } else {
    const meta = Buffer.from(options.meta ?? "", "utf8");
    const u32 = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32BE(n, 0); return b; };
    // An inspect result carries no output frame at all; only a fill result does.
    frame = options.output === undefined
      ? Buffer.concat([u32(meta.length), meta])
      : (() => { const out = Buffer.from(options.output, "binary"); return Buffer.concat([u32(meta.length), meta, u32(out.length), out]); })();
  }
  writeFileSync(entry, [
    "import { writeSync } from 'node:fs';",
    `const frame = Buffer.from(${JSON.stringify(frame.toString("hex"))}, "hex");`,
    "process.stdin.resume();",
    "process.stdin.on('data', () => {});",
    "process.stdin.on('end', () => {",
    "  let off = 0;",
    "  while (off < frame.length) off += writeSync(3, frame, off);",
    "  process.exitCode = 0;",
    "});",
  ].join("\n"));
}

/** A minimal but *valid* inventory for the stated page count. */
function inventoryFor(pages: number) {
  return { fields: [], unsupported: [], pages, hasXfa: false, needAppearances: false, duplicates: [] };
}

function metaFor(pages: number) {
  return JSON.stringify({ ok: true, op: "inspect", pages, inventory: inventoryFor(pages) });
}

const bytes = new TextEncoder().encode("%PDF-1.7\nx");

async function withReply(
  reply: { meta?: string; output?: string; raw?: string },
  run: () => Promise<void>,
) {
  writeChild(reply);
  process.env.FORM_WORKER_ENTRY = entry;
  resetFormWorkersForTest();
  try { await run(); }
  finally { delete process.env.FORM_WORKER_ENTRY; resetFormWorkersForTest(); }
}

test("a well-formed reply is accepted and its page count is used", async () => {
  await withReply({ meta: metaFor(4) }, async () => {
    const result = await processPdfBounded(bytes);
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.equal(result.pages, 4);
    assert.equal(result.inventory?.pages, 4);
  });
});

test("a successful reply without a usable page count is a boundary failure, not a pass", async () => {
  const malformed = [
    JSON.stringify({ ok: true, op: "inspect", inventory: inventoryFor(1) }),                        // missing
    JSON.stringify({ ok: true, op: "inspect", pages: "7", inventory: inventoryFor(1) }),             // string
    JSON.stringify({ ok: true, op: "inspect", pages: null, inventory: inventoryFor(1) }),            // null
    JSON.stringify({ ok: true, op: "inspect", pages: 2.5, inventory: inventoryFor(2) }),             // fractional
    JSON.stringify({ ok: true, op: "inspect", pages: -3, inventory: inventoryFor(1) }),              // negative
    JSON.stringify({ ok: true, op: "inspect", pages: 0, inventory: inventoryFor(0) }),               // zero
    JSON.stringify({ ok: true, op: "inspect", pages: Number.MAX_SAFE_INTEGER + 2, inventory: inventoryFor(1) }), // unsafe
  ];
  for (const meta of malformed) {
    await withReply({ meta }, async () => {
      await assert.rejects(
        () => processPdfBounded(bytes),
        (error: unknown) => error instanceof FormWorkerError && error.code === "WORKER_PROTOCOL_ERROR",
        `reply ${meta} must be refused`,
      );
    });
  }
});

test("a zero-page reply is refused: an empty document is not an unknown one", async () => {
  // R6-F requires a *positive* page count. The previous version of this file
  // asserted the opposite — that 0 was acceptable "as a number" — which is how a
  // zero-page document became a quota pass downstream via `pageCount ?? 0`.
  await withReply({ meta: metaFor(0) }, async () => {
    await assert.rejects(
      () => processPdfBounded(bytes),
      (error: unknown) => error instanceof FormWorkerError && error.code === "WORKER_PROTOCOL_ERROR",
    );
  });
});

test("a truthy non-Boolean discriminator is refused", async () => {
  for (const discriminator of ["true", 1, "yes", {}, []]) {
    const meta = JSON.stringify({ ok: discriminator, op: "inspect", pages: 1, inventory: inventoryFor(1) });
    await withReply({ meta }, async () => {
      await assert.rejects(
        () => processPdfBounded(bytes),
        (error: unknown) => error instanceof FormWorkerError && error.code === "WORKER_PROTOCOL_ERROR",
        `ok:${JSON.stringify(discriminator)} must be refused`,
      );
    });
  }
});

test("an inventory that does not match the real shape is refused", async () => {
  const broken = [
    {},                                                                                    // no inventory at all
    { inventory: {} },                                                                     // empty object
    { inventory: { ...inventoryFor(1), fields: "nope" } },                                // fields not a list
    { inventory: { ...inventoryFor(1), fields: [{ name: "a", kind: "bogus", page: 1, required: false, readOnly: false, value: null }] } },
    { inventory: { ...inventoryFor(1), fields: [{ name: "a", kind: "text", page: 99, required: false, readOnly: false, value: null }] } },
    { inventory: { ...inventoryFor(1), fields: [{ name: "a", kind: "text", page: 1, required: "no", readOnly: false, value: null }] } },
    { inventory: { ...inventoryFor(1), duplicates: [1] } },                                // non-string duplicate
  ];
  for (const fragment of broken) {
    const meta = JSON.stringify({ ok: true, op: "inspect", pages: 1, ...fragment });
    await withReply({ meta }, async () => {
      await assert.rejects(
        () => processPdfBounded(bytes),
        (error: unknown) => error instanceof FormWorkerError && error.code === "WORKER_PROTOCOL_ERROR",
        `inventory ${JSON.stringify(fragment)} must be refused`,
      );
    });
  }
});

test("the operation must match the request", async () => {
  const meta = JSON.stringify({ ok: true, op: "fill", pages: 1, outBytes: 10, checksum: "a".repeat(64), report: { filled: 0, untouched: 0, rasterAppearances: 0, flatten: false } });
  await withReply({ meta, output: "0123456789" }, async () => {
    await assert.rejects(
      () => processPdfBounded(bytes),
      (error: unknown) => error instanceof FormWorkerError && error.code === "WORKER_PROTOCOL_ERROR",
    );
  });
});

test("an unreadable reply is still a protocol error", async () => {
  await withReply({ meta: "not json at all" }, async () => {
    await assert.rejects(
      () => processPdfBounded(bytes),
      (error: unknown) => error instanceof FormWorkerError && error.code === "WORKER_PROTOCOL_ERROR",
    );
  });
});

test("a truncated frame is refused rather than half-read", async () => {
  // A 4-byte length header claiming 200 bytes, followed by 10. The parent must not
  // read the 10 bytes and hope. No trailing data, so this exercises the short-frame
  // path specifically.
  const truncated = Buffer.alloc(4 + 10);
  truncated.writeUInt32BE(200, 0);
  await withReply({ raw: truncated.toString("binary") }, async () => {
    await assert.rejects(
      () => processPdfBounded(bytes),
      (error: unknown) => error instanceof FormWorkerError && error.code === "WORKER_PROTOCOL_ERROR",
    );
  });
});

test("trailing data after the frame is refused", async () => {
  const meta = Buffer.from(metaFor(1), "utf8");
  const header = Buffer.alloc(4); header.writeUInt32BE(meta.length, 0);
  const outHeader = Buffer.alloc(4); outHeader.writeUInt32BE(0, 0);
  const trailing = Buffer.from("garbage", "utf8");
  await withReply({ raw: Buffer.concat([header, meta, outHeader, trailing]).toString("binary") }, async () => {
    await assert.rejects(
      () => processPdfBounded(bytes),
      (error: unknown) => error instanceof FormWorkerError && error.code === "WORKER_PROTOCOL_ERROR",
    );
  });
});

test("stdout is never authoritative", async () => {
  // The frame on fd 3 is valid; stdout carries a *different*, tempting answer. The
  // parent must use the frame. This is the property that stops an engine's own
  // logging from being mistaken for a result.
  writeFileSync(entry, [
    "import { writeSync } from 'node:fs';",
    "const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n, 0); return b; };",
    "const writeFrame = (buf) => { let off = 0; while (off < buf.length) off += writeSync(3, buf, off); };",
    "process.stdin.resume();",
    "process.stdin.on('data', () => {});",
    "process.stdin.on('end', () => {",
    `  const meta = Buffer.from(${JSON.stringify(metaFor(3))}, "utf8");`,
    "  writeFrame(Buffer.concat([u32(meta.length), meta]));",
    `  process.stdout.write(${JSON.stringify(JSON.stringify({ ok: true, op: "inspect", pages: 999, inventory: inventoryFor(999) }) + "\n")});`,
    "  process.exitCode = 0;",
    "});",
  ].join("\n"));
  process.env.FORM_WORKER_ENTRY = entry;
  resetFormWorkersForTest();
  try {
    const result = await processPdfBounded(bytes);
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.equal(result.pages, 3, "the framed reply wins; stdout is noise");
  } finally { delete process.env.FORM_WORKER_ENTRY; resetFormWorkersForTest(); }
});
