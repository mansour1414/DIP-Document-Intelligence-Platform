#!/usr/bin/env node
/**
 * R6.4 — exercise the artifact's *own* production launcher, with no writes to the artifact.
 *
 * ## Why this is a shipped file and not generated at test time
 *
 * The strongest artifact check is to import the artifact's `form-worker.ts` and call
 * `processPdfBounded()` / `fillPdfBounded()`: that runs the real `childEntry()`
 * resolution, the real `childLaunch()` argument list, the real framing and the real
 * decoder, none of which a hand-rolled spawn would prove.
 *
 * The previous version of this scenario wrote that module into the artifact root at test
 * time. It worked in a checkout and failed inside the production worker image with
 *
 *   EROFS: read-only file system, open '/app/dip-smoke-runner-….mjs'
 *
 * The image runs with a read-only root filesystem on purpose. The harness wrote into the
 * one directory it must not write to, so the fix belongs here: this file is committed,
 * copied into the image at build time, and executed as-is.
 *
 * ## Why it does not lose isolation
 *
 * This module imports `../src/lib/pdf/form-worker` by *relative path*, which is the same
 * location in the repository and in a standalone tree (`scripts/` and `src/lib/pdf/` are
 * both preserved at the artifact root), so it resolves the launcher —
 * and every package the launcher needs — through the artifact's own resolution roots.
 * Running it from a relocated copy therefore still proves the copy is self-sufficient;
 * Node never falls back to an ancestor `node_modules` because none is reachable from a
 * temp directory. Harness-side concerns (fixture generation, output re-verification) use
 * the harness's own `pdf-lib`, deliberately, so a broken artifact cannot also break the
 * evidence about itself.
 *
 * Prints `ok` on success and a diagnostic on failure; exits non-zero either way. The
 * smoke script treats a non-zero exit as a failed scenario.
 */
import { PDFDocument } from "pdf-lib";
import { DEFAULT_WORKER_LIMITS, fillPdfBounded, processPdfBounded, shutdownFormWorkers } from "../src/lib/pdf/form-worker";

async function main() {
  const document = await PDFDocument.create();
  const page = document.addPage([595, 842]);
  document.getForm().createTextField("applicant.name").addToPage(page, { x: 72, y: 700, width: 328, height: 22 });
  const input = new Uint8Array(await document.save());

  // One permit: this module exercises the launcher, not its concurrency behaviour.
  const limits = { ...DEFAULT_WORKER_LIMITS, concurrency: 1 };

  const inspected = await processPdfBounded(input, limits);
  if (inspected.ok !== true || inspected.pages !== 1) {
    throw new Error(`runner inspect failed: ${JSON.stringify(inspected)}`);
  }

  const filled = await fillPdfBounded(input, { "applicant.name": "Runner" }, { flatten: true }, limits);
  if (!filled.bytes || !filled.bytes.byteLength) throw new Error("runner fill produced no bytes");

  const reopened = await PDFDocument.load(filled.bytes);
  if (reopened.getForm().getFields().length !== 0) throw new Error("runner flatten left a form");
  if (reopened.getPageCount() !== 1) throw new Error("runner flatten changed the page count");

  await shutdownFormWorkers();
  console.log("ok");
}

main().catch(async (error) => {
  // Best effort: a leaked child would keep the process alive and turn a clear failure into
  // a timeout.
  await shutdownFormWorkers().catch(() => undefined);
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
