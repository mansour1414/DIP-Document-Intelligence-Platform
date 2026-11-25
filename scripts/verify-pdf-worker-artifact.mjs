#!/usr/bin/env node
/**
 * Verify that a built deployment artifact can actually run the bounded PDF child.
 *
 * ## Why this exists
 *
 * The child is launched as a *subprocess* by `tsx`, so Next's module tracer cannot see
 * it and is not obliged to include any part of its dependency closure. The failure
 * mode is therefore silent at build time and total at runtime: the child fails to
 * import, every Fill Forms job reports `WORKER_CRASHED`, and every test still passes
 * because the repository checkout happens to contain the missing file. That is exactly
 * the B31-04 defect this round corrects, so the check must run against the **artifact**
 * and not against the repository.
 *
 * ## What it does
 *
 * Given the directory that will be deployed (a Next standalone tree, or the worker
 * image's `/app`), it resolves each required file the way the child's launcher
 * resolves it — relative to the working directory and to the searched roots — and
 * exits non-zero listing every absence. It does not import the files (that would
 * require the artifact's own `node_modules`); it proves they are *present*, and the
 * smoke tests prove they *work*.
 *
 * Usage:
 *   node scripts/verify-pdf-worker-artifact.mjs [artifact-root]
 */
import { existsSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

/**
 * The required files, mirroring `PDF_WORKER_TRACING` in `next.config.ts`.
 *
 * Duplicated on purpose rather than imported: this script runs *inside* the artifact,
 * where the TypeScript config module is not loadable. `tests` assert the two lists
 * agree, so the duplication cannot drift unnoticed.
 */
export const REQUIRED_PDF_WORKER_FILES = [
  "src/lib/pdf/form-worker-child.ts",
  "src/lib/pdf/worker-protocol.ts",
  "src/lib/pdf/form-types.ts",
  "src/lib/pdf/form-schema.ts",
  "src/lib/pdf/form-validation.ts",
  "src/lib/pdf/form-inspection.ts",
  "src/lib/pdf/form-fill.ts",
  "src/lib/pdf/form-appearance.ts",
  "scripts/node-platform-compat.mjs",
  // R6.2: the launcher starts the child with `--import tsx`, and tsx resolves the `@/`
  // path alias from `tsconfig.json` in the child's working directory. It is a build
  // input, so Next does not copy it into a standalone tree on its own; it is declared in
  // `outputFileTracingIncludes`. Without it every aliased import inside the child fails
  // with MODULE_NOT_FOUND — the same total failure as a missing source file, and
  // invisible to a source-file check alone. (Written without quoting a specifier so a
  // list-scraping test cannot mistake this comment for a declared file.)
  "tsconfig.json",
  // R6.4: the launcher itself. The production-runner smoke scenario imports this file from
  // the artifact and calls the real bounded API, so it is a runtime requirement in its own
  // right — not merely something a route happens to import. It is declared in the tracing
  // list; a source-file check that omitted it would pass an artifact in which the runner
  // could not be exercised at all.
  "src/lib/pdf/form-worker.ts",
];

/** Non-source assets the child needs at runtime. */
export const REQUIRED_PDF_WORKER_ASSETS = [
  // R6.4: the production launcher is `node --import node-platform-compat --import tsx`.
  // `tsx` is loaded by `--import`, so nothing imports it statically and Next's tracer
  // cannot see it. Without these three the child cannot start *at all* — the standalone
  // artifact previously shipped none of them, which is what failed CI with
  // "Cannot find package 'tsx' imported from /tmp/dip-artifact-…".
  "node_modules/tsx/package.json",
  "node_modules/tsx/dist/cli.mjs",
  "node_modules/esbuild/package.json",
  // esbuild spawns the platform binary resolved from its optional dependency; with the
  // package installed but the binary absent it reports "no native binary executable".
  "node_modules/@esbuild/linux-x64/bin/esbuild",
  // The Arabic appearance path rasterises with a native canvas and a bundled font.
  "node_modules/@napi-rs/canvas/package.json",
  "node_modules/@napi-rs/canvas-linux-x64-gnu/package.json",
  "node_modules/@fontsource/noto-sans-arabic/package.json",
  // `pdf-lib` is imported by the child and by the runner's verification of its output.
  "node_modules/pdf-lib/package.json",
  "node_modules/@pdf-lib/standard-fonts/package.json",
  "node_modules/@pdf-lib/upng/package.json",
  "node_modules/pako/package.json",
];

/**
 * Assets that must additionally be *executable*.
 *
 * `esbuild` is a native binary that tsx spawns. A copy that loses its mode bits — a
 * naive archive, a `COPY` from a Windows filesystem, or a tar without permissions —
 * leaves every file present and the artifact dead. Presence checks alone cannot see
 * that, so this is asserted separately.
 */
export const REQUIRED_PDF_WORKER_EXECUTABLES = ["node_modules/@esbuild/linux-x64/bin/esbuild"];

/** Roots the launcher searches, in its order. */
const SEARCH_ROOTS = ["", "src/lib/pdf", ".next/standalone"];

function missingIn(root) {
  const missing = [];
  for (const relative of [...REQUIRED_PDF_WORKER_FILES, ...REQUIRED_PDF_WORKER_ASSETS]) {
    // A required file is satisfied if it exists at the root, or under any of the
    // launcher's searched roots. `form-worker.ts` resolves the child entry through the
    // same list, so this mirrors the runtime lookup rather than inventing a second one.
    const candidates = SEARCH_ROOTS.map((prefix) => join(root, prefix, relative));
    const found = candidates.some((candidate) => existsSync(candidate) && statSync(candidate).isFile());
    if (!found) missing.push(relative);
  }
  for (const relative of REQUIRED_PDF_WORKER_EXECUTABLES) {
    const candidates = SEARCH_ROOTS.map((prefix) => join(root, prefix, relative));
    const executable = candidates.some((candidate) => {
      if (!existsSync(candidate)) return false;
      return (statSync(candidate).mode & 0o111) !== 0;
    });
    if (!executable) missing.push(`${relative} (present, but not executable)`);
  }
  return missing;
}

/** Run the check and return the result rather than exiting, so tests can call it. */
export function checkPdfWorkerArtifact(root) {
  const resolvedRoot = resolve(root);
  if (!existsSync(resolvedRoot)) return { ok: false, root: resolvedRoot, missing: ["<artifact root does not exist>"] };
  const missing = missingIn(resolvedRoot);
  return { ok: missing.length === 0, root: resolvedRoot, missing };
}

const invokedDirectly = process.argv[1] && import.meta.url === `file://${resolve(process.argv[1])}`;
if (invokedDirectly) {
  const root = process.argv[2] ?? process.cwd();
  const result = checkPdfWorkerArtifact(root);
  if (!result.ok) {
    console.error("The PDF worker artifact is incomplete. The bounded child cannot start, so every");
    console.error("Fill Forms job would fail with WORKER_CRASHED. Missing:");
    for (const item of result.missing) console.error(`  - ${item}`);
    console.error(`\nArtifact root: ${result.root}`);
    process.exit(1);
  }
  console.log(`PDF worker artifact complete: ${result.root}`);
}
