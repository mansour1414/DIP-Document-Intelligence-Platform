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
 * ## Target awareness (R7C)
 *
 * The native packages this checks used to be written out as `@esbuild/linux-x64` and
 * `@napi-rs/canvas-linux-x64-gnu`. That made the check correct on exactly one target
 * and wrong on the other three, in the worst possible way: an ARM64 artifact was
 * reported *complete* while missing its natives, and the build then failed on a
 * package the repository does not contain. The count of required files is identical
 * on every target, so a count-based check cannot catch it either.
 *
 * The target is therefore explicit. It defaults to the *running* process, which is
 * right whenever the verifier runs inside the artifact it is checking (the Debian
 * worker image does exactly that). A cross-build passes `--target-cpu`/`--target-libc`
 * so the check describes the artifact being produced rather than the machine that
 * produced it, and `node_modules/.dip-pdf-worker-target.json` — written by the build —
 * is used when present.
 *
 * An unsupported CPU or libc is a hard error, never a fallback to x64.
 *
 * Usage:
 *   node scripts/verify-pdf-worker-artifact.mjs [artifact-root] [--target-cpu=] [--target-libc=]
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { platformArtifactPaths, resolveTarget } from "./pdf-worker-platform.mjs";

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
  // The Arabic appearance path rasterises with a native canvas and a bundled font.
  // `@napi-rs/canvas` itself is libc- and CPU-independent; its platform binary is not,
  // and is supplied per target by `platformAssets()` below.
  "node_modules/@napi-rs/canvas/package.json",
  "node_modules/@fontsource/noto-sans-arabic/package.json",
  // `pdf-lib` is imported by the child and by the runner's verification of its output.
  "node_modules/pdf-lib/package.json",
  "node_modules/@pdf-lib/standard-fonts/package.json",
  "node_modules/@pdf-lib/upng/package.json",
  "node_modules/pako/package.json",
];

/**
 * The native packages for one target: the esbuild binary and the canvas addon.
 *
 * `esbuild` spawns the platform binary resolved from its optional dependency; with the
 * package installed but the binary absent it reports "no native binary executable".
 * `@napi-rs/canvas` resolves its addon from `@napi-rs/canvas-linux-<cpu>-<libc>`; a
 * package built for the other libc is present and *unloadable*, which is the failure
 * mode this target-awareness exists to prevent.
 */
export function platformAssets(target) {
  const { files, executables } = platformArtifactPaths(target);
  return { files, executables };
}

/**
 * Assets that must additionally be *executable*, for one target.
 *
 * `esbuild` is a native binary that tsx spawns. A copy that loses its mode bits — a
 * naive archive, a `COPY` from a Windows filesystem, or a tar without permissions —
 * leaves every file present and the artifact dead. Presence checks alone cannot see
 * that, so this is asserted separately.
 */
export function requiredExecutables(target) {
  return platformArtifactPaths(target).executables;
}

/**
 * The full required-asset list for one target.
 *
 * The static entries above are target-independent; the two native ones are not. Both
 * are combined here so callers cannot accidentally check a mixed-target artifact.
 */
export function requiredAssets(target) {
  return [...REQUIRED_PDF_WORKER_ASSETS, ...platformAssets(target).files];
}

/** Roots the launcher searches, in its order. */
const SEARCH_ROOTS = ["", "src/lib/pdf", ".next/standalone"];

function missingIn(root, target) {
  const missing = [];
  for (const relative of [...REQUIRED_PDF_WORKER_FILES, ...requiredAssets(target)]) {
    // A required file is satisfied if it exists at the root, or under any of the
    // launcher's searched roots. `form-worker.ts` resolves the child entry through the
    // same list, so this mirrors the runtime lookup rather than inventing a second one.
    const candidates = SEARCH_ROOTS.map((prefix) => join(root, prefix, relative));
    const found = candidates.some((candidate) => existsSync(candidate) && statSync(candidate).isFile());
    if (!found) missing.push(relative);
  }
  for (const relative of requiredExecutables(target)) {
    // Already reported above as missing: one cause, one line.
    if (missing.includes(relative)) continue;
    const candidates = SEARCH_ROOTS.map((prefix) => join(root, prefix, relative));
    const present = candidates.some((candidate) => existsSync(candidate));
    const executable = candidates.some((candidate) => existsSync(candidate) && (statSync(candidate).mode & 0o111) !== 0);
    // Distinguish "absent" from "present without its mode bits": they have different
    // causes (wrong target vs a copy that dropped permissions) and the old message
    // claimed the second for both, which sent the reader looking in the wrong place.
    if (!executable) missing.push(present ? `${relative} (present, but not executable)` : relative);
  }
  return missing;
}

/**
 * Where an artifact declares the target it was built for.
 *
 * A cross-build cannot answer "what target is this?" from `process.arch`, and getting
 * it wrong is the whole defect. So the build writes the target next to the artifact's
 * dependencies, and the verifier prefers it. The file is optional: an artifact built
 * natively on the target needs nothing, because the running process *is* the answer.
 */
export const TARGET_MARKER = "node_modules/.dip-pdf-worker-target.json";

/** Read the artifact's declared target, if it has one. Unreadable is not fatal by itself. */
export function declaredTarget(root, overrides = {}) {
  if (overrides.cpu || overrides.libc) return resolveTarget(overrides);
  for (const base of [resolve(root), join(resolve(root), ".next/standalone")]) {
    const marker = join(base, TARGET_MARKER);
    if (!existsSync(marker)) continue;
    try {
      const parsed = JSON.parse(readFileSync(marker, "utf8"));
      return resolveTarget({ cpu: parsed.cpu, libc: parsed.libc });
    } catch (error) {
      // A malformed marker is a build defect, not a reason to fall back silently to the
      // running architecture: that fallback is precisely how a wrong-target artifact
      // gets reported complete. Failing loudly is the honest behaviour.
      throw new Error(`The artifact target marker at ${marker} is unreadable: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return resolveTarget(overrides);
}

/**
 * Run the check and return the result rather than exiting, so tests can call it.
 *
 * `target` may be `{cpu, libc}`; when omitted the artifact marker is used, and failing
 * that the running process.
 */
export function checkPdfWorkerArtifact(root, target = {}) {
  const resolvedRoot = resolve(root);
  if (!existsSync(resolvedRoot)) return { ok: false, root: resolvedRoot, missing: ["<artifact root does not exist>"], target: undefined };
  const resolvedTarget = declaredTarget(resolvedRoot, target);
  const missing = missingIn(resolvedRoot, resolvedTarget);
  return { ok: missing.length === 0, root: resolvedRoot, missing, target: resolvedTarget };
}

const invokedDirectly = process.argv[1] && import.meta.url === `file://${resolve(process.argv[1])}`;
if (invokedDirectly) {
  // Positional first (the artifact root), then `--target-cpu=`/`--target-libc=`.
  const positional = [];
  const overrides = {};
  for (const argument of process.argv.slice(2)) {
    const cpu = /^--target-cpu=(.+)$/u.exec(argument);
    const libc = /^--target-libc=(.+)$/u.exec(argument);
    if (cpu) overrides.cpu = cpu[1];
    else if (libc) overrides.libc = libc[1];
    else positional.push(argument);
  }
  const root = positional[0] ?? process.cwd();
  let result;
  try {
    result = checkPdfWorkerArtifact(root, overrides);
  } catch (error) {
    // An unsupported CPU/libc is a configuration error, not a missing file. Say so
    // distinctly: "x64 was assumed" is the bug that produced a wrong-target artifact
    // being reported complete.
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(2);
  }
  if (!result.ok) {
    console.error("The PDF worker artifact is incomplete. The bounded child cannot start, so every");
    console.error("Fill Forms job would fail with WORKER_CRASHED. Missing:");
    for (const item of result.missing) console.error(`  - ${item}`);
    console.error(`\nTarget: ${result.target.cpu}/${result.target.libc}`);
    console.error(`Artifact root: ${result.root}`);
    process.exit(1);
  }
  console.log(`PDF worker artifact complete for ${result.target.cpu}/${result.target.libc}: ${result.root}`);
}
