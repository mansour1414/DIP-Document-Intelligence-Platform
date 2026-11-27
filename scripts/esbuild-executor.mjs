#!/usr/bin/env node
/**
 * Precompile the PDF executor (R7D.1).
 *
 * ## Why this exists
 *
 * The executor runs inside the untrusted boundary. Shipping `tsx` and `esbuild` there means
 * shipping a TypeScript loader and a native binary into the one place in the system where
 * input is hostile. Plain CommonJS is a much smaller surface.
 *
 * `esbuild` is already installed: it is a locked transitive dependency of `tsx`, which is a
 * direct dependency. **This adds no package and does not touch the lockfile.** It uses what
 * `npm ci` already put on disk.
 *
 * ## The one non-obvious flag
 *
 * `--packages=external` is not an optimization, it is a correctness requirement. If
 * `@napi-rs/canvas` were bundled, esbuild would inline a `require()` of a platform-specific
 * `.node` binary into the JavaScript output — and the artifact would then only work on the
 * architecture that built it, silently. Keeping packages external means the native binding is
 * located at runtime by Node's own resolver, on the target platform, which is exactly the
 * behavior that already works in the application worker.
 *
 * The same reasoning applies to `@fontsource`: the executor calls `require.resolve` on a
 * specific `.woff` file. A bundled font would not be a file on disk and `require.resolve`
 * would fail with `MODULE_NOT_FOUND`. This is the trap the review warned about for the R7C
 * packaging work, and it is why the executor's font resolution must be tested, not assumed.
 *
 * ## What is deliberately NOT done
 *
 * No minification. A stack trace from the executor is diagnostic evidence during an incident,
 * and minified frames are close to useless. The size difference is a few hundred kilobytes and
 * the image is bounded by the PDF engine regardless.
 */

import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { build } from "esbuild";

const outdir = process.argv.includes("--outdir")
  ? process.argv[process.argv.indexOf("--outdir") + 1]
  : "dist";

mkdirSync(outdir, { recursive: true });

/**
 * One entry point, one output file.
 *
 * The child is a single process with a single wire contract, so splitting it into chunks would
 * add load-order questions for no benefit.
 */
const result = await build({
  entryPoints: [join("src", "lib", "pdf", "executor-child.ts")],
  outfile: join(outdir, "executor-child.js"),
  bundle: true,
  platform: "node",
  target: "node22",
  format: "cjs",
  // See the header: this is what preserves native canvas loading and font file resolution.
  packages: "external",
  sourcemap: "inline",
  minify: false,
  legalComments: "none",
  // `import.meta.url` does not exist in CommonJS; the shim keeps any such reference from
  // throwing at load time rather than at first use.
  define: { "import.meta.url": "__filename" },
  logLevel: "info",
  metafile: true,
});

// Report what was actually bundled. A dependency that appears here but not in the runtime stage
// would fail at run time, so this list is the input to the closure check.
const inputs = Object.keys(result.metafile.inputs).filter((path) => !path.startsWith("node_modules"));
console.log(`executor bundle: ${inputs.length} local modules`);
for (const path of inputs.sort()) console.log(`  ${path}`);
