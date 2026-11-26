import type { NextConfig } from "next";
import { withSentryConfig } from "@sentry/nextjs";

/**
 * Every file the bounded PDF child needs in order to start.
 *
 * Kept as one exported list so the build config and the artifact verifier read the
 * same authority. These are *sources*: the child is launched by `tsx`, so the `.ts`
 * files are the runtime artifacts here, not compiled stand-ins.
 */
const PDF_WORKER_TRACING = [
  "./src/lib/pdf/form-worker-child.ts",
  "./src/lib/pdf/worker-protocol.ts",
  "./src/lib/pdf/form-types.ts",
  "./src/lib/pdf/form-schema.ts",
  "./src/lib/pdf/form-validation.ts",
  "./src/lib/pdf/form-inspection.ts",
  "./src/lib/pdf/form-fill.ts",
  "./src/lib/pdf/form-appearance.ts",
  "./scripts/node-platform-compat.mjs",
  // R6.4: the launcher. `/api/fill-forms/inspect` imports it, so the tracer normally
  // reaches it — but "normally" is doing a lot of work there. The Public API route key was
  // wrong until this round (see below), which means that build traced nothing at all, and
  // the smoke scenario imports this module directly. Declaring it makes the artifact's
  // contents independent of which route happens to import it.
  "./src/lib/pdf/form-worker.ts",
  // `tsconfig.json` is a **runtime file**, not a build input: `tsx` reads `paths` from it
  // to resolve `@/` inside the child. The launcher's own requirement was therefore never
  // packaged by tracing.
  "./tsconfig.json",
] as const;

/**
 * The child's runtime dependencies, as packages.
 *
 * This is the *complete* legitimate closure of the production launcher
 * (`node --import ./scripts/node-platform-compat.mjs --import tsx <child>`), established
 * by execution rather than inference: each entry below was removed from a working
 * artifact in turn and the smoke suite failed with a distinct, attributable error. The
 * inverse also holds — `tslib` and `detect-libc` are transitive in the lockfile but are
 * not part of this closure, and removing them leaves all six scenarios passing. Copying
 * `node_modules` wholesale would hide any future omission, so the list is explicit.
 *
 * The path aliases and `tsx`'s own resolution chain are invisible to Next's tracer:
 *
 *   - `tsx` is loaded by `--import`, so nothing imports it statically.
 *   - `esbuild` is a dependency of `tsx`, loaded from `node_modules` at run time.
 *   - `@esbuild/linux-<cpu>` is the platform binary esbuild spawns; without it esbuild
 *     reports "no native binary executable". esbuild publishes one *static*,
 *     libc-independent binary per CPU, so there is no musl variant and none is listed.
 *   - `@napi-rs/canvas` is a *runtime `require`* (deliberately, so no route bundles the
 *     addon), and `@napi-rs/canvas-linux-<cpu>-<libc>` is its platform binary. Unlike
 *     esbuild this one is libc-specific: a glibc build cannot load on Alpine.
 *   - `@fontsource/noto-sans-arabic` is resolved through `require.resolve` at render
 *     time; only the Arabic appearance path exercises it.
 *
 * `pdf-lib` and its `@pdf-lib/*`/`pako` dependencies are normally traced through the
 * child, but are declared here too: they are also reached through the dynamic `require`
 * in the child, and a standalone artifact that is missing them fails every scenario.
 */
const PDF_WORKER_RUNTIME_PACKAGES = [
  "./node_modules/tsx/**/*",
  "./node_modules/esbuild/**/*",
  // R7C: native packages are listed for **every supported target**, not for the
  // build machine. They were x64-only, which is why an ARM64 worker image could
  // not build and an emitted ARM64 standalone artifact shipped without its own
  // natives. Next evaluates this config on the *build* host, so a computed
  // `process.arch` here would bake that host's CPU into an artifact that may be
  // built for another one — and a cross-build (the usual `docker buildx --platform`
  // case) would then trace the wrong packages silently.
  //
  // The globs are harmless when a package is absent: a source image only installs
  // the platform optional dependency matching its own libc/CPU, and Next skips a
  // glob that matches nothing. The artifact verifier is what turns "the right one
  // is missing" into a failure, and it checks the target it is told to check.
  //
  // The two axes are independent, which is why this is not four symmetric rows:
  // esbuild ships one static libc-independent binary per CPU, while canvas ships
  // real gnu/musl builds. Enumerated below so the matrix is auditable rather than
  // inferred.
  //
  //   CPU x libc      esbuild            canvas
  //   x64 / glibc     linux-x64          linux-x64-gnu
  //   x64 / musl      linux-x64          linux-x64-musl
  //   arm64 / glibc   linux-arm64        linux-arm64-gnu
  //   arm64 / musl    linux-arm64        linux-arm64-musl
  "./node_modules/@esbuild/linux-x64/**/*",
  "./node_modules/@esbuild/linux-arm64/**/*",
  "./node_modules/@napi-rs/canvas-linux-x64-gnu/**/*",
  "./node_modules/@napi-rs/canvas-linux-x64-musl/**/*",
  "./node_modules/@napi-rs/canvas-linux-arm64-gnu/**/*",
  "./node_modules/@napi-rs/canvas-linux-arm64-musl/**/*",
  "./node_modules/pdf-lib/**/*",
  "./node_modules/@pdf-lib/standard-fonts/**/*",
  "./node_modules/@pdf-lib/upng/**/*",
  "./node_modules/pako/**/*",
  "./node_modules/@napi-rs/canvas/**/*",
  "./node_modules/@fontsource/noto-sans-arabic/**/*",
] as const;

/**
 * Every artefact the launcher needs in the standalone tree.
 *
 * One list, so the build and the verifier cannot disagree.
 */
const PDF_WORKER_ARTIFACT = [...PDF_WORKER_TRACING, ...PDF_WORKER_RUNTIME_PACKAGES] as const;

/**
 * The database runtime, packaged as **external** packages (R7C.3).
 *
 * ## What went wrong before this
 *
 * R7C.1 tried to fix the Prisma runtime closure by globbing the adapter's directory with
 * `outputFileTracingIncludes`. That was the wrong tool, and it produced a confusing
 * half-failure: the emitted image contained
 * `/app/node_modules/@prisma/adapter-pg/dist/index.js` (so the package *looked* present,
 * and the require stack in the failure pointed at a real file), but its own
 * `require("@prisma/driver-adapter-utils")` had nothing to resolve, and the container
 * died with `MODULE_NOT_FOUND`.
 *
 * This was reproduced here, not inferred. Building a standalone app with the R7C.1 array
 * and then requiring the adapter from the artifact root produces the production error
 * character for character — `Cannot find module '@prisma/driver-adapter-utils'` at
 * `node_modules/@prisma/adapter-pg/dist/index.js:38:36`. The artifact contains
 * `@prisma/adapter-pg` (all seven files: the glob worked) and `pg` (present because Next
 * already externalises it), and `@prisma/driver-adapter-utils` alone is missing. A glob
 * ships the package and nothing it depends on.
 *
 * The reason is that the two mechanisms answer different questions:
 *
 *   - `outputFileTracingIncludes` is a **file glob**. It copies exactly what the pattern
 *     matches. It does not read `package.json`, so it does not know or care that
 *     `@prisma/adapter-pg` depends on four other packages. Globbing a package therefore
 *     ships that package and *orphans its dependencies*.
 *   - `serverExternalPackages` is the **supported marker** for "resolve this at runtime,
 *     do not bundle it". Next's file tracer follows the dependency graph of a package it
 *     is told to leave external, so the whole closure is emitted together.
 *
 * Worse, `@prisma/adapter-pg` was not external at all by default. Next's built-in list
 * contains `@prisma/client`, `prisma` and `pg` — but not the adapter, not
 * `@prisma/driver-adapter-utils`, and not `@prisma/debug`. So webpack bundled the
 * adapter's JavaScript into the server chunk, while its `require()` calls for those
 * unlisted packages were left unresolved at build time, and the glob above then pasted a
 * second, incomplete copy into the image. The failure was a mixture of "bundled where it
 * should have been external" and "copied without its dependencies".
 *
 * ## Why these six roots
 *
 * Declaring the closure roots external makes the tracer emit each package **and** its
 * dependencies, resolved from their real nesting (which matters here: `pg-types` uses a
 * nested `postgres-array@2`, while the adapter uses the hoisted `postgres-array@3`, and
 * only the lockfile knows that).
 *
 * The transitive packages are listed explicitly as well. That is deliberate duplication:
 * a root alone would be enough today, but if a future version of one of these packages
 * starts bundling a dependency instead of requiring it, the explicit entry keeps the
 * intent visible and the artifact check still fails loudly rather than silently shipping
 * a partial tree.
 *
 * NOT included, on purpose:
 *   - `pg-cloudflare` — an *optional* dependency of `pg` for Cloudflare Workers. It is a
 *     native/edge driver this application never loads, and `optionalDependencies` are not
 *     followed here.
 *   - `@types/pg`, `@types/node`, `undici-types` — type declarations. They appear in the
 *     lockfile graph but are never `require()`d, so shipping them would be dead weight.
 *   - any Prisma query engine binary — `src/lib/db/index.ts` uses `PrismaPg`, so queries
 *     go through the driver. An engine would be megabytes of code that never executes.
 *
 * `node_modules/.prisma/client` stays a glob: it is *generated*, not a dependency, so it
 * has no entry in the lockfile for a tracer to follow.
 */

/**
 * Why `serverExternalPackages` alone is not enough (R7C.3, measured).
 *
 * Marking a package external makes the tracer emit its closure — but it emits only the
 * files it saw being *used*. Measured on a real `next build` with only the externals
 * declared, `@prisma/adapter-pg` landed in the standalone tree with `package.json` and
 * `dist/index.mjs` and nothing else:
 *
 *     node_modules/@prisma/adapter-pg/package.json
 *     node_modules/@prisma/adapter-pg/dist/index.mjs
 *
 * The package is dual-format. Its `exports` map selects `dist/index.mjs` for `import` and
 * `dist/index.js` for `require`, and the server bundle uses `import` — so the tracer
 * followed the ESM path and never saw the CJS file. At runtime `server.js` is CommonJS and
 * `require("@prisma/adapter-pg")` resolves the `require` condition to `dist/index.js`,
 * which is not in the image:
 *
 *     MODULE_NOT_FOUND: Cannot find module .../adapter-pg/dist/index.js
 *
 * The same split exists in `@prisma/driver-adapter-utils` and `@prisma/client-runtime-utils`,
 * so fixing only the first one just moves the error. Hence both mechanisms, together:
 * the externals decide *which packages and their dependencies* are emitted, and these
 * globs make sure *every format of each package* is present. Neither is sufficient alone,
 * and the artifact check is what proves the combination.
 */
const PRISMA_EXTERNAL_PACKAGES = [
  "@prisma/client",
  "@prisma/client-runtime-utils",
  "@prisma/adapter-pg",
  "@prisma/driver-adapter-utils",
  "@prisma/debug",
  "pg",
  "pg-connection-string",
  "pg-int8",
  "pg-pool",
  "pg-protocol",
  "pg-types",
  "pgpass",
  "postgres-array",
  "postgres-bytea",
  "postgres-date",
  "postgres-interval",
  "split2",
  "xtend",
] as const;

/**
 * The *generated* half of the Prisma runtime.
 *
 * `prisma generate` writes JavaScript and a schema into `node_modules/.prisma/client`,
 * and `@prisma/client` re-exports from it. Nothing imports that path by name and it has
 * no lockfile entry, so only a file glob reaches it. Generation now runs before the build
 * (`Dockerfile`, R7C.1) — this declaration is what makes the requirement visible here and
 * keeps it true if the build order is ever changed.
 */
const PRISMA_RUNTIME_TRACING = [
  "./node_modules/.prisma/client/**/*",
  // The CJS entry of each package in the closure. See the note below on why this is
  // needed *in addition to* `serverExternalPackages`.
  ...PRISMA_EXTERNAL_PACKAGES.map((name) => `./node_modules/${name}/**/*`),
  // `pg-types` keeps its own copy of `postgres-array` at major 2 while the adapter uses
  // the hoisted major 3. A flat glob for the package name misses the nested one.
  "./node_modules/pg-types/node_modules/postgres-array/**/*",
] as const;

const nextConfig: NextConfig = {
  output: "standalone",
  // R7C.3: see `PRISMA_EXTERNAL_PACKAGES`. These must be external, not bundled, so the
  // file tracer emits each one with its real dependency closure instead of webpack
  // inlining the adapter and leaving its requires unresolved.
  serverExternalPackages: [...PRISMA_EXTERNAL_PACKAGES],
  // The bounded PDF child is **executed**, not imported, so the bundler cannot see it
  // and will not include it in a standalone image on its own. Everything listed here
  // is therefore a first-class build input rather than a bundle side effect.
  //
  // The list is the child's actual dependency closure, not just its entry point.
  // Declaring only `form-worker-child.ts` was insufficient for two separate reasons:
  //
  //   1. `form-worker-child.ts` imports `worker-protocol.ts`, which imports
  //      `form-types.ts`. Neither is reachable from an app route's own import graph,
  //      so tracing the entry alone leaves them behind.
  //   2. The closure also crosses into `@/lib/pdf/form-*` (the real engine and the
  //      structural probes). A missing module here is not a degraded feature: the child
  //      fails to start and every Fill Forms job reports WORKER_CRASHED.
  //
  //      R6.3 removed the one edge that made this list dangerous: `form-inspection.ts`
  //      used to import `@/lib/queue` for a superseded admission counter, which dragged
  //      Redis and BullMQ into a PDF parser. The child's closure is now free of all
  //      application infrastructure, and a test asserts it stays that way.
  //
  // `scripts/verify-pdf-worker-artifact.mjs` resolves this same list from the built
  // output and fails the build if any entry is absent, so the declaration and the
  // check cannot drift apart silently. `./scripts/node-platform-compat.mjs` is
  // included because the child is launched with `--import` of that file; it is not
  // importable TypeScript, so no bundler would ever infer it.
  outputFileTracingIncludes: {
    // The child is *spawned*, never imported, so the bundler cannot see it or anything
    // it resolves at run time. What follows is therefore the complete artifact contract:
    // the child's sources, the launcher that runs them, `tsconfig.json` (which `tsx`
    // reads to resolve `@/`), and the runtime packages.
    //
    // Each entry is a packaging declaration, not a test convenience: the shipped
    // artifact gains only what the shipped launcher already requires, and the smoke
    // test verifies exactly that artifact with no injected configuration.
    //
    // Declared on the same routes as the child, because those are the routes that start
    // it. `outputFileTracingIncludes` is an object of route → globs; a bare string in
    // this position would be a syntax error, which is how this was caught.
    //
    // R6.4: the Public API key is the **filesystem** route, `/v1/jobs`, not the public
    // URL prefix `/api/v1/jobs`. The route lives at `src/app/v1/jobs/route.ts`, so the
    // previous key matched nothing and the Public API standalone build silently shipped
    // without the child — the one deployment path where Fill Forms would fail with
    // WORKER_CRASHED while the verifier reported every file present.
    "/api/fill-forms/inspect": [...PDF_WORKER_ARTIFACT],
    "/api/jobs/[tool]": [...PDF_WORKER_ARTIFACT],
    "/v1/jobs": [...PDF_WORKER_ARTIFACT],
    // The database closure is keyed to `/`, not to individual routes (R7C.3).
    //
    // `outputFileTracingIncludes` keys are matched with `contains: true`, so `"/"` applies
    // to every route. That is deliberate. The routes that reach `src/lib/db/index.ts` are
    // *not* the three above — they are `/api/auth/signin`, `/api/auth/signup`,
    // `/api/auth/oauth/github/callback`, `/api/usage`, `/[locale]/agent`,
    // `/[locale]/workflows` and `/dashboard`. Listing only the PDF routes meant the DB
    // packages were globbed into the tree by whichever route happened to match, so a
    // deployment that served the dashboard but never ran a fill job could have shipped an
    // incomplete database runtime.
    //
    // Keying to `/` also keeps the declaration honest as routes are added: a new route
    // that imports the database needs no change here, and cannot be forgotten.
    "/": [...PRISMA_RUNTIME_TRACING],
  },
  images: {
    remotePatterns: [],
  },
  experimental: {
    serverActions: {
      bodySizeLimit: "50mb",
    },
  },
  async redirects() {
    const tools = ["merge-pdf", "split-pdf", "compress-pdf", "organize-pdf", "rotate-pdf", "delete-pages", "extract-pages", "jpg-to-pdf", "pdf-to-jpg", "watermark-pdf", "crop-pdf", "page-numbers", "header-footer", "resize-pages", "alternate-mix", "flip-pages", "split-pdf-by-size", "split-pdf-by-bookmarks", "split-pdf-by-text", "n-up-pdf", "remove-annotations", "word-to-pdf", "pdf-to-word", "excel-to-pdf", "powerpoint-to-pdf", "ocr-pdf", "summarize-pdf", "chat-with-pdf", "extract-data"];
    return [
      { source: "/", destination: "/en", permanent: false },
      { source: "/pricing", destination: "/en/pricing", permanent: true },
      ...tools.map((tool) => ({ source: `/${tool}`, destination: `/en/tools/${tool}`, permanent: true })),
    ];
  },
};

export default process.env.SENTRY_DSN ? withSentryConfig(nextConfig, { silent: true, disableLogger: true }) : nextConfig;
