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

const nextConfig: NextConfig = {
  output: "standalone",
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
