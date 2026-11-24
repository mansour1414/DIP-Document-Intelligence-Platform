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
  "./src/lib/runtime/config.ts",
  "./scripts/node-platform-compat.mjs",
] as const;

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
  //      structural probes) and — through `form-inspection.ts`'s admission control —
  //      into `@/lib/queue`, which drags in the Redis client. A missing module here is
  //      not a degraded feature: the child fails to start and every Fill Forms job
  //      reports WORKER_CRASHED.
  //
  // `scripts/verify-pdf-worker-artifact.mjs` resolves this same list from the built
  // output and fails the build if any entry is absent, so the declaration and the
  // check cannot drift apart silently. `./scripts/node-platform-compat.mjs` is
  // included because the child is launched with `--import` of that file; it is not
  // importable TypeScript, so no bundler would ever infer it.
  outputFileTracingIncludes: {
    // R6.2: the child's launcher needs `tsconfig.json` *as a runtime file*.
    //
    // `childLaunch()` starts the child with `--import tsx`, and tsx resolves the `@/`
    // path alias by reading `paths` from `tsconfig.json` relative to the child's
    // working directory. That file is a build input, so Next does not copy it into the
    // standalone tree — the launcher's own requirement was therefore never packaged.
    // The worker image copies it explicitly and has always worked; a standalone
    // deployment would have failed at the first Fill Forms job with WORKER_CRASHED
    // while `verify-pdf-worker-artifact.mjs` reported every source file present.
    //
    // This is a packaging declaration, not a test convenience: the shipped artifact
    // gains the file the shipped launcher already reads, and the smoke test verifies
    // exactly that artifact with no injected configuration.
    //
    // Declared on the same routes as the child, because those are the routes that start
    // it. `outputFileTracingIncludes` is an object of route → globs; a bare string in
    // this position would be a syntax error, which is how this was caught.
    "/api/fill-forms/inspect": [...PDF_WORKER_TRACING, "./tsconfig.json"],
    "/api/jobs/[tool]": [...PDF_WORKER_TRACING, "./tsconfig.json"],
    "/api/v1/jobs": [...PDF_WORKER_TRACING, "./tsconfig.json"],
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
