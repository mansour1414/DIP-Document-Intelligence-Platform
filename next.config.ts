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
    "/api/fill-forms/inspect": [...PDF_WORKER_TRACING],
    "/api/jobs/[tool]": [...PDF_WORKER_TRACING],
    "/api/v1/jobs": [...PDF_WORKER_TRACING],
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
