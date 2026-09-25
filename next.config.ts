import type { NextConfig } from "next";
import { withSentryConfig } from "@sentry/nextjs";

const nextConfig: NextConfig = {
  output: "standalone",
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
