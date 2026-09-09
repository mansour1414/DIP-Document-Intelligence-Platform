import { defineConfig } from "@neon/config/v1";

export default defineConfig({
  // Neon Object Storage is the baseline provider (private bucket). The runtime adapter remains S3 portable.
  preview: { buckets: { "dip-documents": {} } },
});
