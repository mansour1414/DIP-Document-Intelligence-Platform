// Test-only shims for modules whose side effects require a live production
// service (Postgres, logger, metrics). They are substituted at bundle time via
// esbuild --alias. The malware gate logic under test is NOT modified.
//
// requireCleanUpload() is called with an explicit `recordRejection` in the
// harness, so the DB insert path in securityEvent() is never reached either.

export const db = {
  async $executeRaw() { return 0; },
  securityEvent: { create: async () => ({}) },
};

export const logger = {
  warn() {}, error() {}, info() {}, debug() {},
};

export const dbClient = { $connect: async () => {}, $disconnect: async () => {} };
