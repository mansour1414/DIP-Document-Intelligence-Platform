// Test-only shim for @/lib/logging (see shim-db.mjs rationale).
export const logger = {
  warn() {}, error() {}, info() {}, debug() {}, trace() {}, fatal() {},
};
export function createLogger() { return logger; }
export default logger;
