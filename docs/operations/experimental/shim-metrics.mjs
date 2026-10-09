// Test-only shim for @/lib/observability/metrics (see shim-db.mjs rationale).
const sink = [];
export function recordMetric(...args) { sink.push(args); }
export async function measure(_name, _meta, fn) { return fn(); }
export function metricsSnapshot() { return sink; }
