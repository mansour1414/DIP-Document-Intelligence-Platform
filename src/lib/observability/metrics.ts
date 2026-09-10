import { logger } from "@/lib/logging";

type Labels = Record<string, string | number | boolean | undefined>;
export type MetricPoint = { name: string; value: number; unit: "count" | "ms" | "bytes" | "ratio"; labels: Labels };
export type MetricSink = (point: MetricPoint) => void;
let sink: MetricSink | undefined;
export function setMetricSink(next?: MetricSink) { sink = next; }
export function recordMetric(name: string, value: number, unit: "count" | "ms" | "bytes" | "ratio", labels: Labels = {}) {
  if (!Number.isFinite(value)) return;
  const safeLabels = Object.fromEntries(Object.entries(labels).filter(([key]) => key !== "user_id"));
  const point = { name, value, unit, labels: safeLabels } satisfies MetricPoint;
  sink?.(point);
  logger.info("metric", { metric: name, value, unit, ...safeLabels });
}

export async function measure<T>(name: string, labels: Labels, work: () => Promise<T>): Promise<T> {
  const started = performance.now();
  try { return await work(); }
  finally { recordMetric(name, Math.round((performance.now() - started) * 100) / 100, "ms", labels); }
}
