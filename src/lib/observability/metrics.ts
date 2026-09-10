import { logger } from "@/lib/logging";

type Labels = Record<string, string | number | boolean | undefined>;
export function recordMetric(name: string, value: number, unit: "count" | "ms" | "bytes" | "ratio", labels: Labels = {}) {
  if (!Number.isFinite(value)) return;
  logger.info("metric", { metric: name, value, unit, ...labels });
}

export async function measure<T>(name: string, labels: Labels, work: () => Promise<T>): Promise<T> {
  const started = performance.now();
  try { return await work(); }
  finally { recordMetric(name, Math.round((performance.now() - started) * 100) / 100, "ms", labels); }
}

