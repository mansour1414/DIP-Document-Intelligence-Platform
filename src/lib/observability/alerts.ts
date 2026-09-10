function threshold(name: string, fallback: number) { const value = Number(process.env[name]); return Number.isFinite(value) && value >= 0 ? value : fallback; }
export const alertThresholds = {
  jobFailureRate: threshold("ALERT_JOB_FAILURE_RATE", 0.05), queueDepth: threshold("ALERT_QUEUE_DEPTH", 100), stuckJobMinutes: threshold("ALERT_STUCK_JOB_MINUTES", 10), storageFailuresFiveMinutes: threshold("ALERT_STORAGE_FAILURES_5M", 5), aiProviderFailureRate: threshold("ALERT_AI_FAILURE_RATE", 0.10), aiCostPerHour: threshold("ALERT_AI_COST_PER_HOUR", 0), cleanupFailures: threshold("ALERT_CLEANUP_FAILURES", 1), tempDiskUsedRatio: threshold("ALERT_TEMP_DISK_USED_RATIO", 0.80),
} as const;

