import { PLAN_POLICIES, type PlanCode } from "@/lib/entitlements/policy";

export const RETENTION_POLICY_VERSION = "2026-09-provisional-v2";
export const retentionPolicy = {
  version: RETENTION_POLICY_VERSION,
  provisional: true,
  plans: {
    FREE: { inputDays: PLAN_POLICIES.FREE.retentionDays, outputDays: PLAN_POLICIES.FREE.retentionDays, failedJobDays: 7 },
    PRO: { inputDays: PLAN_POLICIES.PRO.retentionDays, outputDays: PLAN_POLICIES.PRO.retentionDays, failedJobDays: 30 },
  } satisfies Record<PlanCode, { inputDays: number; outputDays: number; failedJobDays: number }>,
  tempHours: 1,
  billingDays: 2_555,
  auditDays: 365,
} as const;

