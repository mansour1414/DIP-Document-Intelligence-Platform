import type { PlanCode } from "@/lib/entitlements/policy";
import { retentionPolicy } from "./config";

/**
 * The only plan codes the retention scheduler recognizes.
 *
 * Anything else is treated as FREE, which is the shortest approved period and
 * therefore the conservative choice for a cross-tenant sweeper.
 */
const KNOWN_PLAN_CODES: readonly PlanCode[] = ["FREE", "PRO"];

export type SubscriptionFacts = { plan: { code: string } };

/**
 * Resolve the plan that governs a document's retention period.
 *
 * The caller passes the user's active subscriptions, already ordered newest
 * first (`orderBy: { createdAt: "desc" }, take: 1`). A user with no active
 * subscription is on FREE, matching how the rest of the product evaluates
 * entitlements.
 */
export function currentPlanCode(subscriptions: readonly SubscriptionFacts[] | undefined | null): PlanCode {
  const code = subscriptions?.[0]?.plan?.code;
  return KNOWN_PLAN_CODES.includes(code as PlanCode) ? (code as PlanCode) : "FREE";
}

/**
 * Days a document of the given plan must be retained before it is eligible for
 * deletion. Reads the approved policy; it never invents a period.
 */
export function retentionDaysForPlan(code: PlanCode): number {
  return retentionPolicy.plans[code].inputDays;
}

/** Approved per-plan periods, keyed by plan code. */
export function approvedRetentionDays(): Record<PlanCode, number> {
  return {
    FREE: retentionDaysForPlan("FREE"),
    PRO: retentionDaysForPlan("PRO"),
  };
}
