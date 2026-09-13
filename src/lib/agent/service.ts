import { AgentError } from "./errors";
import { evaluateApproval, type AgentApprovalPolicy } from "./approval";
import { previewAgentBudget } from "./budget";
import type { AgentPlanDraft, ResolvedAgentScope, TrustedAgentContext, ValidatedAgentPlan } from "./types";
import { validateAgentPlan } from "./validator";

export function buildValidatedAgentPlan(draft: AgentPlanDraft, scope: ResolvedAgentScope, context: TrustedAgentContext, approvalPolicy: AgentApprovalPolicy): ValidatedAgentPlan {
  const validation = validateAgentPlan(draft, scope, context); if (!validation.valid) throw Object.assign(new AgentError("AGENT_PLAN_INVALID", "Agent plan validation failed."), { issues: validation.issues });
  const budgetPreview = previewAgentBudget(draft, context.budget); if (!budgetPreview.fits) throw Object.assign(new AgentError("AGENT_BUDGET_EXCEEDED", "Agent budget validation failed."), { issues: budgetPreview.reasons });
  const approval = evaluateApproval(draft, context.approvalPolicyVersion, approvalPolicy);
  return Object.freeze({ state: approval.state === "REQUIRED" ? "AWAITING_APPROVAL" : "VALIDATED", draft, scope, order: validation.order, budgetPreview, approval, policyVersion: context.policyVersion });
}

export function applyApproval(plan: ValidatedAgentPlan, approval: ValidatedAgentPlan["approval"]): ValidatedAgentPlan {
  if (approval.policyVersion !== plan.approval.policyVersion || approval.requiredStepIds.join("\0") !== plan.approval.requiredStepIds.join("\0")) throw new AgentError("AGENT_PLAN_INVALID", "Approval does not match the validated policy decision.");
  if (approval.state !== "APPROVED" && approval.state !== "REJECTED") throw new AgentError("AGENT_APPROVAL_REQUIRED", "A final trusted approval decision is required.");
  return Object.freeze({ ...plan, state: approval.state, approval });
}
