import { creditCost } from "@/lib/billing/credit-policy";
import { toolRegistry } from "@/lib/tools/registry";
import type { AgentBudget, AgentBudgetPreview, AgentPlanDraft, AgentValidationIssue } from "./types";

export function assertTrustedBudget(budget: AgentBudget) { for (const [key, value] of Object.entries(budget)) if (!Number.isFinite(value) || value < 0) throw new TypeError(`Trusted budget ${key} must be a non-negative finite number.`); }
export function previewAgentBudget(draft: AgentPlanDraft, budget: AgentBudget): AgentBudgetPreview {
  assertTrustedBudget(budget); const reasons: AgentValidationIssue[] = [];
  const tools = draft.steps.flatMap((step) => { const tool = toolRegistry[step.toolId]; return tool ? [{ stepId: step.stepId, toolId: step.toolId, resourceCost: tool.resourceCost, ai: tool.aiFlag, credits: creditCost(step.toolId) }] : []; });
  const credits = tools.reduce((sum, tool) => sum + tool.credits, 0);
  if (draft.steps.length > budget.maxSteps) reasons.push({ code: "AGENT_BUDGET_EXCEEDED", path: "steps", message: `Plan requires ${draft.steps.length} steps; budget allows ${budget.maxSteps}.` });
  if (credits > budget.maxCredits) reasons.push({ code: "AGENT_BUDGET_EXCEEDED", path: "budget.credits", message: `Known credit requirement ${credits} exceeds ${budget.maxCredits}.` });
  return Object.freeze({ stepCount: draft.steps.length, tools: Object.freeze(tools.map((tool) => Object.freeze(tool))), credits: Object.freeze({ status: "KNOWN", value: credits }), executionMs: Object.freeze({ status: "UNKNOWN", value: null }), providerCost: Object.freeze({ status: "UNKNOWN", value: null }), fits: !reasons.length, reasons: Object.freeze(reasons) });
}
