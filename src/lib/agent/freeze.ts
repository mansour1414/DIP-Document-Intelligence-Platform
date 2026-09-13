import { createHash } from "crypto";
import { AgentError } from "./errors";
import type { FrozenAgentPlan, ValidatedAgentPlan } from "./types";

export function canonicalJson(value: unknown): string { if (value === null || typeof value !== "object") return JSON.stringify(value); if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`; return `{${Object.entries(value as Record<string, unknown>).filter(([, item]) => item !== undefined).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(",")}}`; }
function deepFreeze<T>(value: T): T { if (value && typeof value === "object" && !Object.isFrozen(value)) { Object.freeze(value); for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child); } return value; }
export function freezeAgentPlan(plan: ValidatedAgentPlan): FrozenAgentPlan {
  if (!plan.budgetPreview.fits) throw new AgentError("AGENT_BUDGET_EXCEEDED", "An over-budget plan cannot be frozen.");
  if (plan.approval.state === "REQUIRED") throw new AgentError("AGENT_APPROVAL_REQUIRED", "Required approval has not been granted.");
  if (plan.approval.state === "REJECTED" || plan.state === "REJECTED") throw new AgentError("AGENT_APPROVAL_REJECTED", "A rejected plan cannot be frozen.");
  if (!((plan.state === "VALIDATED" && plan.approval.state === "NOT_REQUIRED") || (plan.state === "APPROVED" && plan.approval.state === "APPROVED"))) throw new AgentError("AGENT_PLAN_INVALID", "Only a validated no-approval plan or a trusted approved plan can be frozen.");
  const semantic = { draft: plan.draft, scope: plan.scope, order: plan.order, budgetPreview: plan.budgetPreview, approval: plan.approval, policyVersion: plan.policyVersion };
  const hash = hashSemanticPlan(semantic);
  return deepFreeze({ state: "FROZEN", ...semantic, integrity: { algorithm: "sha256", hash } });
}
type FrozenSemantic = Omit<FrozenAgentPlan, "state" | "integrity">;
function hashSemanticPlan(semantic: FrozenSemantic) { const approval = { ...semantic.approval, decidedAt: undefined }; return createHash("sha256").update(canonicalJson({ ...semantic, approval })).digest("hex"); }
export function assertFrozenAgentPlan(plan: unknown): asserts plan is FrozenAgentPlan {
  if (!plan || typeof plan !== "object") throw new AgentError("AGENT_PLAN_NOT_FROZEN", "Only a frozen approved plan may later reach the Workflow Engine.");
  const candidate = plan as Partial<FrozenAgentPlan>;
  if (candidate.state !== "FROZEN" || !candidate.draft || !candidate.scope || !candidate.order || !candidate.budgetPreview?.fits || !candidate.approval || !candidate.policyVersion || candidate.integrity?.algorithm !== "sha256" || !["NOT_REQUIRED", "APPROVED"].includes(candidate.approval.state)) throw new AgentError("AGENT_PLAN_NOT_FROZEN", "Frozen plan contract is incomplete or unauthorized.");
  const semantic: FrozenSemantic = { draft: candidate.draft, scope: candidate.scope, order: candidate.order, budgetPreview: candidate.budgetPreview, approval: candidate.approval, policyVersion: candidate.policyVersion };
  if (candidate.integrity.hash !== hashSemanticPlan(semantic)) throw new AgentError("AGENT_PLAN_NOT_FROZEN", "Frozen plan integrity check failed.");
}
