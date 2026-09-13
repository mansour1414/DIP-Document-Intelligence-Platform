import { AgentError } from "./errors";
import { assertFrozenAgentPlan } from "./freeze";
import type { AgentExecutionEvidence, AgentVerificationReason, AgentVerificationResult, FrozenAgentPlan } from "./types";

export function createVerificationResult(input: Omit<AgentVerificationResult, "status"> & { status?: "SUCCEEDED" | "FAILED" }): AgentVerificationResult {
  const failed = input.artifactValidation === "FAILED" || input.schemaValidation === "FAILED" || input.mimeValidation === "FAILED" || input.reasons.length > 0;
  const status = input.status ?? (failed ? "FAILED" : "SUCCEEDED");
  if ((status === "SUCCEEDED" && failed) || (status === "FAILED" && !input.reasons.length)) throw new AgentError("AGENT_PLAN_INVALID", "Verification status and evidence are inconsistent.");
  return Object.freeze({ ...input, status, expectedOutputs: Object.freeze(input.expectedOutputs), actualOutputs: Object.freeze(input.actualOutputs), reasons: Object.freeze(input.reasons) });
}
export function verificationFailure(reasons: readonly AgentVerificationReason[], expectedOutputs: AgentVerificationResult["expectedOutputs"] = [], actualOutputs: AgentVerificationResult["actualOutputs"] = []): AgentVerificationResult { return createVerificationResult({ status: "FAILED", expectedOutputs, actualOutputs, artifactValidation: "FAILED", schemaValidation: "NOT_RUN", mimeValidation: "NOT_RUN", reasons }); }
export function createExecutionEvidence(plan: FrozenAgentPlan, input: Omit<AgentExecutionEvidence, "planId" | "planVersion" | "frozenPlanHash">): AgentExecutionEvidence { assertFrozenAgentPlan(plan); return Object.freeze({ planId: plan.draft.planId, planVersion: plan.draft.version, frozenPlanHash: plan.integrity.hash, ...input, jobIds: Object.freeze([...input.jobIds]), jobStepIds: Object.freeze([...input.jobStepIds]), toolExecutionIds: Object.freeze([...input.toolExecutionIds]), outputFileIds: Object.freeze([...input.outputFileIds]) }); }
