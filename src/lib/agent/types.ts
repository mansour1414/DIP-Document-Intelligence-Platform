import type { Entitlements } from "@/lib/entitlements/policy";
import type { ToolDefinition } from "@/lib/tools/registry";

export type AgentLocale = "ar" | "en";
export type AgentRequest = Readonly<{ request: string; locale: AgentLocale; scope: Readonly<{ inputs: Readonly<Record<string, readonly string[]>> }> }>;
export type AgentBudget = Readonly<{ maxSteps: number; maxInputTokens: number; maxOutputTokens: number; maxCredits: number; maxExecutionMs: number }>;
export type AgentApprovalState = "NOT_REQUIRED" | "REQUIRED" | "APPROVED" | "REJECTED";
export type AgentPlanState = "DRAFT" | "VALIDATED" | "AWAITING_APPROVAL" | "APPROVED" | "REJECTED" | "FROZEN";

export type AgentInputBinding =
  | Readonly<{ source: "request"; input: string }>
  | Readonly<{ source: "step"; stepId: string; output?: number }>;
export type AgentPlanStep = Readonly<{ stepId: string; toolId: string; toolVersion: string; dependsOn: readonly string[]; inputs: readonly AgentInputBinding[]; options?: Readonly<Record<string, string | number | boolean>>; reason: string }>;
export type AgentPlanDraft = Readonly<{ schemaVersion: 1; planId: string; version: number; steps: readonly AgentPlanStep[] }>;

export type ResolvedAgentFile = Readonly<{ id: string; mimeType: string; size: number; pageCount?: number }>;
export type ResolvedAgentScope = Readonly<{ inputs: Readonly<Record<string, readonly ResolvedAgentFile[]>>; fileIds: readonly string[] }>;
export type TrustedAgentContext = Readonly<{ userId: string; correlationId: string; locale: AgentLocale; allowedToolIds: ReadonlySet<string>; entitlements: Entitlements; budget: AgentBudget; approvalPolicyVersion: string; policyVersion: string }>;

export type AgentValidationIssue = Readonly<{ code: string; path: string; message: string }>;
export type AgentValidationResult = Readonly<{ valid: boolean; issues: readonly AgentValidationIssue[]; order: readonly string[]; tools: Readonly<Record<string, ToolDefinition>> }>;

export type BudgetKnowledge = "KNOWN" | "ESTIMATED" | "UNKNOWN";
export type AgentBudgetPreview = Readonly<{ stepCount: number; tools: readonly Readonly<{ stepId: string; toolId: string; resourceCost: ToolDefinition["resourceCost"]; ai: boolean; credits: number }>[]; credits: Readonly<{ status: "KNOWN"; value: number }>; executionMs: Readonly<{ status: "UNKNOWN"; value: null }>; providerCost: Readonly<{ status: "UNKNOWN"; value: null }>; fits: boolean; reasons: readonly AgentValidationIssue[] }>;

export type AgentApprovalDecision = Readonly<{ state: AgentApprovalState; policyVersion: string; requiredStepIds: readonly string[]; decidedBy?: string; decidedAt?: string; reason?: string }>;
export type ValidatedAgentPlan = Readonly<{ state: "VALIDATED" | "AWAITING_APPROVAL" | "APPROVED" | "REJECTED"; draft: AgentPlanDraft; scope: ResolvedAgentScope; order: readonly string[]; budgetPreview: AgentBudgetPreview; approval: AgentApprovalDecision; policyVersion: string }>;
export type FrozenAgentPlan = Readonly<{ state: "FROZEN"; draft: AgentPlanDraft; scope: ResolvedAgentScope; order: readonly string[]; budgetPreview: AgentBudgetPreview; approval: AgentApprovalDecision; policyVersion: string; integrity: Readonly<{ algorithm: "sha256"; hash: string }> }>;

export type AgentVerificationReason = Readonly<{ code: string; message: string; stepId?: string; outputFileId?: string }>;
export type AgentVerificationResult = Readonly<{ status: "SUCCEEDED" | "FAILED"; expectedOutputs: readonly Readonly<{ stepId: string; mimeTypes: readonly string[] }>[]; actualOutputs: readonly Readonly<{ stepId: string; fileIds: readonly string[]; mimeTypes: readonly string[] }>[]; artifactValidation: "PASSED" | "FAILED" | "NOT_RUN"; schemaValidation: "PASSED" | "FAILED" | "NOT_RUN"; mimeValidation: "PASSED" | "FAILED" | "NOT_RUN"; reasons: readonly AgentVerificationReason[] }>;
export type AgentExecutionEvidence = Readonly<{ planId: string; planVersion: number; frozenPlanHash: string; workflowRunId?: string; jobIds: readonly string[]; jobStepIds: readonly string[]; toolExecutionIds: readonly string[]; outputFileIds: readonly string[]; correlationId: string; verification: AgentVerificationResult }>;
