import { randomUUID } from "crypto";
import type { Prisma } from "@prisma/client";
import { executeAiGateway, type AgentPlannerTask } from "@/lib/ai/gateway";
import { AI_LIMITS } from "@/lib/ai/gateway/task";
import { runtimeLimits } from "@/lib/runtime/config";
import { resolvePlan } from "@/lib/entitlements/service";
import { planCanUseTool } from "@/lib/entitlements/policy";
import { withTenant } from "@/lib/db/tenant";
import { toolRegistry, workerToolIds } from "@/lib/tools/registry";
import { MAX_WORKFLOW_NODES, assertValidWorkflow } from "@/lib/workflows/validator";
import { startWorkflowRun, cancelWorkflowRun } from "@/lib/workflows/service";
import type { WorkflowDefinition } from "@/lib/workflows/types";
import { recordMetric } from "@/lib/observability/metrics";
import { parseAgentRequest } from "./schema";
import { resolveAgentScope } from "./scope";
import { buildValidatedAgentPlan, applyApproval } from "./service";
import { decideApproval } from "./approval";
import { freezeAgentPlan, assertFrozenAgentPlan } from "./freeze";
import { createExecutionEvidence, createVerificationResult, verificationFailure } from "./verification";
import type { AgentBudget, AgentPlanDraft, AgentRequest, FrozenAgentPlan, ResolvedAgentScope, TrustedAgentContext, ValidatedAgentPlan } from "./types";
import { AgentError } from "./errors";
import { agentAuditContext, type AgentAuditEvent } from "./audit";
import { logger } from "@/lib/logging";

const json = (value: unknown) => value as Prisma.InputJsonValue;
const terminal = new Set(["SUCCEEDED", "FAILED", "CANCELLED"]);
const agentExcludedTools = new Set(["protect-pdf", "unlock-pdf", "pdf-permissions"]);
type Planner = (task: AgentPlannerTask, context: { agentRunId: string; correlationId: string; userId: string; toolId: "agent-planner" }) => Promise<{ output: AgentPlanDraft; estimatedCost: number }>;
const productionPlanner: Planner = (task, context) => executeAiGateway(task, context);

async function audit(userId: string, event: AgentAuditEvent, context: Parameters<typeof agentAuditContext>[0], resourceId?: string) {
  const details = agentAuditContext(context); logger.info(event, details);
  const persistedDetails = JSON.stringify(Object.fromEntries(Object.entries(details).filter(([, value]) => value !== undefined)));
  await withTenant({ userId }, (tx) => tx.$executeRaw`
    INSERT INTO audit_logs(id, user_id, action, resource, resource_id, details)
    VALUES (${randomUUID()}::uuid, ${userId}::uuid, ${event}, 'agent_run', ${resourceId ?? null}::uuid, ${persistedDetails}::jsonb)
  `);
}

function trustedBudget(entitlements: Awaited<ReturnType<typeof resolvePlan>>["entitlements"]): AgentBudget {
  return Object.freeze({ maxSteps: MAX_WORKFLOW_NODES, maxInputTokens: AI_LIMITS.maxDocumentCharacters, maxOutputTokens: AI_LIMITS.maxOutputTokens, maxCredits: entitlements.maxAiCreditsPerRequest, maxExecutionMs: runtimeLimits.jobTimeoutMs });
}

function allowedTools(entitlements: Awaited<ReturnType<typeof resolvePlan>>["entitlements"], locale: "ar" | "en") {
  return Object.values(toolRegistry).filter((tool) => workerToolIds.has(tool.toolId) && !agentExcludedTools.has(tool.toolId) && planCanUseTool(entitlements, tool.toolId) && (!tool.aiFlag || entitlements.aiAccess) && tool.locales.includes(locale));
}

function plannerTask(runId: string, request: AgentRequest, scope: ResolvedAgentScope, budget: AgentBudget, tools: ReturnType<typeof allowedTools>): AgentPlannerTask {
  return { toolId: "agent-planner", locale: request.locale, request: request.request, planId: runId, planVersion: 1, maxSteps: budget.maxSteps, maxOutputTokens: budget.maxOutputTokens,
    inputs: Object.entries(scope.inputs).map(([name, files]) => ({ name, files: files.map(({ mimeType, size, pageCount }) => ({ mimeType, size, ...(pageCount === undefined ? {} : { pageCount }) })) })),
    tools: tools.map((tool) => ({ toolId: tool.toolId, version: tool.version, inputMime: tool.mime.input, outputMime: tool.mime.output, maxFiles: tool.limits.maxFiles, resourceCost: tool.resourceCost, ai: tool.aiFlag })) };
}

function approvalPolicy(draft: AgentPlanDraft) { const configured = new Set((process.env.AGENT_APPROVAL_TOOL_IDS ?? "").split(",").map((v) => v.trim()).filter(Boolean)); return { requiredStepIds: draft.steps.filter((step) => configured.has(step.toolId)).map((step) => step.stepId) }; }

export function compileFrozenAgentPlan(plan: FrozenAgentPlan): WorkflowDefinition {
  assertFrozenAgentPlan(plan);
  const definition: WorkflowDefinition = { schemaVersion: 1, nodes: plan.draft.steps.map((step) => ({ id: step.stepId, toolId: step.toolId, toolVersion: step.toolVersion, dependsOn: [...step.dependsOn], inputs: step.inputs.map((binding) => binding.source === "request" ? { source: "workflow" as const, input: binding.input } : { source: "node" as const, nodeId: binding.stepId, ...(binding.output === undefined ? {} : { output: binding.output }) }), ...(step.options ? { options: { ...step.options } } : {}) })) };
  assertValidWorkflow(definition); return definition;
}

async function persistAndExecute(userId: string, runId: string, planVersionId: string, frozen: FrozenAgentPlan) {
  const definition = compileFrozenAgentPlan(frozen);
  const workflow = await withTenant({ userId }, async (tx) => { const workflow = await tx.workflow.create({ data: { ownerId: userId, name: `Agent ${runId}`, origin: "AGENT_INTERNAL" } }); const version = await tx.workflowVersion.create({ data: { workflowId: workflow.id, version: 1, definition: json(definition) } }); await tx.workflow.update({ where: { id: workflow.id }, data: { currentVersionId: version.id } }); await tx.agentPlanVersion.update({ where: { id: planVersionId }, data: { state: "FROZEN", frozenPlan: json(frozen), integrityHash: frozen.integrity.hash, workflowVersionId: version.id } }); await tx.agentRun.update({ where: { id: runId }, data: { status: "FROZEN" } }); return workflow; });
  await audit(userId, "agent.plan.frozen", { userId, correlationId: await correlation(userId, runId), planId: frozen.draft.planId, planVersion: frozen.draft.version, frozenPlanHash: frozen.integrity.hash }, runId);
  const workflowRun = await startWorkflowRun(userId, workflow.id, Object.fromEntries(Object.entries(frozen.scope.inputs).map(([name, files]) => [name, files.map((file) => file.id)])), await correlation(userId, runId));
  await withTenant({ userId }, (tx) => tx.agentRun.update({ where: { id: runId }, data: { workflowRunId: workflowRun.id, status: "EXECUTING" } }));
  await audit(userId, "agent.workflow.linked", { userId, correlationId: workflowRun.correlationId, planId: frozen.draft.planId, decision: "linked" }, runId); await audit(userId, "agent.execution.started", { userId, correlationId: workflowRun.correlationId, planId: frozen.draft.planId }, runId);
}

async function correlation(userId: string, runId: string) { const run = await withTenant({ userId }, (tx) => tx.agentRun.findFirstOrThrow({ where: { id: runId, ownerId: userId }, select: { correlationId: true } })); return run.correlationId; }

export async function createAgentRun(userId: string, raw: unknown, idempotencyKey: string, correlationId: string = randomUUID(), planner: Planner = productionPlanner) {
  const request = parseAgentRequest(raw); const existing = await withTenant({ userId }, (tx) => tx.agentRun.findUnique({ where: { ownerId_idempotencyKey: { ownerId: userId, idempotencyKey } }, include: { currentPlanVersion: true } })); if (existing) return existing;
  const resolved = await resolvePlan(userId), budget = trustedBudget(resolved.entitlements), tools = allowedTools(resolved.entitlements, request.locale);
  const created = await withTenant({ userId }, (tx) => tx.agentRun.create({ data: { ownerId: userId, locale: request.locale, request: request.request, scope: json(request.scope), trustedBudget: json(budget), allowedToolIds: tools.map((tool) => tool.toolId), correlationId, idempotencyKey, status: "PLANNING" } }));
  await audit(userId, "agent.request.received", { userId, correlationId }, created.id);
  await audit(userId, "agent.planning.started", { userId, correlationId }, created.id);
  try {
    const scope = await resolveAgentScope(request, userId); await audit(userId, "agent.scope.resolved", { userId, correlationId, decision: "authorized" }, created.id);
    const response = await planner(plannerTask(created.id, request, scope, budget, tools), { agentRunId: created.id, correlationId, userId, toolId: "agent-planner" }); const draft = response.output; await audit(userId, "agent.plan.proposed", { userId, correlationId, planId: draft.planId, planVersion: draft.version }, created.id);
    if (draft.planId !== created.id || draft.version !== 1) throw new AgentError("AGENT_PLAN_INVALID", "Planner changed the trusted plan identity.");
    const context: TrustedAgentContext = { userId, correlationId, locale: request.locale, allowedToolIds: new Set(tools.map((tool) => tool.toolId)), entitlements: resolved.entitlements, budget, approvalPolicyVersion: "agent-approval-v1", policyVersion: "agent-policy-v1" };
    const validated = buildValidatedAgentPlan(draft, scope, context, approvalPolicy);
    await audit(userId, "agent.plan.validated", { userId, correlationId, planId: draft.planId, planVersion: draft.version }, created.id);
    await audit(userId, "agent.budget.previewed", { userId, correlationId, planId: draft.planId, planVersion: draft.version, budgetFits: validated.budgetPreview.fits }, created.id);
    const plan = await withTenant({ userId }, async (tx) => { const plan = await tx.agentPlanVersion.create({ data: { agentRunId: created.id, version: 1, draft: json(draft), resolvedScope: json(scope), budgetPreview: json(validated.budgetPreview), approval: json(validated.approval), state: validated.state } }); await tx.agentRun.update({ where: { id: created.id }, data: { currentPlanVersionId: plan.id, status: validated.state === "AWAITING_APPROVAL" ? "AWAITING_APPROVAL" : "PLAN_VALIDATED" } }); return plan; });
    if (validated.state === "AWAITING_APPROVAL") await audit(userId, "agent.approval.required", { userId, correlationId, planId: draft.planId, planVersion: draft.version, approvalState: validated.approval.state }, created.id);
    if (validated.state === "VALIDATED") await persistAndExecute(userId, created.id, plan.id, freezeAgentPlan(validated));
    return getAgentRun(userId, created.id);
  } catch (error) { const code = error instanceof AgentError ? error.code : error instanceof Error ? error.message : "AGENT_FAILED"; await withTenant({ userId }, (tx) => tx.agentRun.update({ where: { id: created.id }, data: { status: "FAILED", errorCode: code, completedAt: new Date() } })); recordMetric("agent_failure_total", 1, "count", { error_code: code }); throw error; }
}

export async function decideAgentRun(userId: string, runId: string, decision: "APPROVED" | "REJECTED") {
  const run = await withTenant({ userId }, (tx) => tx.agentRun.findFirst({ where: { id: runId, ownerId: userId }, include: { currentPlanVersion: true } })); if (!run?.currentPlanVersion || run.status !== "AWAITING_APPROVAL") throw new AgentError("AGENT_APPROVAL_REQUIRED", "Run is not awaiting approval.");
  const p = run.currentPlanVersion, validated: ValidatedAgentPlan = { state: "AWAITING_APPROVAL", draft: p.draft as unknown as AgentPlanDraft, scope: p.resolvedScope as unknown as ResolvedAgentScope, order: (p.draft as unknown as AgentPlanDraft).steps.map((s) => s.stepId), budgetPreview: p.budgetPreview as unknown as ValidatedAgentPlan["budgetPreview"], approval: p.approval as unknown as ValidatedAgentPlan["approval"], policyVersion: "agent-policy-v1" };
  const approval = decideApproval(validated.approval, decision, userId); const decided = applyApproval(validated, approval);
  if (decision === "REJECTED") { await withTenant({ userId }, async (tx) => { await tx.agentPlanVersion.update({ where: { id: p.id }, data: { approval: json(approval), state: "REJECTED" } }); await tx.agentRun.update({ where: { id: run.id }, data: { status: "FAILED", errorCode: "AGENT_APPROVAL_REJECTED", completedAt: new Date() } }); }); await audit(userId, "agent.approval.rejected", { userId, correlationId: run.correlationId, planId: validated.draft.planId, planVersion: validated.draft.version, approvalState: approval.state }, run.id); return getAgentRun(userId, run.id); }
  await withTenant({ userId }, (tx) => tx.agentPlanVersion.update({ where: { id: p.id }, data: { approval: json(approval), state: "APPROVED" } })); await audit(userId, "agent.approval.approved", { userId, correlationId: run.correlationId, planId: validated.draft.planId, planVersion: validated.draft.version, approvalState: approval.state }, run.id); await persistAndExecute(userId, run.id, p.id, freezeAgentPlan(decided)); return getAgentRun(userId, run.id);
}

export async function getAgentRun(userId: string, runId: string): Promise<unknown> { const run = await withTenant({ userId }, (tx) => tx.agentRun.findFirst({ where: { id: runId, ownerId: userId }, include: { currentPlanVersion: true, workflowRun: { include: { jobs: { include: { steps: true, toolExecutions: true } } } } } })); if (!run) return null; if (run.workflowRun && !terminal.has(run.status) && ["SUCCEEDED", "FAILED", "CANCELLED"].includes(run.workflowRun.status)) return finalize(userId, run as Parameters<typeof finalize>[1]); return run; }

async function finalize(userId: string, run: { id: string; correlationId: string; status: string; currentPlanVersion: { frozenPlan: Prisma.JsonValue | null } | null; workflowRun: { id: string; status: string; jobs: Array<{ id: string; status: string; toolId: string; workflowNodeId: string | null; result: Prisma.JsonValue | null; steps: Array<{ id: string }>; toolExecutions: Array<{ id: string }> }> } }): Promise<unknown> {
  if (run.workflowRun.status === "CANCELLED") { await withTenant({ userId }, (tx) => tx.agentRun.update({ where: { id: run.id }, data: { status: "CANCELLED", completedAt: new Date() } })); await audit(userId, "agent.execution.failed", { userId, correlationId: run.correlationId, reasonCode: "CANCELLED" }, run.id); return getAgentRun(userId, run.id); }
  const frozen = run.currentPlanVersion?.frozenPlan as unknown as FrozenAgentPlan; assertFrozenAgentPlan(frozen);
  const outputs = run.workflowRun.jobs.flatMap((job) => { const result = job.result as { outputFileIds?: string[] } | null; return result?.outputFileIds ?? []; });
  const files = await withTenant({ userId }, (tx) => tx.file.findMany({ where: { id: { in: outputs }, document: { userId } }, select: { id: true, mimeType: true } }));
  const complete = run.workflowRun.status === "SUCCEEDED" && run.workflowRun.jobs.every((job) => job.status === "SUCCEEDED" && job.result) && files.length === outputs.length;
  const verification = complete ? createVerificationResult({ expectedOutputs: frozen.draft.steps.map((step) => ({ stepId: step.stepId, mimeTypes: toolRegistry[step.toolId].mime.output })), actualOutputs: run.workflowRun.jobs.map((job) => { const ids = (job.result as { outputFileIds?: string[] } | null)?.outputFileIds ?? []; return { stepId: job.workflowNodeId!, fileIds: ids, mimeTypes: toolRegistry[job.toolId].aiFlag ? ["application/json"] : files.filter((file) => ids.includes(file.id)).map((file) => file.mimeType) }; }), artifactValidation: "PASSED", schemaValidation: "PASSED", mimeValidation: "PASSED", reasons: [] }) : verificationFailure([{ code: "AGENT_WORKFLOW_FAILED", message: "Workflow execution or artifact verification failed." }]);
  const evidence = createExecutionEvidence(frozen, { correlationId: run.correlationId, workflowRunId: run.workflowRun.id, jobIds: run.workflowRun.jobs.map((j) => j.id), jobStepIds: run.workflowRun.jobs.flatMap((j) => j.steps.map((s) => s.id)), toolExecutionIds: run.workflowRun.jobs.flatMap((j) => j.toolExecutions.map((e) => e.id)), outputFileIds: outputs, verification });
  const succeeded = verification.status === "SUCCEEDED"; await withTenant({ userId }, (tx) => tx.agentRun.update({ where: { id: run.id }, data: { status: succeeded ? "SUCCEEDED" : "FAILED", verification: json(verification), evidence: json(evidence), errorCode: succeeded ? null : verification.reasons[0]?.code, completedAt: new Date() } })); await audit(userId, succeeded ? "agent.verification.succeeded" : "agent.verification.failed", { userId, correlationId: run.correlationId, planId: frozen.draft.planId, planVersion: frozen.draft.version, frozenPlanHash: frozen.integrity.hash, reasonCode: succeeded ? undefined : verification.reasons[0]?.code }, run.id); await audit(userId, succeeded ? "agent.execution.completed" : "agent.execution.failed", { userId, correlationId: run.correlationId, planId: frozen.draft.planId, planVersion: frozen.draft.version }, run.id); if (succeeded) await audit(userId, "agent.result.produced", { userId, correlationId: run.correlationId, planId: frozen.draft.planId, planVersion: frozen.draft.version }, run.id); return getAgentRun(userId, run.id);
}

export async function cancelAgentRun(userId: string, runId: string) { const run = await withTenant({ userId }, (tx) => tx.agentRun.findFirst({ where: { id: runId, ownerId: userId } })); if (!run) throw new AgentError("AGENT_PLAN_INVALID", "Agent run not found."); await audit(userId, "agent.cancellation.requested", { userId, correlationId: run.correlationId }, run.id); if (run.workflowRunId) await cancelWorkflowRun(userId, run.workflowRunId); await withTenant({ userId }, (tx) => tx.agentRun.update({ where: { id: run.id }, data: { status: "CANCELLED", completedAt: new Date() } })); return getAgentRun(userId, run.id); }
