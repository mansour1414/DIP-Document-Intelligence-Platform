import { logger, type LogContext } from "@/lib/logging";

export const AGENT_AUDIT_EVENTS = ["agent.request.received", "agent.scope.resolved", "agent.plan.proposed", "agent.plan.validation_failed", "agent.plan.validated", "agent.permission.denied", "agent.budget.previewed", "agent.budget.rejected", "agent.approval.required", "agent.approval.approved", "agent.approval.rejected", "agent.plan.frozen", "agent.verification.succeeded", "agent.verification.failed"] as const;
export type AgentAuditEvent = typeof AGENT_AUDIT_EVENTS[number];
export type AgentAuditContext = Readonly<{ userId: string; correlationId: string; planId?: string; planVersion?: number; stepId?: string; toolId?: string; decision?: string; reasonCode?: string; budgetFits?: boolean; approvalState?: string; frozenPlanHash?: string }>;
export function agentAuditContext(context: AgentAuditContext): LogContext { return { user_id: context.userId, correlation_id: context.correlationId, plan_id: context.planId, plan_version: context.planVersion, step_id: context.stepId, tool_id: context.toolId, decision: context.decision, reason_code: context.reasonCode, budget_fits: context.budgetFits, approval_state: context.approvalState, frozen_plan_hash: context.frozenPlanHash }; }
export function recordAgentAudit(event: AgentAuditEvent, context: AgentAuditContext) { logger.info(event, agentAuditContext(context)); }
