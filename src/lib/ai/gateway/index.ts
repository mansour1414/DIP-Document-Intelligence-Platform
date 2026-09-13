import { logger } from "@/lib/logging";
import { enforceAiPolicy } from "./policy";
import { routeAiTask, type AiRoute } from "./routing";
import { buildProviderRequest, validateAiTask } from "./task";
import type { AgentPlanDraft } from "@/lib/agent/types";
import type { AiRequestContext, AiTask, AgentPlannerTask, GatewayTask, AiValidatedOutput, ProviderResponse } from "./types";
import { recordAiUsageOnce } from "./usage";
import { validateProviderResponse } from "./validation";
import { recordMetric } from "@/lib/observability/metrics";

export type GatewayDependencies = {
  policy: typeof enforceAiPolicy;
  route: (task: GatewayTask) => AiRoute;
  account: typeof recordAiUsageOnce;
};

const productionDependencies: GatewayDependencies = { policy: enforceAiPolicy, route: routeAiTask, account: recordAiUsageOnce };

export function executeAiGateway(task: AgentPlannerTask, context: AiRequestContext, dependencies?: GatewayDependencies): Promise<{ output: AgentPlanDraft; response: ProviderResponse; estimatedCost: number }>;
export function executeAiGateway(task: AiTask, context: AiRequestContext, dependencies?: GatewayDependencies): Promise<{ output: AiValidatedOutput; response: ProviderResponse; estimatedCost: number }>;
export async function executeAiGateway(task: GatewayTask, context: AiRequestContext, dependencies: GatewayDependencies = productionDependencies): Promise<{ output: AiValidatedOutput | AgentPlanDraft; response: ProviderResponse; estimatedCost: number }> {
  if (task.toolId !== "agent-planner") validateAiTask(task);
  await dependencies.policy(task, context);
  const route = dependencies.route(task); const request = buildProviderRequest(task, route.model);
  const response = await route.adapter.generate(request);
  const output = validateProviderResponse(task, response.text);
  const usage = await dependencies.account(context, response);
  const labels = { tool_id: context.toolId, engine: response.provider, engine_version: response.model, status: "succeeded" };
  recordMetric("ai_latency_ms", response.latencyMs, "ms", labels); recordMetric("ai_input_tokens", response.inputTokens, "count", labels); recordMetric("ai_output_tokens", response.outputTokens, "count", labels); recordMetric("ai_estimated_cost", usage.cost, "ratio", labels);
  logger.info("ai.request.completed", { provider: response.provider, model: response.model, input_tokens: response.inputTokens, output_tokens: response.outputTokens, latency_ms: response.latencyMs, estimated_cost: usage.cost, tool_id: context.toolId, job_id: context.jobId, agent_run_id: context.agentRunId, correlation_id: context.correlationId, user_id: context.userId, usage_reused: usage.reused });
  return { output, response, estimatedCost: usage.cost };
}

export * from "./types";
