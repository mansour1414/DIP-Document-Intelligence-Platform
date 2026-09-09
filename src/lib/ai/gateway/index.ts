import { logger } from "@/lib/logging";
import { enforceAiPolicy } from "./policy";
import { routeAiTask, type AiRoute } from "./routing";
import { buildProviderRequest, validateAiTask } from "./task";
import type { AiRequestContext, AiTask, AiValidatedOutput, ProviderResponse } from "./types";
import { recordAiUsageOnce } from "./usage";
import { validateProviderResponse } from "./validation";

export type GatewayDependencies = {
  policy: typeof enforceAiPolicy;
  route: (task: AiTask) => AiRoute;
  account: typeof recordAiUsageOnce;
};

const productionDependencies: GatewayDependencies = { policy: enforceAiPolicy, route: routeAiTask, account: recordAiUsageOnce };

export async function executeAiGateway(task: AiTask, context: AiRequestContext, dependencies: GatewayDependencies = productionDependencies): Promise<{ output: AiValidatedOutput; response: ProviderResponse; estimatedCost: number }> {
  validateAiTask(task);
  await dependencies.policy(task, context);
  const route = dependencies.route(task); const request = buildProviderRequest(task, route.model);
  const response = await route.adapter.generate(request);
  const output = validateProviderResponse(task, response.text);
  const usage = await dependencies.account(context, response);
  logger.info("ai.request.completed", { provider: response.provider, model: response.model, input_tokens: response.inputTokens, output_tokens: response.outputTokens, latency_ms: response.latencyMs, estimated_cost: usage.cost, tool_id: context.toolId, job_id: context.jobId, correlation_id: context.correlationId, user_id: context.userId, usage_reused: usage.reused });
  return { output, response, estimatedCost: usage.cost };
}

export * from "./types";
