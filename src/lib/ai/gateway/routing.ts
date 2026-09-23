import { GeminiProviderAdapter } from "./providers/gemini";
import { GroqProviderAdapter } from "./providers/groq";
import { AiGatewayError, type AiProviderAdapter, type GatewayTask } from "./types";
import { assertAiPricingConfigured } from "./usage";

export type AiRouteClass = "high_accuracy" | "balanced" | "economy";
export type AiRoute = { adapter: AiProviderAdapter; model: string; routeClass?: AiRouteClass };
export type ProductionAiProvider = "groq" | "gemini";

export function productionAiProvider(): ProductionAiProvider {
  const provider = (process.env.AI_PROVIDER ?? "groq").toLowerCase();
  if (provider !== "groq" && provider !== "gemini") throw new AiGatewayError("AI_PROVIDER_NOT_REGISTERED", `Production provider ${provider} is not registered.`);
  return provider;
}

export function routeAiTask(task: GatewayTask): AiRoute {
  if (!task.toolId) throw new AiGatewayError("AI_TASK_INVALID", "AI task is missing a tool identifier.");
  const routeClass: AiRouteClass = task.toolId === "extract-data" ? "high_accuracy" : task.toolId === "chat-with-pdf" ? "balanced" : "economy";
  const provider = productionAiProvider();
  const model = provider === "groq"
    ? process.env[`GROQ_MODEL_${routeClass.toUpperCase()}`] ?? process.env.GROQ_MODEL ?? "openai/gpt-oss-120b"
    : process.env[`GEMINI_MODEL_${routeClass.toUpperCase()}`] ?? process.env.GEMINI_MODEL ?? "gemini-3.8-flash";
  assertAiPricingConfigured(provider, model);
  return { adapter: provider === "groq" ? new GroqProviderAdapter() : new GeminiProviderAdapter(), model, routeClass };
}

export function routeAiEvaluationTask(task: GatewayTask): AiRoute {
  if (process.env.GROQ_EVALUATION_ENABLED !== "1") throw new AiGatewayError("AI_EVALUATION_DISABLED", "Groq evaluation is disabled.");
  if (task.toolId === "agent-planner") throw new AiGatewayError("AI_EVALUATION_TASK_NOT_ALLOWED", "Groq evaluation is limited to document AI tools.");
  const provider = (process.env.AI_EVALUATION_PROVIDER ?? "groq").toLowerCase();
  if (provider !== "groq") throw new AiGatewayError("AI_PROVIDER_NOT_REGISTERED", `Evaluation provider ${provider} is not registered.`);
  const routeClass: AiRouteClass = task.toolId === "extract-data" ? "high_accuracy" : task.toolId === "chat-with-pdf" ? "balanced" : "economy";
  const model = process.env[`GROQ_MODEL_${routeClass.toUpperCase()}`] ?? process.env.GROQ_MODEL ?? "openai/gpt-oss-120b";
  assertAiPricingConfigured(provider, model);
  return { adapter: new GroqProviderAdapter(), model, routeClass };
}
