import { GeminiProviderAdapter } from "./providers/gemini";
import { AiGatewayError, type AiProviderAdapter, type GatewayTask } from "./types";

export type AiRouteClass = "high_accuracy" | "balanced" | "economy";
export type AiRoute = { adapter: AiProviderAdapter; model: string; routeClass?: AiRouteClass };

export function routeAiTask(task: GatewayTask): AiRoute {
  if (!task.toolId) throw new AiGatewayError("AI_TASK_INVALID", "AI task is missing a tool identifier.");
  const provider = (process.env.AI_PROVIDER ?? "gemini").toLowerCase();
  if (provider !== "gemini") throw new AiGatewayError("AI_PROVIDER_NOT_REGISTERED", `AI provider ${provider} is not registered.`);
  const routeClass: AiRouteClass = task.toolId === "extract-data" ? "high_accuracy" : task.toolId === "chat-with-pdf" ? "balanced" : "economy";
  const model = process.env[`GEMINI_MODEL_${routeClass.toUpperCase()}`] ?? process.env.GEMINI_MODEL ?? "gemini-3.6-flash";
  return { adapter: new GeminiProviderAdapter(), model, routeClass };
}
