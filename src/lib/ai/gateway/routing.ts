import { GeminiProviderAdapter } from "./providers/gemini";
import { AiGatewayError, type AiProviderAdapter, type AiTask } from "./types";

export type AiRoute = { adapter: AiProviderAdapter; model: string };

export function routeAiTask(task: AiTask): AiRoute {
  if (!task.toolId) throw new AiGatewayError("AI_TASK_INVALID", "AI task is missing a tool identifier.");
  const provider = (process.env.AI_PROVIDER ?? "gemini").toLowerCase();
  if (provider !== "gemini") throw new AiGatewayError("AI_PROVIDER_NOT_REGISTERED", `AI provider ${provider} is not registered.`);
  return { adapter: new GeminiProviderAdapter(), model: process.env.GEMINI_MODEL ?? "gemini-2.5-flash" };
}
