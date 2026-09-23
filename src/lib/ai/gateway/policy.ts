import { db } from "@/lib/db";
import { withTenant } from "@/lib/db/tenant";
import { AiGatewayError, type AiRequestContext, type GatewayTask } from "./types";
import { productionAiProvider } from "./routing";

export function assertDocumentScope(input: { taskDocumentId: string; fileDocumentId: string; ownerId: string; requesterId: string; inputCount: number }) {
  if (input.inputCount !== 1 || input.taskDocumentId !== input.fileDocumentId || input.ownerId !== input.requesterId) throw new AiGatewayError("DOCUMENT_SCOPE_VIOLATION", "The requested document is outside the job scope.");
}

async function explicitlyDisabled(key: string) {
  const flag = await db.featureFlag.findUnique({ where: { key }, select: { enabled: true } });
  return flag?.enabled === false;
}

async function enforceCommonAiPolicy(task: GatewayTask, context: AiRequestContext) {
  if (process.env.AI_ENABLED === "false" || await explicitlyDisabled("ai.enabled")) throw new AiGatewayError("AI_KILL_SWITCH_ACTIVE", "AI processing is disabled.");
  if (await explicitlyDisabled(`ai.tool.${task.toolId}.enabled`)) throw new AiGatewayError("AI_TOOL_DISABLED", "This AI tool is disabled.");
  if (task.toolId !== context.toolId) throw new AiGatewayError("AI_TOOL_SCOPE_VIOLATION", "The task does not match the queued tool.");
  if (task.toolId !== "agent-planner") { const document = await withTenant({ userId: context.userId }, (tx) => tx.document.findFirst({ where: { id: task.documentId, userId: context.userId }, select: { id: true } })); if (!document) throw new AiGatewayError("DOCUMENT_SCOPE_VIOLATION", "The requested document is outside the job scope."); }
  // Credits and commercial entitlements are reserved before enqueue by the orchestrator.
}

export async function enforceAiPolicy(task: GatewayTask, context: AiRequestContext) {
  const provider = productionAiProvider();
  if (process.env[`${provider.toUpperCase()}_ENABLED`] === "false" || await explicitlyDisabled(`ai.provider.${provider}.enabled`)) throw new AiGatewayError("AI_PROVIDER_DISABLED", "The AI provider is disabled.");
  await enforceCommonAiPolicy(task, context);
}

export async function enforceAiEvaluationPolicy(task: GatewayTask, context: AiRequestContext) {
  if (process.env.GROQ_EVALUATION_ENABLED !== "1") throw new AiGatewayError("AI_EVALUATION_DISABLED", "Groq evaluation is disabled.");
  if (process.env.GROQ_ENABLED === "false" || await explicitlyDisabled("ai.provider.groq.enabled")) throw new AiGatewayError("AI_PROVIDER_DISABLED", "The evaluation provider is disabled.");
  await enforceCommonAiPolicy(task, context);
}
