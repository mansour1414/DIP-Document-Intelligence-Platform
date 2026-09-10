import { db } from "@/lib/db";
import { AiGatewayError, type AiRequestContext, type AiTask } from "./types";

export function assertDocumentScope(input: { taskDocumentId: string; fileDocumentId: string; ownerId: string; requesterId: string; inputCount: number }) {
  if (input.inputCount !== 1 || input.taskDocumentId !== input.fileDocumentId || input.ownerId !== input.requesterId) throw new AiGatewayError("DOCUMENT_SCOPE_VIOLATION", "The requested document is outside the job scope.");
}

async function explicitlyDisabled(key: string) {
  const flag = await db.featureFlag.findUnique({ where: { key }, select: { enabled: true } });
  return flag?.enabled === false;
}

export async function enforceAiPolicy(task: AiTask, context: AiRequestContext) {
  if (process.env.AI_ENABLED === "false" || await explicitlyDisabled("ai.enabled")) throw new AiGatewayError("AI_KILL_SWITCH_ACTIVE", "AI processing is disabled.");
  if (process.env.GEMINI_ENABLED === "false" || await explicitlyDisabled("ai.provider.gemini.enabled")) throw new AiGatewayError("AI_PROVIDER_DISABLED", "The AI provider is disabled.");
  if (await explicitlyDisabled(`ai.tool.${task.toolId}.enabled`)) throw new AiGatewayError("AI_TOOL_DISABLED", "This AI tool is disabled.");
  if (task.toolId !== context.toolId) throw new AiGatewayError("AI_TOOL_SCOPE_VIOLATION", "The task does not match the queued tool.");
  const document = await db.document.findFirst({ where: { id: task.documentId, userId: context.userId }, select: { id: true } });
  if (!document) throw new AiGatewayError("DOCUMENT_SCOPE_VIOLATION", "The requested document is outside the job scope.");
  // Credits and commercial entitlements are reserved before enqueue by the orchestrator.
}
