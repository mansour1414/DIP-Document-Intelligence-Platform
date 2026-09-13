import { parseAgentPlanDraft } from "@/lib/agent/schema";
import type { AgentPlanDraft } from "@/lib/agent/types";
import { AiGatewayError, type AiTask, type AgentPlannerTask, type GatewayTask, type AiValidatedOutput, type Citation } from "./types";

function stringArray(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) throw new AiGatewayError("AI_RESPONSE_SCHEMA_INVALID", `${field} must be an array of strings.`);
  return value.map((item) => item.trim()).filter(Boolean);
}

function citations(value: unknown, pageCount: number): Citation[] {
  if (!Array.isArray(value)) throw new AiGatewayError("AI_RESPONSE_SCHEMA_INVALID", "citations must be an array.");
  return value.map((item) => {
    if (!item || typeof item !== "object") throw new AiGatewayError("AI_RESPONSE_SCHEMA_INVALID", "A citation is invalid.");
    const page = (item as { page?: unknown }).page; const quote = (item as { quote?: unknown }).quote;
    if (!Number.isInteger(page) || Number(page) < 1 || Number(page) > pageCount) throw new AiGatewayError("AI_CITATION_INVALID", "A citation refers outside the document scope.");
    if (quote !== undefined && (typeof quote !== "string" || quote.length > 500)) throw new AiGatewayError("AI_CITATION_INVALID", "A citation quote is invalid.");
    return { page: Number(page), ...(typeof quote === "string" && quote.trim() ? { quote: quote.trim() } : {}) };
  });
}

export function validateProviderResponse(task: AiTask, text: string): AiValidatedOutput;
export function validateProviderResponse(task: AgentPlannerTask, text: string): AgentPlanDraft;
export function validateProviderResponse(task: GatewayTask, text: string): AiValidatedOutput | AgentPlanDraft;
export function validateProviderResponse(task: GatewayTask, text: string): AiValidatedOutput | AgentPlanDraft {
  let value: unknown;
  try { value = JSON.parse(text); } catch { throw new AiGatewayError("AI_RESPONSE_SCHEMA_INVALID", "The provider returned malformed JSON."); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new AiGatewayError("AI_RESPONSE_SCHEMA_INVALID", "The provider output is not an object.");
  if (task.toolId === "agent-planner") { try { return parseAgentPlanDraft(value); } catch { throw new AiGatewayError("AI_RESPONSE_SCHEMA_INVALID", "The planner returned an invalid AgentPlanDraft."); } }
  const record = value as Record<string, unknown>; const checkedCitations = citations(record.citations, task.pageCount);
  if (task.toolId !== "extract-data") {
    if (typeof record.answer !== "string" || !record.answer.trim() || record.answer.length > 40_000) throw new AiGatewayError("AI_RESPONSE_SCHEMA_INVALID", "The provider answer is empty or too large.");
    return { answer: record.answer.trim(), citations: checkedCitations };
  }
  if (typeof record.summary !== "string" || record.summary.length > 40_000) throw new AiGatewayError("AI_RESPONSE_SCHEMA_INVALID", "summary must be text.");
  return { summary: record.summary.trim(), entities: stringArray(record.entities, "entities"), dates: stringArray(record.dates, "dates"), amounts: stringArray(record.amounts, "amounts"), contacts: stringArray(record.contacts, "contacts"), actionItems: stringArray(record.actionItems, "actionItems"), citations: checkedCitations };
}
