import type { AiRequestContext, ProviderResponse } from "./types";
import { acquireTransactionAdvisoryLock } from "@/lib/db/advisory-lock";
import { withTenant } from "@/lib/db/tenant";

type GeminiPrice = { inputPerMillion: number; outputPerMillion: number };
// Audited 2026-09-21 from https://ai.google.dev/gemini-api/docs/pricing (Standard paid tier).
export const GEMINI_38_STANDARD_PRICE_EFFECTIVE_AT = new Date("2027-01-01T00:00:00Z");
const GEMINI_38_INTRODUCTORY_PRICE: GeminiPrice = { inputPerMillion: 0.75, outputPerMillion: 3.75 };
const GEMINI_38_STANDARD_PRICE: GeminiPrice = { inputPerMillion: 1.50, outputPerMillion: 7.50 };
function envNumber(name: string) { const raw = process.env[name]?.trim(); if (!raw) return; const value = Number(raw); return Number.isFinite(value) && value >= 0 ? value : undefined; }
export function defaultGeminiPrice(model: string, at = new Date()): GeminiPrice { if (model !== "gemini-3.8-flash") throw new Error("GEMINI_PRICE_NOT_CONFIGURED"); return at < GEMINI_38_STANDARD_PRICE_EFFECTIVE_AT ? GEMINI_38_INTRODUCTORY_PRICE : GEMINI_38_STANDARD_PRICE; }

export function estimateAiCost(response: Pick<ProviderResponse, "model" | "inputTokens" | "outputTokens">, at = new Date()) {
  const configuredInput = envNumber("GEMINI_INPUT_USD_PER_MILLION"); const configuredOutput = envNumber("GEMINI_OUTPUT_USD_PER_MILLION");
  if ((configuredInput === undefined) !== (configuredOutput === undefined)) throw new Error("GEMINI_PRICE_CONFIGURATION_INCOMPLETE");
  const defaults = configuredInput === undefined ? defaultGeminiPrice(response.model, at) : { inputPerMillion: configuredInput, outputPerMillion: configuredOutput! };
  const { inputPerMillion, outputPerMillion } = defaults;
  return (response.inputTokens * inputPerMillion + response.outputTokens * outputPerMillion) / 1_000_000;
}

export async function recordAiUsageOnce(context: AiRequestContext, response: ProviderResponse) {
  const cost = estimateAiCost(response);
  const reference = context.agentRunId ? { agentRunId: context.agentRunId } : { jobId: context.jobId };
  const referenceKey = context.agentRunId ? `agent:${context.agentRunId}` : `job:${context.jobId}`;
  return withTenant({ userId: context.userId }, async (tx) => {
    await acquireTransactionAdvisoryLock(tx, `ai-usage:${referenceKey}`);
    const existing = await tx.aiUsage.findFirst({ where: reference, select: { id: true, cost: true } });
    if (existing) return { id: existing.id, cost: Number(existing.cost), reused: true };
    const usage = await tx.aiUsage.create({ data: { userId: context.userId, ...reference, provider: response.provider, model: response.model, taskType: context.toolId, tokensInput: response.inputTokens, tokensOutput: response.outputTokens, cost }, select: { id: true, cost: true } });
    return { id: usage.id, cost: Number(usage.cost), reused: false };
  // The advisory lock serializes the concrete Job or AgentRun usage key.
  // READ COMMITTED gives a waiter a fresh snapshot after the lock holder commits;
  // SERIALIZABLE would retain its pre-wait snapshot and raise P2034 on the insert.
  });
}
