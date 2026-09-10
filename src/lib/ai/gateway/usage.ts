import { db } from "@/lib/db";
import type { AiRequestContext, ProviderResponse } from "./types";
import { acquireTransactionAdvisoryLock } from "@/lib/db/advisory-lock";

function envNumber(name: string, fallback: number) { const value = Number(process.env[name]); return Number.isFinite(value) && value >= 0 ? value : fallback; }

export function estimateAiCost(response: Pick<ProviderResponse, "inputTokens" | "outputTokens">) {
  const inputPerMillion = envNumber("GEMINI_INPUT_USD_PER_MILLION", 0.30);
  const outputPerMillion = envNumber("GEMINI_OUTPUT_USD_PER_MILLION", 2.50);
  return (response.inputTokens * inputPerMillion + response.outputTokens * outputPerMillion) / 1_000_000;
}

export async function recordAiUsageOnce(context: AiRequestContext, response: ProviderResponse) {
  const cost = estimateAiCost(response);
  return db.$transaction(async (tx) => {
    await acquireTransactionAdvisoryLock(tx, `ai-usage:${context.jobId}`);
    const existing = await tx.aiUsage.findFirst({ where: { jobId: context.jobId }, select: { id: true, cost: true } });
    if (existing) return { id: existing.id, cost: Number(existing.cost), reused: true };
    const usage = await tx.aiUsage.create({ data: { userId: context.userId, jobId: context.jobId, provider: response.provider, model: response.model, taskType: context.toolId, tokensInput: response.inputTokens, tokensOutput: response.outputTokens, cost }, select: { id: true, cost: true } });
    return { id: usage.id, cost: Number(usage.cost), reused: false };
  // The advisory lock is the serialization mechanism for this job key.
  // READ COMMITTED gives a waiter a fresh snapshot after the lock holder commits;
  // SERIALIZABLE would retain its pre-wait snapshot and raise P2034 on the insert.
  }, { isolationLevel: "ReadCommitted" });
}
