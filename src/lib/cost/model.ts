export type CostInputs = { cpuDurationMs: number; memoryClassMb: number; storageBytes: number; storageOperations: number; aiInputTokens: number; aiOutputTokens: number; ocrPages: number; officeDurationMs: number; succeeded: boolean };
export type CostRates = { cpuPerMs: number; memoryMbMs: number; storageByte: number; storageOperation: number; aiInputToken: number; aiOutputToken: number; ocrPage: number; officeMs: number };
function rate(name: string) { const value = Number(process.env[name] ?? 0); return Number.isFinite(value) && value >= 0 ? value : 0; }
export function configuredCostRates(): CostRates { return { cpuPerMs: rate("COST_CPU_PER_MS"), memoryMbMs: rate("COST_MEMORY_MB_MS"), storageByte: rate("COST_STORAGE_BYTE"), storageOperation: rate("COST_STORAGE_OPERATION"), aiInputToken: rate("COST_AI_INPUT_TOKEN"), aiOutputToken: rate("COST_AI_OUTPUT_TOKEN"), ocrPage: rate("COST_OCR_PAGE"), officeMs: rate("COST_OFFICE_MS") }; }
export function estimateJobCost(input: CostInputs, rates: CostRates) {
  const components = { cpu: input.cpuDurationMs * rates.cpuPerMs, memory: input.cpuDurationMs * input.memoryClassMb * rates.memoryMbMs, storage: input.storageBytes * rates.storageByte + input.storageOperations * rates.storageOperation, ai: input.aiInputTokens * rates.aiInputToken + input.aiOutputTokens * rates.aiOutputToken, ocr: input.ocrPages * rates.ocrPage, office: input.officeDurationMs * rates.officeMs };
  const estimatedTotal = Object.values(components).reduce((sum, value) => sum + value, 0);
  return { components, estimatedTotal, costPerSuccessfulJob: input.succeeded ? estimatedTotal : null };
}
