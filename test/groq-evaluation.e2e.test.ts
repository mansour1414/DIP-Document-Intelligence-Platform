import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { AiGatewayError, executeAiGateway, type AiProviderAdapter, type AiTask, type AiValidatedOutput, type ProviderResponse } from "../src/lib/ai/gateway";
import { buildProviderRequest } from "../src/lib/ai/gateway/task";
import { GeminiProviderAdapter } from "../src/lib/ai/gateway/providers/gemini";
import { GroqProviderAdapter } from "../src/lib/ai/gateway/providers/groq";
import { estimateAiCost } from "../src/lib/ai/gateway/usage";

type Fixture = { id: string; locale: "ar" | "en"; documentId: string; pages: string[]; question: string };
type Provider = { name: "gemini" | "groq"; model: string; adapter: AiProviderAdapter };
type EvaluationResult = {
  fixture: string; locale: Fixture["locale"]; tool: AiTask["toolId"]; provider: Provider["name"]; model: string;
  status: "success" | "failure"; errorCode: string | null; retryable: boolean | null; httpStatus: number | null;
  latencyMs: number; inputTokens: number | null; outputTokens: number | null;
  structuredOutputValid: boolean; citationsValid: boolean; groundingValid: boolean; citationCount: number;
  accounted: boolean;
};
const taskIds = ["summarize-pdf", "chat-with-pdf", "extract-data"] as const;
const live = process.env.AI_PROVIDER_EVALUATION_E2E === "1" ? test : test.skip;

function taskFor(fixture: Fixture, toolId: AiTask["toolId"]): AiTask {
  return {
    toolId, locale: fixture.locale, documentId: fixture.documentId,
    documentText: fixture.pages.map((page, index) => `[PAGE ${index + 1}]\n${page}\n[/PAGE ${index + 1}]`).join("\n"),
    pageCount: fixture.pages.length,
    ...(toolId === "chat-with-pdf" ? { question: fixture.question } : {}),
  };
}

function groundingChecks(output: AiValidatedOutput, fixture: Fixture) {
  const citationsValid = output.citations.length > 0 && output.citations.every(({ page }) => Number.isInteger(page) && page >= 1 && page <= fixture.pages.length);
  const groundingValid = citationsValid && output.citations.every(({ page, quote }) => !quote || fixture.pages[page - 1].includes(quote));
  return { citationsValid, groundingValid, citationCount: output.citations.length };
}

async function evaluateCase(fixture: Fixture, toolId: AiTask["toolId"], provider: Provider): Promise<EvaluationResult> {
  const task = taskFor(fixture, toolId); const started = Date.now(); let response: ProviderResponse | undefined; let accounted = false;
  const result: EvaluationResult = {
    fixture: fixture.id, locale: fixture.locale, tool: toolId, provider: provider.name, model: provider.model,
    status: "failure", errorCode: null, retryable: null, httpStatus: null, latencyMs: 0,
    inputTokens: null, outputTokens: null, structuredOutputValid: false, citationsValid: false, groundingValid: false, citationCount: 0, accounted: false,
  };
  try {
    const gateway = await executeAiGateway(task, { jobId: randomUUID(), correlationId: randomUUID(), userId: randomUUID(), toolId }, {
      // Synthetic checked-in fixtures have no tenant document or production credit reservation.
      policy: async () => {},
      route: () => ({ adapter: { provider: provider.adapter.provider, version: provider.adapter.version, generate: async (request) => { response = await provider.adapter.generate(request); return response; } }, model: provider.model }),
      account: async (_context, usage) => { const cost = estimateAiCost(usage); accounted = true; return { id: randomUUID(), cost, reused: false }; },
    });
    const checks = groundingChecks(gateway.output, fixture);
    Object.assign(result, { status: checks.groundingValid ? "success" : "failure", errorCode: checks.groundingValid ? null : "AI_EVALUATION_GROUNDING_FAILED", structuredOutputValid: true, ...checks });
  } catch (error) {
    // Provider messages and raw output can contain document text; only stable classifications are recorded.
    result.errorCode = error instanceof AiGatewayError ? error.code : "AI_EVALUATION_UNEXPECTED_FAILURE";
    result.retryable = error instanceof AiGatewayError ? error.retryable : null;
    result.httpStatus = error instanceof AiGatewayError ? error.metadata.httpStatus ?? null : null;
  }
  result.latencyMs = response?.latencyMs ?? Date.now() - started;
  result.inputTokens = response?.inputTokens ?? null; result.outputTokens = response?.outputTokens ?? null;
  result.accounted = accounted;
  return result;
}

async function evaluateCorpus(fixtures: Fixture[], providers: Provider[]) {
  const results: EvaluationResult[] = [];
  for (const fixture of fixtures) for (const toolId of taskIds) for (const provider of providers) {
    results.push(await evaluateCase(fixture, toolId, provider));
  }
  return results;
}

function comparisonSummary(results: EvaluationResult[]) {
  return (["gemini", "groq"] as const).map((provider) => {
    const cases = results.filter((result) => result.provider === provider);
    return {
      provider, total: cases.length, succeeded: cases.filter((result) => result.status === "success").length,
      failed: cases.filter((result) => result.status === "failure").length,
      structuredOutputValid: cases.filter((result) => result.structuredOutputValid).length,
      citationsValid: cases.filter((result) => result.citationsValid).length,
      groundingValid: cases.filter((result) => result.groundingValid).length,
      inputTokens: cases.reduce((sum, result) => sum + (result.inputTokens ?? 0), 0),
      outputTokens: cases.reduce((sum, result) => sum + (result.outputTokens ?? 0), 0),
      latencyMs: cases.reduce((sum, result) => sum + result.latencyMs, 0),
      errors: cases.filter((result) => result.errorCode).map(({ fixture, locale, tool, errorCode, httpStatus, retryable }) => ({ fixture, locale, tool, errorCode, httpStatus, retryable })),
    };
  });
}

function assertGroqEvaluationGate(results: EvaluationResult[], fixtureCount: number) {
  const groq = results.filter((result) => result.provider === "groq");
  assert.equal(groq.length, fixtureCount * taskIds.length, "Groq evaluation did not cover every locale and task");
  assert.ok(groq.every((result) => result.status === "success" && result.structuredOutputValid && result.citationsValid && result.groundingValid && result.accounted && (result.inputTokens ?? 0) > 0 && (result.outputTokens ?? 0) > 0), "Groq failed the CR-002 automated Evaluation Gate; inspect the safe comparison summary");
}

live("CR-002 compares Gemini and Groq independently across the bilingual document-AI corpus", { timeout: 900_000 }, async () => {
  assert.ok(process.env.GROQ_API_KEY, "GROQ_API_KEY is required for Groq evaluation");
  const fixtures = JSON.parse(await readFile(new URL("fixtures/ai/groq-evaluation.json", import.meta.url), "utf8")) as Fixture[];
  const providers: Provider[] = [
    { name: "groq", model: process.env.GROQ_MODEL ?? "openai/gpt-oss-120b", adapter: new GroqProviderAdapter() },
    ...(process.env.GEMINI_API_KEY ? [{ name: "gemini" as const, model: process.env.GEMINI_MODEL ?? "gemini-3.8-flash", adapter: new GeminiProviderAdapter() }] : []),
  ];
  const results = await evaluateCorpus(fixtures, providers);
  console.log(JSON.stringify({ event: "cr002.ai_evaluation.completed", results, comparison: comparisonSummary(results) }));
  assertGroqEvaluationGate(results, fixtures.length);
});

test("Gemini failure does not prevent Groq calls or determine Groq's gate result", async () => {
  const fixture: Fixture = { id: "regression", locale: "en", documentId: randomUUID(), pages: ["The contract value is USD 24,000."], question: "What is the value?" };
  let groqCalls = 0;
  const providers: Provider[] = [
    { name: "gemini", model: "gemini-3.8-flash", adapter: { provider: "gemini", version: "test", async generate() { throw new AiGatewayError("AI_PROVIDER_RATE_LIMITED", "redacted", true, { httpStatus: 429 }); } } },
    { name: "groq", model: "openai/gpt-oss-120b", adapter: { provider: "groq", version: "test", async generate(request) { groqCalls += 1; return { provider: "groq", model: request.model, text: JSON.stringify(request.content.includes("Extract structured data") ? { summary: "USD 24,000", entities: [], dates: [], amounts: ["USD 24,000"], contacts: [], actionItems: [], citations: [{ page: 1 }] } : { answer: "USD 24,000", citations: [{ page: 1 }] }), inputTokens: 10, outputTokens: 5, latencyMs: 2 }; } } },
  ];
  const results = await evaluateCorpus([fixture], providers);
  assert.equal(groqCalls, taskIds.length); assert.equal(results.filter((result) => result.provider === "gemini" && result.errorCode === "AI_PROVIDER_RATE_LIMITED").length, taskIds.length);
  assert.equal(comparisonSummary(results).find((summary) => summary.provider === "groq")?.succeeded, taskIds.length);
  assert.doesNotThrow(() => assertGroqEvaluationGate(results, 1));
  results.find((result) => result.provider === "groq")!.groundingValid = false;
  assert.throws(() => assertGroqEvaluationGate(results, 1), /Groq failed/);
});

test("CR-002 corpus covers Arabic and English for all three structured document tasks", async () => {
  const fixtures = JSON.parse(await readFile(new URL("fixtures/ai/groq-evaluation.json", import.meta.url), "utf8")) as Fixture[];
  assert.deepEqual(new Set(fixtures.map((fixture) => fixture.locale)), new Set(["ar", "en"]));
  for (const fixture of fixtures) for (const toolId of taskIds) {
    const request = buildProviderRequest(taskFor(fixture, toolId), "openai/gpt-oss-120b");
    assert.equal(request.responseSchema.type, "object"); assert.match(request.systemInstruction, /document scope/); assert.match(request.systemInstruction, /untrusted evidence/);
  }
});
