import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { executeAiGateway, type AiProviderAdapter, type AiTask } from "../src/lib/ai/gateway";
import { buildProviderRequest } from "../src/lib/ai/gateway/task";
import { GeminiProviderAdapter } from "../src/lib/ai/gateway/providers/gemini";
import { GroqProviderAdapter } from "../src/lib/ai/gateway/providers/groq";
import { estimateAiCost } from "../src/lib/ai/gateway/usage";

type Fixture = { id: string; locale: "ar" | "en"; documentId: string; pages: string[]; question: string };
const live = process.env.AI_PROVIDER_EVALUATION_E2E === "1" ? test : test.skip;

function taskFor(fixture: Fixture, toolId: AiTask["toolId"]): AiTask {
  return {
    toolId,
    locale: fixture.locale,
    documentId: fixture.documentId,
    documentText: fixture.pages.map((page, index) => `[PAGE ${index + 1}]\n${page}\n[/PAGE ${index + 1}]`).join("\n"),
    pageCount: fixture.pages.length,
    ...(toolId === "chat-with-pdf" ? { question: fixture.question } : {}),
  };
}

live("CR-002 compares Gemini and Groq across the bilingual document-AI corpus", { timeout: 240_000 }, async () => {
  assert.ok(process.env.GEMINI_API_KEY, "GEMINI_API_KEY is required for provider comparison");
  assert.ok(process.env.GROQ_API_KEY, "GROQ_API_KEY is required for provider comparison");
  const fixtures = JSON.parse(await readFile(new URL("fixtures/ai/groq-evaluation.json", import.meta.url), "utf8")) as Fixture[];
  const providers: Array<{ name: "gemini" | "groq"; model: string; adapter: AiProviderAdapter }> = [
    { name: "gemini", model: process.env.GEMINI_MODEL ?? "gemini-3.8-flash", adapter: new GeminiProviderAdapter() },
    { name: "groq", model: process.env.GROQ_MODEL ?? "openai/gpt-oss-120b", adapter: new GroqProviderAdapter() },
  ];
  const results: Array<Record<string, string | number>> = [];
  for (const fixture of fixtures) for (const toolId of ["summarize-pdf", "chat-with-pdf", "extract-data"] as const) for (const provider of providers) {
    const task = taskFor(fixture, toolId); let accounted = 0;
    const result = await executeAiGateway(task, { jobId: crypto.randomUUID(), correlationId: crypto.randomUUID(), userId: crypto.randomUUID(), toolId }, {
      policy: async () => {},
      route: () => ({ adapter: provider.adapter, model: provider.model }),
      account: async (_context, response) => { accounted += 1; return { id: crypto.randomUUID(), cost: estimateAiCost(response), reused: false }; },
    });
    assert.equal(accounted, 1); assert.equal(result.response.provider, provider.name); assert.ok(result.response.inputTokens > 0); assert.ok(result.response.outputTokens > 0);
    assert.ok(result.output.citations.every((citation) => citation.page >= 1 && citation.page <= fixture.pages.length));
    results.push({ fixture: fixture.id, locale: fixture.locale, tool: toolId, provider: provider.name, model: result.response.model, inputTokens: result.response.inputTokens, outputTokens: result.response.outputTokens, latencyMs: result.response.latencyMs, citations: result.output.citations.length });
  }
  console.log(JSON.stringify({ event: "cr002.ai_evaluation.completed", results }));
});

test("CR-002 corpus covers Arabic and English for all three structured document tasks", async () => {
  const fixtures = JSON.parse(await readFile(new URL("fixtures/ai/groq-evaluation.json", import.meta.url), "utf8")) as Fixture[];
  assert.deepEqual(new Set(fixtures.map((fixture) => fixture.locale)), new Set(["ar", "en"]));
  for (const fixture of fixtures) for (const toolId of ["summarize-pdf", "chat-with-pdf", "extract-data"] as const) {
    const request = buildProviderRequest(taskFor(fixture, toolId), "openai/gpt-oss-120b");
    assert.equal(request.responseSchema.type, "object"); assert.match(request.systemInstruction, /document scope/); assert.match(request.systemInstruction, /untrusted evidence/);
  }
});
