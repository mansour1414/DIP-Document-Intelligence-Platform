import { timeoutFor } from "@/lib/runtime/config";
import { AiGatewayError, type AiProviderAdapter, type ProviderRequest, type ProviderResponse } from "../types";

type GroqPayload = {
  choices?: Array<{ message?: { content?: string } }>;
  usage?: { prompt_tokens?: number; completion_tokens?: number };
  error?: { code?: number | string; type?: string };
};

function safeProviderIdentifier(value: number | string | undefined) {
  const normalized = value === undefined ? undefined : String(value);
  return normalized && /^[A-Z0-9_.-]{1,80}$/i.test(normalized) ? normalized : undefined;
}

function httpFailure(status: number, payload: GroqPayload | null, model: string, latencyMs: number) {
  const retryable = status === 408 || status === 429 || status >= 500;
  const code = status === 408 ? "AI_PROVIDER_TIMEOUT" : status === 429 ? "AI_PROVIDER_RATE_LIMITED" : status === 401 || status === 403 ? "AI_PROVIDER_AUTH_FAILED" : "AI_PROVIDER_ERROR";
  const message = status === 408 ? "Groq timed out." : status === 429 ? "Groq rate limit was reached." : status >= 500 ? "Groq is temporarily unavailable." : "Groq rejected the request.";
  return new AiGatewayError(code, message, retryable, {
    provider: "groq",
    model,
    httpStatus: status,
    providerCode: safeProviderIdentifier(payload?.error?.code),
    providerStatus: safeProviderIdentifier(payload?.error?.type),
    latencyMs,
  });
}

export class GroqProviderAdapter implements AiProviderAdapter {
  readonly provider = "groq";
  readonly version = "openai-v1-chat-completions";

  constructor(private readonly apiKey = process.env.GROQ_API_KEY) {}

  async generate(request: ProviderRequest): Promise<ProviderResponse> {
    if (!this.apiKey) throw new AiGatewayError("AI_PROVIDER_NOT_CONFIGURED", "Groq evaluation is not configured.", false, { provider: this.provider, model: request.model });
    const controller = new AbortController(); const timeout = setTimeout(() => controller.abort(), timeoutFor("ai")); const started = Date.now();
    try {
      const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        signal: controller.signal,
        headers: { Authorization: `Bearer ${this.apiKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          model: request.model,
          messages: [{ role: "system", content: request.systemInstruction }, { role: "user", content: request.content }],
          max_completion_tokens: request.maxOutputTokens,
          response_format: { type: "json_schema", json_schema: { name: "dip_document_result", strict: false, schema: request.responseSchema } },
        }),
      });
      const payload = await response.json().catch(() => null) as GroqPayload | null;
      if (!response.ok) throw httpFailure(response.status, payload, request.model, Date.now() - started);
      const text = payload?.choices?.[0]?.message?.content?.trim();
      if (!text) throw new AiGatewayError("AI_PROVIDER_EMPTY_RESPONSE", "Groq returned no usable response.", true, { provider: this.provider, model: request.model, latencyMs: Date.now() - started });
      if (!payload?.usage || !Number.isInteger(payload.usage.prompt_tokens) || !Number.isInteger(payload.usage.completion_tokens)) throw new AiGatewayError("AI_PROVIDER_USAGE_MISSING", "Groq did not return token accounting metadata.", true, { provider: this.provider, model: request.model, latencyMs: Date.now() - started });
      return { provider: this.provider, model: request.model, text, inputTokens: payload.usage.prompt_tokens!, outputTokens: payload.usage.completion_tokens!, latencyMs: Date.now() - started };
    } catch (error) {
      if (error instanceof AiGatewayError) throw error;
      if (error instanceof Error && error.name === "AbortError") throw new AiGatewayError("AI_PROVIDER_TIMEOUT", "Groq timed out.", true, { provider: this.provider, model: request.model, latencyMs: Date.now() - started });
      throw new AiGatewayError("AI_PROVIDER_UNAVAILABLE", "Groq is unavailable.", true, { provider: this.provider, model: request.model, latencyMs: Date.now() - started });
    } finally { clearTimeout(timeout); }
  }
}
