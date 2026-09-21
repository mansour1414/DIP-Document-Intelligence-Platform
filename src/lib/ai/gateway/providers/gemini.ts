import { AiGatewayError, type AiProviderAdapter, type ProviderRequest, type ProviderResponse } from "../types";
import { timeoutFor } from "@/lib/runtime/config";

type GeminiPayload = {
  candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
  usageMetadata?: { promptTokenCount?: number; candidatesTokenCount?: number };
  error?: { code?: number | string; message?: string; status?: string };
};

function safeProviderIdentifier(value: number | string | undefined) {
  const normalized = value === undefined ? undefined : String(value);
  return normalized && /^[A-Z0-9_.-]{1,80}$/i.test(normalized) ? normalized : undefined;
}

function httpFailure(status: number, payload: GeminiPayload | null, model: string, latencyMs: number) {
  const retryable = status === 408 || status === 429 || status >= 500;
  const code = status === 408 ? "AI_PROVIDER_TIMEOUT" : status === 429 ? "AI_PROVIDER_RATE_LIMITED" : status === 401 || status === 403 ? "AI_PROVIDER_AUTH_FAILED" : "AI_PROVIDER_ERROR";
  const message = status === 408 ? "Gemini timed out." : status === 429 ? "Gemini rate limit was reached." : status >= 500 ? "Gemini is temporarily unavailable." : "Gemini rejected the request.";
  return new AiGatewayError(code, message, retryable, {
    provider: "gemini",
    model,
    httpStatus: status,
    providerCode: safeProviderIdentifier(payload?.error?.code),
    providerStatus: safeProviderIdentifier(payload?.error?.status),
    latencyMs,
  });
}

export class GeminiProviderAdapter implements AiProviderAdapter {
  readonly provider = "gemini";
  readonly version = "v1beta-rest";

  constructor(private readonly apiKey = process.env.GEMINI_API_KEY) {}

  async generate(request: ProviderRequest): Promise<ProviderResponse> {
    if (!this.apiKey) throw new AiGatewayError("AI_PROVIDER_NOT_CONFIGURED", "Gemini is not configured.", false, { provider: this.provider, model: request.model });
    const controller = new AbortController(); const timeout = setTimeout(() => controller.abort(), timeoutFor("ai")); const started = Date.now();
    try {
      const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(request.model)}:generateContent?key=${encodeURIComponent(this.apiKey)}`, {
        method: "POST", signal: controller.signal, headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: request.systemInstruction }] },
          contents: [{ role: "user", parts: [{ text: request.content }] }],
          generationConfig: { maxOutputTokens: request.maxOutputTokens, responseMimeType: "application/json", responseJsonSchema: request.responseSchema },
        }),
      });
      const payload = await response.json().catch(() => null) as GeminiPayload | null;
      if (!response.ok) throw httpFailure(response.status, payload, request.model, Date.now() - started);
      const text = payload?.candidates?.[0]?.content?.parts?.map((part) => part.text ?? "").join("").trim();
      if (!text) throw new AiGatewayError("AI_PROVIDER_EMPTY_RESPONSE", "Gemini returned no usable response.", true, { provider: this.provider, model: request.model, latencyMs: Date.now() - started });
      if (!payload?.usageMetadata || !Number.isInteger(payload.usageMetadata.promptTokenCount) || !Number.isInteger(payload.usageMetadata.candidatesTokenCount)) throw new AiGatewayError("AI_PROVIDER_USAGE_MISSING", "Gemini did not return token accounting metadata.", true, { provider: this.provider, model: request.model, latencyMs: Date.now() - started });
      return { provider: this.provider, model: request.model, text, inputTokens: payload.usageMetadata.promptTokenCount!, outputTokens: payload.usageMetadata.candidatesTokenCount!, latencyMs: Date.now() - started };
    } catch (error) {
      if (error instanceof AiGatewayError) throw error;
      if (error instanceof Error && error.name === "AbortError") throw new AiGatewayError("AI_PROVIDER_TIMEOUT", "Gemini timed out.", true, { provider: this.provider, model: request.model, latencyMs: Date.now() - started });
      throw new AiGatewayError("AI_PROVIDER_UNAVAILABLE", "Gemini is unavailable.", true, { provider: this.provider, model: request.model, latencyMs: Date.now() - started });
    } finally { clearTimeout(timeout); }
  }
}
