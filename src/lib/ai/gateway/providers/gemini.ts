import { AiGatewayError, type AiProviderAdapter, type ProviderRequest, type ProviderResponse } from "../types";
import { timeoutFor } from "@/lib/runtime/config";

type GeminiPayload = {
  candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
  usageMetadata?: { promptTokenCount?: number; candidatesTokenCount?: number };
  error?: { message?: string; status?: string };
};

export class GeminiProviderAdapter implements AiProviderAdapter {
  readonly provider = "gemini";
  readonly version = "v1beta-rest";

  constructor(private readonly apiKey = process.env.GEMINI_API_KEY) {}

  async generate(request: ProviderRequest): Promise<ProviderResponse> {
    if (!this.apiKey) throw new AiGatewayError("AI_PROVIDER_NOT_CONFIGURED", "Gemini is not configured.");
    const controller = new AbortController(); const timeout = setTimeout(() => controller.abort(), timeoutFor("ai")); const started = Date.now();
    try {
      const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(request.model)}:generateContent?key=${encodeURIComponent(this.apiKey)}`, {
        method: "POST", signal: controller.signal, headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: request.systemInstruction }] },
          contents: [{ role: "user", parts: [{ text: request.content }] }],
          generationConfig: { temperature: 0.1, maxOutputTokens: request.maxOutputTokens, responseMimeType: "application/json", responseJsonSchema: request.responseSchema },
        }),
      });
      const payload = await response.json().catch(() => null) as GeminiPayload | null;
      if (!response.ok) {
        const code = response.status === 429 ? "AI_PROVIDER_RATE_LIMITED" : response.status === 401 || response.status === 403 ? "AI_PROVIDER_AUTH_FAILED" : "AI_PROVIDER_ERROR";
        throw new AiGatewayError(code, payload?.error?.message ?? "Gemini could not complete the request.", response.status === 429 || response.status >= 500);
      }
      const text = payload?.candidates?.[0]?.content?.parts?.map((part) => part.text ?? "").join("").trim();
      if (!text) throw new AiGatewayError("AI_PROVIDER_EMPTY_RESPONSE", "Gemini returned no usable response.", true);
      if (!payload?.usageMetadata || !Number.isInteger(payload.usageMetadata.promptTokenCount) || !Number.isInteger(payload.usageMetadata.candidatesTokenCount)) throw new AiGatewayError("AI_PROVIDER_USAGE_MISSING", "Gemini did not return token accounting metadata.", true);
      return { provider: this.provider, model: request.model, text, inputTokens: payload.usageMetadata.promptTokenCount!, outputTokens: payload.usageMetadata.candidatesTokenCount!, latencyMs: Date.now() - started };
    } catch (error) {
      if (error instanceof AiGatewayError) throw error;
      if (error instanceof Error && error.name === "AbortError") throw new AiGatewayError("AI_PROVIDER_TIMEOUT", "Gemini timed out.", true);
      throw new AiGatewayError("AI_PROVIDER_UNAVAILABLE", error instanceof Error ? error.message : "Gemini is unavailable.", true);
    } finally { clearTimeout(timeout); }
  }
}
