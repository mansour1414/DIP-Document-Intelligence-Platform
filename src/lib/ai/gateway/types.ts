export const AI_TOOL_IDS = ["summarize-pdf", "chat-with-pdf", "extract-data"] as const;
export type AiTool = typeof AI_TOOL_IDS[number];
export type AiLocale = "en" | "ar";

export type Citation = { page: number; quote?: string };
export type AiValidatedOutput = {
  answer?: string;
  summary?: string;
  entities?: string[];
  dates?: string[];
  amounts?: string[];
  contacts?: string[];
  actionItems?: string[];
  citations: Citation[];
};

export type AiTask = {
  toolId: AiTool;
  locale: AiLocale;
  documentId: string;
  documentText: string;
  pageCount: number;
  question?: string;
};

export type AiRequestContext = {
  jobId: string;
  correlationId: string;
  userId: string;
  toolId: AiTool;
};

export type ProviderRequest = {
  model: string;
  systemInstruction: string;
  content: string;
  responseSchema: Record<string, unknown>;
  maxOutputTokens: number;
};

export type ProviderResponse = {
  provider: string;
  model: string;
  text: string;
  inputTokens: number;
  outputTokens: number;
  latencyMs: number;
};

export interface AiProviderAdapter {
  readonly provider: string;
  readonly version: string;
  generate(request: ProviderRequest): Promise<ProviderResponse>;
}

export class AiGatewayError extends Error {
  constructor(public readonly code: string, message: string, public readonly retryable = false) {
    super(message);
    this.name = "AiGatewayError";
  }
}
