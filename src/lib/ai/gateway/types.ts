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

export type AgentPlannerTask = {
  toolId: "agent-planner";
  locale: AiLocale;
  request: string;
  planId: string;
  planVersion: number;
  inputs: readonly { name: string; files: readonly { mimeType: string; size: number; pageCount?: number }[] }[];
  tools: readonly { toolId: string; version: string; inputMime: readonly string[]; outputMime: readonly string[]; maxFiles: number; resourceCost: string; ai: boolean }[];
  maxSteps: number;
  maxOutputTokens: number;
};

export type GatewayTask = AiTask | AgentPlannerTask;

type AiRequestContextBase = {
  correlationId: string;
  userId: string;
  toolId: AiTool | "agent-planner";
};
export type AiRequestContext = AiRequestContextBase & ({ jobId: string; agentRunId?: never } | { jobId?: never; agentRunId: string });

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
