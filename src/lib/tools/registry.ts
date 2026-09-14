import { toolsConfig } from "@/config";

export type ToolDefinition = {
  toolId: string; name: string; version: string; inputSchema: Record<string, unknown>; outputSchema: Record<string, unknown>;
  executionMode: "server" | "ai" | "client"; mime: { input: string[]; output: string[] }; limits: { maxBytes: number; maxFiles: number; maxPages?: number; maxObjects?: number };
  capabilities: string[]; securityClass: "standard" | "restricted" | "isolated"; resourceCost: "low" | "medium" | "high"; aiFlag: boolean; locales: string[];
  enabled: boolean; apiEligible: boolean;
};
function outputMime(toolId: string) {
  if (toolId === "pdf-to-word") return ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"];
  if (toolId === "pdf-to-jpg") return ["image/jpeg", "application/zip"];
  if (["summarize-pdf", "chat-with-pdf", "extract-data"].includes(toolId)) return ["application/json"];
  return ["application/pdf"];
}
function inputSchema(toolId: string, maxFiles: number) {
  const ai = ["summarize-pdf", "chat-with-pdf", "extract-data"].includes(toolId);
  return { type: "object", required: ["fileIds"], properties: { fileIds: { type: "array", minItems: toolId === "merge-pdf" ? 2 : 1, maxItems: ai ? 1 : maxFiles }, options: { type: "object", properties: ai ? { locale: { enum: ["en", "ar"] }, question: { type: "string", maxLength: 4000 }, documentId: { type: "string", format: "uuid" } } : {} } } };
}
function outputSchema(toolId: string) {
  if (["summarize-pdf", "chat-with-pdf"].includes(toolId)) return { type: "object", required: ["answer", "citations"], properties: { answer: { type: "string" }, citations: { type: "array" } } };
  if (toolId === "extract-data") return { type: "object", required: ["summary", "entities", "dates", "amounts", "contacts", "actionItems", "citations"], properties: { summary: { type: "string" }, entities: { type: "array" }, dates: { type: "array" }, amounts: { type: "array" }, contacts: { type: "array" }, actionItems: { type: "array" }, citations: { type: "array" } } };
  return { type: "object", required: ["outputFileIds"], properties: { outputFileIds: { type: "array" } } };
}

/** The existing UI catalog remains the single source of truth. */
export const toolRegistry = Object.fromEntries(toolsConfig.map((tool) => [tool.id, {
  toolId: tool.id, name: tool.name, version: String(tool.version),
  inputSchema: inputSchema(tool.id, tool.limits.maxFiles),
  outputSchema: outputSchema(tool.id),
  executionMode: tool.execution, mime: { input: [...tool.supportedMimeTypes], output: outputMime(tool.id) }, limits: { ...tool.limits, maxObjects: tool.limits.maxFiles },
  capabilities: [...tool.capabilities], securityClass: tool.securityClass, resourceCost: tool.aiEnabled || tool.securityClass === "isolated" ? "high" : tool.capabilities.length ? "medium" : "low",
  aiFlag: tool.aiEnabled, locales: [...tool.locales], enabled: true, apiEligible: tool.execution !== "client",
}])) as Record<string, ToolDefinition>;

/** Tools enabled on the unified runtime workers. */
export const workerToolIds = new Set([
  "merge-pdf", "split-pdf", "organize-pdf", "rotate-pdf", "delete-pages", "extract-pages", "jpg-to-pdf",
  "compress-pdf", "pdf-to-jpg", "watermark-pdf",
  "word-to-pdf", "pdf-to-word", "excel-to-pdf", "powerpoint-to-pdf", "ocr-pdf",
  "summarize-pdf", "chat-with-pdf", "extract-data",
]);

export function getToolDefinition(toolId: string) { const tool = toolRegistry[toolId]; if (!tool) throw new Error("TOOL_NOT_REGISTERED"); return tool; }
export function isPublicApiTool(tool: ToolDefinition) { return tool.enabled && tool.apiEligible && workerToolIds.has(tool.toolId); }
