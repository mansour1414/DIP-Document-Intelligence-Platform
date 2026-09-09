import { toolsConfig } from "@/config";

export type ToolDefinition = {
  toolId: string; name: string; version: string; inputSchema: Record<string, unknown>; outputSchema: Record<string, unknown>;
  executionMode: "server" | "ai" | "client"; mime: { input: string[]; output: string[] }; limits: { maxBytes: number; maxFiles: number; maxPages?: number; maxObjects?: number };
  capabilities: string[]; securityClass: "standard" | "restricted" | "isolated"; resourceCost: "low" | "medium" | "high"; aiFlag: boolean; locales: string[];
};
function outputMime(toolId: string) {
  if (toolId === "pdf-to-word") return ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"];
  if (toolId === "pdf-to-jpg") return ["image/jpeg", "application/zip"];
  if (["summarize-pdf", "chat-with-pdf", "extract-data"].includes(toolId)) return ["application/json"];
  return ["application/pdf"];
}

/** The existing UI catalog remains the single source of truth. */
export const toolRegistry = Object.fromEntries(toolsConfig.map((tool) => [tool.id, {
  toolId: tool.id, name: tool.name, version: String(tool.version),
  inputSchema: { type: "object", required: ["fileIds"], properties: { fileIds: { type: "array", minItems: tool.id === "merge-pdf" ? 2 : 1, maxItems: tool.limits.maxFiles }, options: { type: "object" } } },
  outputSchema: { type: "object", required: ["outputFileIds"], properties: { outputFileIds: { type: "array" } } },
  executionMode: tool.execution, mime: { input: [...tool.supportedMimeTypes], output: outputMime(tool.id) }, limits: { ...tool.limits, maxObjects: tool.limits.maxFiles },
  capabilities: [...tool.capabilities], securityClass: tool.securityClass, resourceCost: tool.aiEnabled || tool.securityClass === "isolated" ? "high" : tool.capabilities.length ? "medium" : "low",
  aiFlag: tool.aiEnabled, locales: [...tool.locales],
}])) as Record<string, ToolDefinition>;

/** First migration batch; remaining browser-render and AI tools stay on their existing engines. */
export const workerToolIds = new Set([
  "merge-pdf", "split-pdf", "organize-pdf", "rotate-pdf", "delete-pages", "extract-pages", "jpg-to-pdf",
  "word-to-pdf", "pdf-to-word", "excel-to-pdf", "powerpoint-to-pdf", "ocr-pdf",
]);

export function getToolDefinition(toolId: string) { const tool = toolRegistry[toolId]; if (!tool) throw new Error("TOOL_NOT_REGISTERED"); return tool; }
