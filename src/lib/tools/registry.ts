export type ToolDefinition = {
  toolId: string; name: string; version: string; inputSchema: Record<string, unknown>; outputSchema: Record<string, unknown>;
  executionMode: "server" | "ai" | "client"; mime: { input: string[]; output: string[] }; limits: { maxBytes: number; maxFiles: number; maxPages?: number; maxObjects?: number };
  capabilities: string[]; securityClass: "untrusted-document" | "ai" | "client-only"; resourceCost: "low" | "medium" | "high"; aiFlag: boolean; locales: string[];
};
const pdf = ["application/pdf"];
export const toolRegistry: Record<string, ToolDefinition> = {
  "merge-pdf": { toolId: "merge-pdf", name: "Merge PDF", version: "1.0.0", inputSchema: { type: "object", required: ["fileIds"] }, outputSchema: { type: "object", required: ["outputFileId"] }, executionMode: "server", mime: { input: pdf, output: pdf }, limits: { maxBytes: 100 * 1024 * 1024, maxFiles: 20, maxPages: 500, maxObjects: 20 }, capabilities: ["pdf.merge"], securityClass: "untrusted-document", resourceCost: "medium", aiFlag: false, locales: ["ar", "en"] },
  "word-to-pdf": { toolId: "word-to-pdf", name: "Word to PDF", version: "1.0.0", inputSchema: { type: "object" }, outputSchema: { type: "object" }, executionMode: "server", mime: { input: ["application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"], output: pdf }, limits: { maxBytes: 100 * 1024 * 1024, maxFiles: 1 }, capabilities: ["document.convert"], securityClass: "untrusted-document", resourceCost: "high", aiFlag: false, locales: ["ar", "en"] },
};
export function getToolDefinition(toolId: string) { const tool = toolRegistry[toolId]; if (!tool) throw new Error("TOOL_NOT_REGISTERED"); return tool; }
