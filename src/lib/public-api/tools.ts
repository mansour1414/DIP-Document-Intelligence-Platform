import type { ApiPrincipal } from "@/lib/api-platform/auth";
import { resolvePlan } from "@/lib/entitlements/service";
import { planCanUseTool } from "@/lib/entitlements/policy";
import { isPublicApiTool, toolRegistry, type ToolDefinition } from "@/lib/tools/registry";
import { PublicApiError } from "./errors";

export function publicToolDto(tool: ToolDefinition) { return { id: tool.toolId, name: tool.name, version: tool.version, executionMode: tool.executionMode, inputSchema: tool.inputSchema, outputSchema: tool.outputSchema, mime: tool.mime, limits: tool.limits, capabilities: tool.capabilities, locales: tool.locales, ai: tool.aiFlag }; }
export async function listPublicTools(principal: ApiPrincipal) { const plan = await resolvePlan(principal.executionUserId); return Object.values(toolRegistry).filter((tool) => isPublicApiTool(tool) && planCanUseTool(plan.entitlements, tool.toolId)).map(publicToolDto); }
export async function getPublicTool(principal: ApiPrincipal, toolId: string) { const tool = toolRegistry[toolId]; const plan = await resolvePlan(principal.executionUserId); if (!tool || !isPublicApiTool(tool) || !planCanUseTool(plan.entitlements, toolId)) throw new PublicApiError("NOT_FOUND", "The requested tool was not found.", 404); return publicToolDto(tool); }
