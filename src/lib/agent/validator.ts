import { effectiveToolLimits, planCanUseTool } from "@/lib/entitlements/policy";
import { toolRegistry } from "@/lib/tools/registry";
import type { AgentPlanDraft, AgentValidationIssue, AgentValidationResult, ResolvedAgentScope, TrustedAgentContext } from "./types";
import { ToolOptionsValidationError, validateToolOptions } from "@/lib/tools/options";

const add = (issues: AgentValidationIssue[], code: string, path: string, message: string) => issues.push({ code, path, message });
export function validateAgentPlan(draft: AgentPlanDraft, scope: ResolvedAgentScope, context: TrustedAgentContext): AgentValidationResult {
  const issues: AgentValidationIssue[] = [], tools: Record<string, (typeof toolRegistry)[string]> = {}, byId = new Map<string, AgentPlanDraft["steps"][number]>();
  draft.steps.forEach((step, index) => { const path = `steps[${index}]`; if (byId.has(step.stepId)) add(issues, "AGENT_DEPENDENCY_INVALID", `${path}.stepId`, `Duplicate step ID ${step.stepId}.`); else byId.set(step.stepId, step);
    const tool = toolRegistry[step.toolId];
    if (!tool) add(issues, "AGENT_TOOL_NOT_REGISTERED", `${path}.toolId`, "Tool is not registered.");
    else { tools[step.stepId] = tool; if (step.toolVersion !== tool.version) add(issues, "AGENT_TOOL_VERSION_UNSUPPORTED", `${path}.toolVersion`, `Expected version ${tool.version}.`); if (!context.allowedToolIds.has(step.toolId)) add(issues, "AGENT_TOOL_NOT_ALLOWED", `${path}.toolId`, "Tool is outside the trusted Agent allowlist."); if (!planCanUseTool(context.entitlements, step.toolId) || (tool.aiFlag && !context.entitlements.aiAccess)) add(issues, "AGENT_ENTITLEMENT_DENIED", `${path}.toolId`, "Server-derived entitlements deny this tool."); if (!tool.locales.includes(context.locale)) add(issues, "AGENT_PLAN_INVALID", `${path}.toolId`, `Tool does not support locale ${context.locale}.`); if (!tool.inputSchema || !tool.outputSchema) add(issues, "AGENT_PLAN_INVALID", `${path}.toolId`, "Tool Registry contracts are incomplete."); try { validateToolOptions(step.toolId, step.options ?? {}); } catch (error) { add(issues, "AGENT_PLAN_INVALID", `${path}.options`, error instanceof ToolOptionsValidationError ? error.message : "Options are invalid."); } }
  });
  const indegree = new Map([...byId.keys()].map((id) => [id, 0])), outgoing = new Map([...byId.keys()].map((id) => [id, [] as string[]]));
  draft.steps.forEach((step, index) => { const path = `steps[${index}]`, declared = new Set(step.dependsOn);
    for (const dependency of declared) { if (dependency === step.stepId) add(issues, "AGENT_DEPENDENCY_INVALID", `${path}.dependsOn`, "A step cannot depend on itself."); else if (!byId.has(dependency)) add(issues, "AGENT_DEPENDENCY_INVALID", `${path}.dependsOn`, `Missing dependency ${dependency}.`); else { indegree.set(step.stepId, (indegree.get(step.stepId) ?? 0) + 1); outgoing.get(dependency)!.push(step.stepId); } }
    let inputCount = 0; const tool = toolRegistry[step.toolId];
    step.inputs.forEach((binding, bindingIndex) => { const bindingPath = `${path}.inputs[${bindingIndex}]`;
      if (binding.source === "request") { const files = scope.inputs[binding.input]; if (!files) add(issues, "AGENT_BINDING_INVALID", bindingPath, `Request input ${binding.input} is undeclared.`); else { inputCount += files.length; if (tool && files.some((file) => !tool.mime.input.includes(file.mimeType))) add(issues, "AGENT_MIME_INCOMPATIBLE", bindingPath, "Scoped input MIME type is incompatible with the tool."); if (tool) { const limits = effectiveToolLimits(tool, context.entitlements); if (files.some((file) => file.size > limits.maxBytes || (file.pageCount ?? 0) > limits.maxPages)) add(issues, "AGENT_ENTITLEMENT_DENIED", bindingPath, "Scoped input exceeds a Tool Registry or plan limit."); } } }
      else { const upstream = byId.get(binding.stepId); if (!upstream) add(issues, "AGENT_BINDING_INVALID", bindingPath, "Upstream step does not exist."); else if (!declared.has(binding.stepId)) add(issues, "AGENT_BINDING_INVALID", bindingPath, "Upstream output requires an explicit dependency."); else { const upstreamTool = toolRegistry[upstream.toolId]; if (binding.output !== undefined && upstreamTool && upstreamTool.limits.maxObjects !== undefined && binding.output >= upstreamTool.limits.maxObjects) add(issues, "AGENT_BINDING_INVALID", `${bindingPath}.output`, "Output index exceeds the deterministic tool limit."); if (tool && upstreamTool && !upstreamTool.mime.output.some((mime) => tool.mime.input.includes(mime))) add(issues, "AGENT_MIME_INCOMPATIBLE", bindingPath, "Known tool output and input MIME types are incompatible."); } }
    });
    if (tool && inputCount) { const fileIds = (tool.inputSchema.properties as Record<string, { minItems?: number }> | undefined)?.fileIds; const minimum = fileIds?.minItems ?? 1; if (inputCount < minimum || inputCount > tool.limits.maxFiles) add(issues, "AGENT_PLAN_INVALID", `${path}.inputs`, "Known request input count is outside the Tool Registry contract."); }
  });
  const ready = [...byId.keys()].filter((id) => indegree.get(id) === 0).sort(), order: string[] = [];
  while (ready.length) { const id = ready.shift()!; order.push(id); for (const next of outgoing.get(id) ?? []) { const degree = (indegree.get(next) ?? 1) - 1; indegree.set(next, degree); if (!degree) { ready.push(next); ready.sort(); } } }
  if (order.length !== byId.size) add(issues, "AGENT_PLAN_CYCLE", "steps", "Agent plan graph contains a cycle.");
  return Object.freeze({ valid: !issues.length, issues: Object.freeze(issues), order: Object.freeze(order), tools: Object.freeze(tools) });
}
