import { planCanUseTool, type Entitlements } from "@/lib/entitlements/policy";
import { toolRegistry, workerToolIds } from "@/lib/tools/registry";
import type { WorkflowDefinition, WorkflowNode, WorkflowValidationIssue, WorkflowValidationResult } from "./types";
import { ToolOptionsValidationError, validateToolOptions } from "@/lib/tools/options";

export const MAX_WORKFLOW_NODES = 20;
const NODE_ID = /^[a-zA-Z][a-zA-Z0-9_-]{0,99}$/;
const secretTools = new Set(["protect-pdf", "unlock-pdf", "pdf-permissions"]);

function issue(issues: WorkflowValidationIssue[], code: string, path: string, message: string) { issues.push({ code, path, message }); }
function isNode(value: unknown): value is WorkflowNode { return Boolean(value && typeof value === "object" && !Array.isArray(value)); }

export function validateWorkflowDefinition(value: unknown, entitlements?: Entitlements): WorkflowValidationResult {
  const issues: WorkflowValidationIssue[] = [];
  if (!value || typeof value !== "object" || Array.isArray(value)) return { valid: false, issues: [{ code: "WORKFLOW_SCHEMA_INVALID", path: "$", message: "Definition must be an object." }], order: [] };
  const definition = value as Partial<WorkflowDefinition>;
  if (definition.schemaVersion !== 1) issue(issues, "WORKFLOW_SCHEMA_VERSION_UNSUPPORTED", "schemaVersion", "schemaVersion must be 1.");
  if (!Array.isArray(definition.nodes) || definition.nodes.length === 0) return { valid: false, issues: [...issues, { code: "WORKFLOW_NODES_REQUIRED", path: "nodes", message: "At least one node is required." }], order: [] };
  if (definition.nodes.length > MAX_WORKFLOW_NODES) issue(issues, "WORKFLOW_NODE_LIMIT_EXCEEDED", "nodes", `No more than ${MAX_WORKFLOW_NODES} nodes are allowed.`);
  const nodes = definition.nodes.filter(isNode); const byId = new Map<string, WorkflowNode>();
  nodes.forEach((node, index) => {
    const path = `nodes[${index}]`;
    if (!NODE_ID.test(node.id ?? "")) issue(issues, "WORKFLOW_NODE_ID_INVALID", `${path}.id`, "Node IDs must be explicit safe identifiers.");
    else if (byId.has(node.id)) issue(issues, "WORKFLOW_NODE_DUPLICATE", `${path}.id`, `Duplicate node ID ${node.id}.`); else byId.set(node.id, node);
    const tool = toolRegistry[node.toolId];
    if (!tool) issue(issues, "TOOL_NOT_REGISTERED", `${path}.toolId`, "Referenced tool is not registered.");
    else {
      if (!workerToolIds.has(node.toolId)) issue(issues, "TOOL_DISABLED", `${path}.toolId`, "Referenced tool is disabled for workflow execution.");
      if (secretTools.has(node.toolId)) issue(issues, "WORKFLOW_SECRET_INPUT_UNSUPPORTED", `${path}.toolId`, "Secret-bearing tools require interactive ephemeral input and cannot be persisted in workflows.");
      if (node.toolVersion !== tool.version) issue(issues, "TOOL_VERSION_UNSUPPORTED", `${path}.toolVersion`, `Expected tool version ${tool.version}.`);
      if (entitlements && !planCanUseTool(entitlements, node.toolId)) issue(issues, "PLAN_LIMIT_EXCEEDED", `${path}.toolId`, "The active plan cannot use this tool.");
    }
    if (!Array.isArray(node.dependsOn)) issue(issues, "WORKFLOW_DEPENDENCIES_INVALID", `${path}.dependsOn`, "Dependencies must be an array.");
    if (!Array.isArray(node.inputs) || node.inputs.length === 0) issue(issues, "WORKFLOW_INPUT_BINDING_REQUIRED", `${path}.inputs`, "At least one explicit input binding is required.");
    else node.inputs.forEach((binding, bindingIndex) => {
      const bindingPath = `${path}.inputs[${bindingIndex}]`;
      if (!binding || typeof binding !== "object") issue(issues, "WORKFLOW_BINDING_INVALID", bindingPath, "Binding must be an object.");
      else if (binding.source === "workflow") { if (!binding.input || typeof binding.input !== "string") issue(issues, "WORKFLOW_INPUT_INVALID", bindingPath, "Workflow input name is required."); }
      else if (binding.source === "node") { if (!binding.nodeId || typeof binding.nodeId !== "string") issue(issues, "WORKFLOW_ARTIFACT_REFERENCE_INVALID", bindingPath, "Upstream node ID is required."); }
      else issue(issues, "WORKFLOW_BINDING_SOURCE_INVALID", bindingPath, "Only workflow and node artifact sources are supported.");
    });
    if (node.options !== undefined && (!node.options || typeof node.options !== "object" || Array.isArray(node.options))) issue(issues, "WORKFLOW_PARAMETERS_INVALID", `${path}.options`, "Options must be an object.");
    else if (tool) { try { validateToolOptions(node.toolId, node.options ?? {}); } catch (error) { const message = error instanceof ToolOptionsValidationError ? error.message : "Options are invalid."; issue(issues, "WORKFLOW_PARAMETERS_INVALID", `${path}.options`, message); } }
  });
  const indegree = new Map(nodes.map((node) => [node.id, 0])); const outgoing = new Map(nodes.map((node) => [node.id, [] as string[]]));
  nodes.forEach((node, index) => {
    const dependencies = new Set(node.dependsOn ?? []);
    node.inputs?.filter((binding) => binding.source === "node").forEach((binding) => dependencies.add(binding.nodeId));
    dependencies.forEach((dependency) => {
      if (dependency === node.id) issue(issues, "WORKFLOW_CYCLE", `nodes[${index}].dependsOn`, "A node cannot depend on itself.");
      else if (!byId.has(dependency)) issue(issues, "WORKFLOW_DEPENDENCY_MISSING", `nodes[${index}].dependsOn`, `Missing dependency ${dependency}.`);
      else { indegree.set(node.id, (indegree.get(node.id) ?? 0) + 1); outgoing.get(dependency)!.push(node.id); }
    });
    const tool = toolRegistry[node.toolId];
    node.inputs?.filter((binding) => binding.source === "node").forEach((binding) => {
      const upstream = byId.get(binding.nodeId); const upstreamTool = upstream && toolRegistry[upstream.toolId];
      if (tool && upstreamTool && !upstreamTool.mime.output.some((mime) => tool.mime.input.includes(mime))) issue(issues, "WORKFLOW_MIME_INCOMPATIBLE", `nodes[${index}].inputs`, `${upstream.toolId} output is incompatible with ${node.toolId}.`);
    });
  });
  const ready = [...nodes.filter((node) => indegree.get(node.id) === 0).map((node) => node.id)].sort(); const order: string[] = [];
  while (ready.length) { const id = ready.shift()!; order.push(id); for (const next of outgoing.get(id) ?? []) { const degree = (indegree.get(next) ?? 1) - 1; indegree.set(next, degree); if (degree === 0) { ready.push(next); ready.sort(); } } }
  if (order.length !== nodes.length && !issues.some((item) => item.code === "WORKFLOW_CYCLE")) issue(issues, "WORKFLOW_CYCLE", "nodes", "Workflow graph contains a cycle.");
  return { valid: issues.length === 0, issues, order };
}

export function assertValidWorkflow(value: unknown, entitlements?: Entitlements): asserts value is WorkflowDefinition {
  const result = validateWorkflowDefinition(value, entitlements); if (!result.valid) throw Object.assign(new Error("WORKFLOW_INVALID"), { code: "WORKFLOW_INVALID", issues: result.issues });
}
