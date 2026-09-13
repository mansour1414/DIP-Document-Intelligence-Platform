import { AgentError } from "./errors";
import type { AgentPlanDraft, AgentPlanStep, AgentRequest } from "./types";

const ID = /^[A-Za-z][A-Za-z0-9_-]{0,99}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const forbidden = /(user|tenant|owner|role|permission|entitlement|credit|budget|approval|storage|bucket|object.?key|file.?id|file.?path|filesystem|max.?steps|max.?(input|output).?tokens|max.?execution|sql|code|javascript|python|shell|command|subprocess|url|http|network|credential|api.?key|environment|worker|queue|processor|provider)/i;
const object = (value: unknown, path: string): Record<string, unknown> => { if (!value || typeof value !== "object" || Array.isArray(value)) throw new AgentError("AGENT_PLAN_INVALID", "Expected an object.", path); return value as Record<string, unknown>; };
function exact(value: Record<string, unknown>, allowed: readonly string[], path: string) { for (const key of Object.keys(value)) if (!allowed.includes(key)) throw new AgentError(forbidden.test(key) ? "AGENT_FORBIDDEN_FIELD" : "AGENT_PLAN_INVALID", `Unknown field ${key}.`, `${path}.${key}`); }
const text = (value: unknown, path: string, max = 4_000) => { if (typeof value !== "string" || !value.trim() || value.length > max) throw new AgentError("AGENT_PLAN_INVALID", "Expected non-empty text.", path); return value; };
const positive = (value: unknown, path: string) => { if (!Number.isSafeInteger(value) || Number(value) < 1) throw new AgentError("AGENT_PLAN_INVALID", "Expected a positive integer.", path); return Number(value); };

export function parseAgentRequest(value: unknown): AgentRequest {
  const root = object(value, "$"); exact(root, ["request", "locale", "scope"], "$");
  if (root.locale !== "ar" && root.locale !== "en") throw new AgentError("AGENT_PLAN_INVALID", "Locale must be ar or en.", "$.locale");
  const scope = object(root.scope, "$.scope"); exact(scope, ["inputs"], "$.scope"); const inputs = object(scope.inputs, "$.scope.inputs");
  const parsed: Record<string, readonly string[]> = {};
  for (const [name, ids] of Object.entries(inputs)) { if (!ID.test(name) || !Array.isArray(ids) || ids.some((id) => typeof id !== "string" || !UUID.test(id))) throw new AgentError("AGENT_PLAN_INVALID", "Scope inputs must contain explicit File UUIDs.", `$.scope.inputs.${name}`); parsed[name] = Object.freeze([...new Set(ids)]); }
  return Object.freeze({ request: text(root.request, "$.request", 20_000), locale: root.locale, scope: Object.freeze({ inputs: Object.freeze(parsed) }) });
}

function parseStep(value: unknown, index: number): AgentPlanStep {
  const path = `$.steps[${index}]`, step = object(value, path); exact(step, ["stepId", "toolId", "toolVersion", "dependsOn", "inputs", "options", "reason"], path);
  if (!ID.test(String(step.stepId ?? ""))) throw new AgentError("AGENT_PLAN_INVALID", "Invalid stable step ID.", `${path}.stepId`);
  if (!Array.isArray(step.dependsOn) || step.dependsOn.some((id) => typeof id !== "string" || !ID.test(id))) throw new AgentError("AGENT_DEPENDENCY_INVALID", "Dependencies must be stable step IDs.", `${path}.dependsOn`);
  if (!Array.isArray(step.inputs) || !step.inputs.length) throw new AgentError("AGENT_BINDING_INVALID", "At least one explicit input binding is required.", `${path}.inputs`);
  const inputs = step.inputs.map((raw, bindingIndex) => { const bindingPath = `${path}.inputs[${bindingIndex}]`, binding = object(raw, bindingPath); if (binding.source === "request") { exact(binding, ["source", "input"], bindingPath); return Object.freeze({ source: "request" as const, input: text(binding.input, `${bindingPath}.input`, 100) }); } if (binding.source === "step") { exact(binding, ["source", "stepId", "output"], bindingPath); const output = binding.output; if (output !== undefined && (!Number.isSafeInteger(output) || Number(output) < 0)) throw new AgentError("AGENT_BINDING_INVALID", "Output index must be a non-negative integer.", `${bindingPath}.output`); return Object.freeze({ source: "step" as const, stepId: text(binding.stepId, `${bindingPath}.stepId`, 100), ...(output === undefined ? {} : { output: Number(output) }) }); } throw new AgentError("AGENT_BINDING_INVALID", "Only request and declared step outputs are valid bindings.", `${bindingPath}.source`); });
  let options: Readonly<Record<string, string | number | boolean>> | undefined;
  if (step.options !== undefined) { const raw = object(step.options, `${path}.options`); for (const [key, option] of Object.entries(raw)) { if (forbidden.test(key)) throw new AgentError("AGENT_FORBIDDEN_FIELD", `Forbidden option field ${key}.`, `${path}.options.${key}`); if (!["string", "number", "boolean"].includes(typeof option) || (typeof option === "number" && !Number.isFinite(option))) throw new AgentError("AGENT_PLAN_INVALID", "Options must be scalar JSON values.", `${path}.options.${key}`); } options = Object.freeze(raw as Record<string, string | number | boolean>); }
  return Object.freeze({ stepId: String(step.stepId), toolId: text(step.toolId, `${path}.toolId`, 100), toolVersion: text(step.toolVersion, `${path}.toolVersion`, 30), dependsOn: Object.freeze([...step.dependsOn] as string[]), inputs: Object.freeze(inputs), ...(options ? { options } : {}), reason: text(step.reason, `${path}.reason`, 500) });
}

export function parseAgentPlanDraft(value: unknown): AgentPlanDraft {
  const root = object(value, "$"); exact(root, ["schemaVersion", "planId", "version", "steps"], "$");
  if (root.schemaVersion !== 1) throw new AgentError("AGENT_PLAN_INVALID", "schemaVersion must be 1.", "$.schemaVersion");
  if (!Array.isArray(root.steps) || !root.steps.length) throw new AgentError("AGENT_PLAN_INVALID", "At least one step is required.", "$.steps");
  return Object.freeze({ schemaVersion: 1, planId: text(root.planId, "$.planId", 100), version: positive(root.version, "$.version"), steps: Object.freeze(root.steps.map(parseStep)) });
}
