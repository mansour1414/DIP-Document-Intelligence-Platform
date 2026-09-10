import test from "node:test";
import assert from "node:assert/strict";
import { MAX_WORKFLOW_NODES, validateWorkflowDefinition } from "../src/lib/workflows/validator";
import { workflowTemplates } from "../src/lib/workflows/templates";

const valid = { schemaVersion: 1, nodes: [
  { id: "merge", toolId: "merge-pdf", toolVersion: "1", dependsOn: [], inputs: [{ source: "workflow", input: "documents" }] },
  { id: "compress", toolId: "compress-pdf", toolVersion: "1", dependsOn: ["merge"], inputs: [{ source: "node", nodeId: "merge", output: 0 }] },
] };

test("workflow validator produces a deterministic DAG order", () => { const result = validateWorkflowDefinition(valid); assert.equal(result.valid, true); assert.deepEqual(result.order, ["merge", "compress"]); });
test("workflow validator rejects cycles", () => { const definition = structuredClone(valid); definition.nodes[0].dependsOn = ["compress"]; definition.nodes[0].inputs = [{ source: "node", nodeId: "compress", output: 0 }]; const result = validateWorkflowDefinition(definition); assert.equal(result.valid, false); assert.ok(result.issues.some((item) => item.code === "WORKFLOW_CYCLE")); });
test("workflow validator rejects missing dependencies and duplicate IDs", () => { const definition = structuredClone(valid); definition.nodes[1].id = "merge"; definition.nodes[1].dependsOn = ["missing"]; const codes = validateWorkflowDefinition(definition).issues.map((item) => item.code); assert.ok(codes.includes("WORKFLOW_NODE_DUPLICATE")); assert.ok(codes.includes("WORKFLOW_DEPENDENCY_MISSING")); });
test("workflow validator rejects invalid tools, versions, MIME chains and node excess", () => { const invalidTool = structuredClone(valid); invalidTool.nodes[0].toolId = "shell"; assert.ok(validateWorkflowDefinition(invalidTool).issues.some((item) => item.code === "TOOL_NOT_REGISTERED")); const invalidVersion = structuredClone(valid); invalidVersion.nodes[0].toolVersion = "99"; assert.ok(validateWorkflowDefinition(invalidVersion).issues.some((item) => item.code === "TOOL_VERSION_UNSUPPORTED")); const invalidMime = structuredClone(valid); invalidMime.nodes[1].toolId = "word-to-pdf"; assert.ok(validateWorkflowDefinition(invalidMime).issues.some((item) => item.code === "WORKFLOW_MIME_INCOMPATIBLE")); const excessive = { schemaVersion: 1, nodes: Array.from({ length: MAX_WORKFLOW_NODES + 1 }, (_, index) => ({ id: `n${index}`, toolId: "compress-pdf", toolVersion: "1", dependsOn: [], inputs: [{ source: "workflow", input: "documents" }] })) }; assert.ok(validateWorkflowDefinition(excessive).issues.some((item) => item.code === "WORKFLOW_NODE_LIMIT_EXCEEDED")); });
test("all four system templates validate against registered tool contracts", () => { assert.equal(workflowTemplates.length, 4); for (const template of workflowTemplates) assert.equal(validateWorkflowDefinition(template.definition).valid, true, template.id); });
