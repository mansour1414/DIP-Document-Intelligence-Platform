import { randomUUID } from "crypto";
import type { Prisma } from "@prisma/client";
import { withTenant } from "@/lib/db/tenant";
import { resolvePlan } from "@/lib/entitlements/service";
import { createToolJobFromFiles } from "@/lib/jobs/orchestrator";
import { logger } from "@/lib/logging";
import { recordMetric } from "@/lib/observability/metrics";
import type { WorkflowDefinition, WorkflowNode } from "./types";
import { assertValidWorkflow, validateWorkflowDefinition } from "./validator";

const json = <T>(value: Prisma.JsonValue) => value as unknown as T;
const terminal = new Set(["SUCCEEDED", "FAILED", "CANCELLED", "EXPIRED"]);

export async function listWorkflows(userId: string) { return withTenant({ userId }, (tx) => tx.workflow.findMany({ where: { ownerId: userId, status: "ACTIVE" }, include: { currentVersion: true }, orderBy: { updatedAt: "desc" } })); }
export async function getWorkflow(userId: string, id: string) { return withTenant({ userId }, (tx) => tx.workflow.findFirst({ where: { id, ownerId: userId }, include: { currentVersion: true, versions: { orderBy: { version: "desc" } } } })); }
export async function createWorkflow(userId: string, input: { name: string; definition: unknown }) {
  if (!input.name?.trim() || input.name.trim().length > 120) throw Object.assign(new Error("WORKFLOW_NAME_INVALID"), { code: "WORKFLOW_NAME_INVALID" });
  const plan = await resolvePlan(userId); assertValidWorkflow(input.definition, plan.entitlements);
  return withTenant({ userId }, async (tx) => { const workflow = await tx.workflow.create({ data: { ownerId: userId, name: input.name.trim() } }); const version = await tx.workflowVersion.create({ data: { workflowId: workflow.id, version: 1, definition: input.definition as Prisma.InputJsonValue } }); return tx.workflow.update({ where: { id: workflow.id }, data: { currentVersionId: version.id }, include: { currentVersion: true } }); });
}
export async function updateWorkflow(userId: string, id: string, input: { name?: string; definition: unknown }) {
  const plan = await resolvePlan(userId); assertValidWorkflow(input.definition, plan.entitlements);
  return withTenant({ userId }, async (tx) => { const workflow = await tx.workflow.findFirst({ where: { id, ownerId: userId, status: "ACTIVE" }, include: { currentVersion: true } }); if (!workflow) throw Object.assign(new Error("NOT_FOUND"), { code: "NOT_FOUND" }); const version = await tx.workflowVersion.create({ data: { workflowId: id, version: (workflow.currentVersion?.version ?? 0) + 1, definition: input.definition as Prisma.InputJsonValue } }); return tx.workflow.update({ where: { id }, data: { currentVersionId: version.id, ...(input.name?.trim() ? { name: input.name.trim().slice(0, 120) } : {}) }, include: { currentVersion: true } }); });
}
export async function archiveWorkflow(userId: string, id: string) { return withTenant({ userId }, async (tx) => { const result = await tx.workflow.updateMany({ where: { id, ownerId: userId }, data: { status: "ARCHIVED" } }); if (!result.count) throw Object.assign(new Error("NOT_FOUND"), { code: "NOT_FOUND" }); }); }
export async function validateForUser(userId: string, definition: unknown) { const plan = await resolvePlan(userId); return validateWorkflowDefinition(definition, plan.entitlements); }

export async function startWorkflowRun(userId: string, workflowId: string, inputs: Record<string, string[]>, correlationId: string = randomUUID()) {
  const workflow = await withTenant({ userId }, (tx) => tx.workflow.findFirst({ where: { id: workflowId, ownerId: userId, status: "ACTIVE" }, include: { currentVersion: true } }));
  if (!workflow?.currentVersion) throw Object.assign(new Error("NOT_FOUND"), { code: "NOT_FOUND" });
  const plan = await resolvePlan(userId); assertValidWorkflow(workflow.currentVersion.definition, plan.entitlements);
  const ids = [...new Set(Object.values(inputs).flat())];
  const owned = await withTenant({ userId }, (tx) => tx.file.count({ where: { id: { in: ids }, document: { userId } } }));
  if (!ids.length || owned !== ids.length) throw Object.assign(new Error("WORKFLOW_ARTIFACT_UNAUTHORIZED"), { code: "WORKFLOW_ARTIFACT_UNAUTHORIZED" });
  const run = await withTenant({ userId }, (tx) => tx.workflowRun.create({ data: { ownerId: userId, workflowVersionId: workflow.currentVersion!.id, status: "QUEUED", inputs, correlationId } }));
  recordMetric("workflow_runs_total", 1, "count", { status: "queued" }); await advanceWorkflowRun(run.id, userId); return run;
}

function outputs(job: { result: Prisma.JsonValue | null }) { const result = job.result as { outputFileIds?: unknown } | null; return Array.isArray(result?.outputFileIds) ? result.outputFileIds.filter((id): id is string => typeof id === "string") : []; }
function resolveInputs(node: WorkflowNode, runInputs: Record<string, string[]>, jobs: Array<{ workflowNodeId: string | null; result: Prisma.JsonValue | null }>) {
  const byNode = new Map(jobs.map((job) => [job.workflowNodeId, outputs(job)])); const ids: string[] = [];
  for (const binding of node.inputs) if (binding.source === "workflow") ids.push(...(runInputs[binding.input] ?? [])); else { const values = byNode.get(binding.nodeId) ?? []; if (binding.output === undefined) ids.push(...values); else if (values[binding.output]) ids.push(values[binding.output]); }
  return ids;
}

export async function advanceWorkflowRun(runId: string, userId: string) {
  const run = await withTenant({ userId }, (tx) => tx.workflowRun.findFirst({ where: { id: runId, ownerId: userId }, include: { workflowVersion: true, jobs: true } })); if (!run || terminal.has(run.status)) return;
  const definition = json<WorkflowDefinition>(run.workflowVersion.definition); assertValidWorkflow(definition);
  const byNode = new Map(run.jobs.map((job) => [job.workflowNodeId, job]));
  const failed = run.jobs.find((job) => ["FAILED", "EXPIRED"].includes(job.status));
  if (failed) { await withTenant({ userId }, (tx) => tx.workflowRun.update({ where: { id: run.id }, data: { status: "FAILED", errorCode: failed.errorCode ?? "WORKFLOW_NODE_FAILED", error: { nodeId: failed.workflowNodeId, jobId: failed.id }, completedAt: new Date() } })); recordMetric("workflow_failure_total", 1, "count", { failed_node: failed.workflowNodeId ?? "unknown" }); return; }
  if (run.status === "CANCELLED") return;
  if (run.jobs.length === definition.nodes.length && run.jobs.every((job) => job.status === "SUCCEEDED")) { const result = Object.fromEntries(run.jobs.map((job) => [job.workflowNodeId!, outputs(job)])); await withTenant({ userId }, (tx) => tx.workflowRun.update({ where: { id: run.id }, data: { status: "SUCCEEDED", result, completedAt: new Date() } })); recordMetric("workflow_success_total", 1, "count"); return; }
  if (run.jobs.some((job) => ["QUEUED", "RUNNING", "RETRYING"].includes(job.status))) return;
  const next = definition.nodes.find((node) => !byNode.has(node.id) && node.dependsOn.every((id) => byNode.get(id)?.status === "SUCCEEDED"));
  if (!next) { await withTenant({ userId }, (tx) => tx.workflowRun.update({ where: { id: run.id }, data: { status: "FAILED", errorCode: "WORKFLOW_STALLED", error: { message: "No runnable node remains." }, completedAt: new Date() } })); return; }
  const fileIds = resolveInputs(next, json<Record<string, string[]>>(run.inputs), run.jobs); if (!fileIds.length) { await withTenant({ userId }, (tx) => tx.workflowRun.update({ where: { id: run.id }, data: { status: "FAILED", errorCode: "WORKFLOW_BINDING_EMPTY", error: { nodeId: next.id }, completedAt: new Date() } })); return; }
  await withTenant({ userId }, (tx) => tx.workflowRun.update({ where: { id: run.id }, data: { status: "RUNNING", startedAt: run.startedAt ?? new Date() } }));
  await createToolJobFromFiles({ userId: run.ownerId, toolId: next.toolId, fileIds, options: next.options, idempotencyKey: `workflow:${run.id}:${next.id}`, correlationId: run.correlationId, workflowRunId: run.id, workflowNodeId: next.id });
}

export async function getWorkflowRun(userId: string, id: string) { return withTenant({ userId }, (tx) => tx.workflowRun.findFirst({ where: { id, ownerId: userId }, include: { workflowVersion: { include: { workflow: { select: { id: true, name: true } } } }, jobs: { include: { steps: true }, orderBy: { createdAt: "asc" } } } })); }
export async function cancelWorkflowRun(userId: string, id: string) { return withTenant({ userId }, async (tx) => { const run = await tx.workflowRun.findFirst({ where: { id, ownerId: userId } }); if (!run) throw Object.assign(new Error("NOT_FOUND"), { code: "NOT_FOUND" }); if (terminal.has(run.status)) return run; await tx.job.updateMany({ where: { workflowRunId: id, status: { in: ["QUEUED", "RETRYING"] } }, data: { status: "CANCELLED", completedAt: new Date(), errorCode: "WORKFLOW_CANCELLED" } }); const cancelled = await tx.workflowRun.update({ where: { id }, data: { status: "CANCELLED", cancelledAt: new Date(), completedAt: new Date(), errorCode: "WORKFLOW_CANCELLED" } }); logger.info("workflow.cancelled", { workflow_run_id: id, correlation_id: run.correlationId }); recordMetric("workflow_cancellations_total", 1, "count"); return cancelled; }); }
