import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { buildProviderRequest } from "../src/lib/ai/gateway/task";
import { compileFrozenAgentPlan } from "../src/lib/agent/runtime";
import { buildValidatedAgentPlan, freezeAgentPlan, parseAgentPlanDraft } from "../src/lib/agent";
import { PLAN_POLICIES } from "../src/lib/entitlements/policy";

const root = new URL("../", import.meta.url);
const file = (path: string) => readFile(new URL(path, root), "utf8");

test("planner request is bounded, structured, and contains no executable authority", () => {
  const request = buildProviderRequest({
    toolId: "agent-planner",
    locale: "en",
    request: "Compress my selected document.",
    planId: "plan-1",
    planVersion: 1,
    maxSteps: 3,
    maxOutputTokens: 321,
    inputs: [{ name: "documents", files: [{ mimeType: "application/pdf", size: 100, pageCount: 1 }] }],
    tools: [{ toolId: "compress-pdf", version: "1", inputMime: ["application/pdf"], outputMime: ["application/pdf"], maxFiles: 20, resourceCost: "LOW", ai: false }],
  }, "fake-model");
  assert.equal(request.maxOutputTokens, 321);
  assert.equal(request.responseSchema.additionalProperties, false);
  assert.match(request.systemInstruction, /non-executing workflow planner/);
  assert.doesNotMatch(request.content, /storageKey|bucket|userId|tenantId/);
});

test("frozen plans compile deterministically to the existing workflow definition", () => {
  const draft = parseAgentPlanDraft({ schemaVersion: 1, planId: "plan-1", version: 1, steps: [
    { stepId: "compress", toolId: "compress-pdf", toolVersion: "1", dependsOn: [], inputs: [{ source: "request", input: "documents" }], reason: "Reduce size." },
  ] });
  const frozen = freezeAgentPlan(buildValidatedAgentPlan(draft, {
    inputs: { documents: [{ id: "11111111-1111-4111-8111-111111111111", mimeType: "application/pdf", size: 100, pageCount: 1 }] },
    fileIds: ["11111111-1111-4111-8111-111111111111"],
  }, {
    userId: "user-1", correlationId: "correlation-1", locale: "en", allowedToolIds: new Set(["compress-pdf"]), entitlements: PLAN_POLICIES.PRO,
    budget: { maxSteps: 3, maxInputTokens: 1000, maxOutputTokens: 500, maxCredits: 10, maxExecutionMs: 60_000 }, approvalPolicyVersion: "v1", policyVersion: "v1",
  }, () => ({ requiredStepIds: [] })));
  assert.deepEqual(compileFrozenAgentPlan(frozen), { schemaVersion: 1, nodes: [{ id: "compress", toolId: "compress-pdf", toolVersion: "1", dependsOn: [], inputs: [{ source: "workflow", input: "documents" }] }] });
});

test("Phase 8 migration has origin, lifecycle constraints, indexes, grants, and forced RLS", async () => {
  const migration = await file("prisma/migrations/20260913120000_phase8_document_agent/migration.sql");
  for (const expected of ["AGENT_INTERNAL", "agent_runs", "agent_plan_versions", "ENABLE ROW LEVEL SECURITY", "FORCE ROW LEVEL SECURITY", "agent_runs_tenant_policy", "agent_plan_versions_tenant_policy", "integrity_hash", "GRANT SELECT,INSERT,UPDATE,DELETE"])
    assert.match(migration, new RegExp(expected));
  assert.match(migration, /CREATE (?:UNIQUE )?INDEX/);
});

test("Agent audit migration grants INSERT only and enforces the tenant boundary", async () => {
  const migration = await file("prisma/migrations/20260913130000_phase8_agent_audit_permissions/migration.sql");
  assert.match(migration, /ALTER TABLE "audit_logs" ENABLE ROW LEVEL SECURITY/);
  assert.match(migration, /ALTER TABLE "audit_logs" FORCE ROW LEVEL SECURITY/);
  assert.match(migration, /CREATE POLICY audit_logs_tenant_insert_policy ON "audit_logs"\s+FOR INSERT\s+WITH CHECK \(\s*"user_id" = NULLIF\(current_setting\('app\.current_user_id', true\), ''\)::uuid\s*\)/);
  assert.match(migration, /GRANT INSERT ON "audit_logs" TO dip_app/);
  assert.doesNotMatch(migration, /GRANT (?:ALL|SELECT|UPDATE|DELETE)[^;]*"audit_logs"/);
});

test("first-party APIs authenticate and bind identity server-side", async () => {
  const sources = await Promise.all([
    file("src/app/api/agent-runs/route.ts"),
    file("src/app/api/agent-runs/[runId]/route.ts"),
    file("src/app/api/agent-runs/[runId]/approval/route.ts"),
    file("src/app/api/agent-runs/[runId]/cancel/route.ts"),
  ]);
  for (const source of sources) assert.match(source, /requireUser\(\)/);
  assert.ok(sources.every((source) => !/body\.(?:userId|ownerId|tenantId|budget)/.test(source)));
});

test("Agent UI is bilingual, RTL-aware, and uses only first-party Agent APIs", async () => {
  const source = await file("src/components/agent/agent-workspace.tsx");
  assert.match(source, /dir=\{ar \? "rtl" : "ltr"\}/);
  assert.match(source, /\/api\/agent-runs/);
  assert.match(source, /الموافقة|موافقة/);
  assert.match(source, /Approve/);
  assert.doesNotMatch(source, /gemini|openai\.com|anthropic|workers?\//i);
});

test("Agent runtime delegates execution only through the Workflow service", async () => {
  const source = await file("src/lib/agent/runtime.ts");
  assert.match(source, /startWorkflowRun/);
  assert.match(source, /cancelWorkflowRun/);
  assert.doesNotMatch(source, /documentWorker|aiWorker|processDocument|enqueueJob|provider\.generate/);
  assert.match(source, /\$executeRaw`\s*INSERT INTO audit_logs/);
  assert.doesNotMatch(source, /auditLog\.create/);
});
