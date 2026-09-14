import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import test from "node:test";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "@prisma/client";
import { PDFDocument } from "pdf-lib";
import type { AgentPlannerTask } from "../src/lib/ai/gateway";

const integration = process.env.RUN_WORKFLOW_E2E === "1" ? test : test.skip;

integration("Phase 7 executes a real multi-step workflow with retry, failure, cancellation and idempotency", { timeout: 120_000 }, async () => {
  const owner = new PrismaClient({ adapter: new PrismaPg({ connectionString: process.env.DIP_RLS_TEST_OWNER_URL! }) });
  const { db } = await import("../src/lib/db/index");
  const { withTenant } = await import("../src/lib/db/tenant");
  const { createWorkflow, updateWorkflow, startWorkflowRun, getWorkflowRun, cancelWorkflowRun } = await import("../src/lib/workflows/service");
  const { createAgentRun, getAgentRun, cancelAgentRun } = await import("../src/lib/agent/runtime");
  const { getStorage, closeStorage } = await import("../src/lib/storage/index");
  const { getJobQueue, enqueueJob, closeQueueResources } = await import("../src/lib/queue/index");
  const { getToolDefinition } = await import("../src/lib/tools/registry");
  const { documentWorker, aiWorker } = await import("../workers/document-worker");
  const storage = getStorage();
  const userId = randomUUID();
  const objectKeys = new Set<string>();
  const definition = { schemaVersion: 1 as const, nodes: [
    { id: "merge", toolId: "merge-pdf", toolVersion: "1", dependsOn: [] as string[], inputs: [{ source: "workflow" as const, input: "documents" }] },
    { id: "compress", toolId: "compress-pdf", toolVersion: "1", dependsOn: ["merge"], inputs: [{ source: "node" as const, nodeId: "merge", output: 0 }] },
  ] };

  const pdf = async (label: string) => { const document = await PDFDocument.create(); document.addPage().drawText(label); return document.save(); };
  const createInputs = async (prefix: string, store = true) => {
    const document = await owner.document.create({ data: { userId, title: `${prefix} inputs` } });
    const ids: string[] = [];
    for (const [index, bytes] of (await Promise.all([pdf(`${prefix} A`), pdf(`${prefix} B`)])).entries()) {
      const key = `input/${userId}/${prefix}-${index}.pdf`;
      const checksum = createHash("sha256").update(bytes).digest("base64");
      if (store) { await storage.put({ key, bytes, contentType: "application/pdf", checksum }); objectKeys.add(key); }
      const storageObject = await owner.storageObject.create({ data: { provider: "s3", bucket: process.env.STORAGE_BUCKET!, objectKey: key, size: BigInt(bytes.byteLength), checksum } });
      const file = await owner.file.create({ data: { documentId: document.id, originalName: `${prefix}-${index}.pdf`, mimeType: "application/pdf", size: BigInt(bytes.byteLength), storageKey: key, storageObjectId: storageObject.id, checksum, pageCount: 1 } });
      await owner.fileVersion.create({ data: { fileId: file.id, ownerId: userId, version: 1, storageKey: key, checksum } });
      ids.push(file.id);
    }
    return ids;
  };
  const waitRun = async (runId: string, expected: string[]) => {
    for (let index = 0; index < 240; index += 1) {
      const run = await getWorkflowRun(userId, runId);
      if (run && expected.includes(run.status)) return run;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    throw new Error(`WORKFLOW_RUN_STUCK:${runId}`);
  };
  const waitAgent = async (runId: string, expected: string[]) => {
    for (let index = 0; index < 240; index += 1) {
      const run = await getAgentRun(userId, runId) as { status: string } | null;
      if (run && expected.includes(run.status)) return run;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    throw new Error(`AGENT_RUN_STUCK:${runId}`);
  };
  const fakePlanner = async (task: AgentPlannerTask) => ({ output: { schemaVersion: 1 as const, planId: task.planId, version: task.planVersion, steps: [{ stepId: "compress", toolId: "compress-pdf", toolVersion: "1", dependsOn: [], inputs: [{ source: "request" as const, input: "documents" }], reason: "Compress the selected document." }] }, estimatedCost: 0 });

  try {
    const runtimeIdentity = await db.$queryRaw<Array<{ current_user: string; rolsuper: boolean; rolbypassrls: boolean; rolcreatedb: boolean; rolcreaterole: boolean }>>`
      SELECT current_user, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole
      FROM pg_roles WHERE rolname = current_user
    `;
    assert.deepEqual(runtimeIdentity, [{ current_user: "dip_app", rolsuper: false, rolbypassrls: false, rolcreatedb: false, rolcreaterole: false }]);
    await owner.user.create({ data: { id: userId, email: `workflow-e2e-${userId}@example.invalid`, creditLedger: { create: { type: "BONUS", amount: 100, balance: 100, idempotencyKey: "workflow-e2e-seed", reason: "PROMOTIONAL_GRANT" } } } });
    assert.equal(getToolDefinition("merge-pdf").version, "1");
    assert.equal(getToolDefinition("compress-pdf").mime.input.includes("application/pdf"), true);

    const successInputs = await createInputs("success");
    const workflow = await createWorkflow(userId, { name: "Phase 7 closure", definition });
    const versioned = await updateWorkflow(userId, workflow.id, { name: "Phase 7 closure v2", definition });
    assert.equal(versioned.currentVersion?.version, 2);
    const successRun = await startWorkflowRun(userId, workflow.id, { documents: successInputs }, randomUUID());
    const succeeded = await waitRun(successRun.id, ["SUCCEEDED", "FAILED"]);
    assert.equal(succeeded.status, "SUCCEEDED");
    assert.equal(succeeded.jobs.length, 2);
    assert.deepEqual(succeeded.jobs.map((job) => job.workflowNodeId), ["merge", "compress"]);
    assert.ok(succeeded.jobs.every((job) => job.status === "SUCCEEDED" && job.steps.length === 1 && job.steps[0].status === "SUCCEEDED"));

    const records = await withTenant({ userId }, (tx) => tx.job.findMany({ where: { workflowRunId: successRun.id }, include: { toolExecutions: true }, orderBy: { createdAt: "asc" } }));
    assert.equal(records.length, 2);
    assert.ok(records.every((job) => job.toolExecutions.length === 1));
    const firstOutputs = (records[0].result as { outputFileIds: string[] }).outputFileIds;
    const secondInputs = (records[1].params as { inputFileIds: string[] }).inputFileIds;
    assert.deepEqual(secondInputs, [firstOutputs[0]], "step output must be the downstream input");
    const finalOutputs = (records[1].result as { outputFileIds: string[] }).outputFileIds;
    const finalFiles = await withTenant({ userId }, (tx) => tx.file.findMany({ where: { id: { in: finalOutputs } } }));
    assert.equal(finalFiles.length, 1);
    for (const file of finalFiles) { objectKeys.add(file.storageKey); const head = await storage.head(file.storageKey); assert.equal(head?.contentType, "application/pdf"); assert.ok((head?.size ?? 0) > 0); }

    const agentKey = randomUUID();
    const agent = await createAgentRun(userId, { request: "Compress my selected document.", locale: "en", scope: { inputs: { documents: [successInputs[0]] } } }, agentKey, randomUUID(), fakePlanner) as { id: string; workflowRunId: string | null };
    const repeatedAgent = await createAgentRun(userId, { request: "Compress my selected document.", locale: "en", scope: { inputs: { documents: [successInputs[0]] } } }, agentKey, randomUUID(), fakePlanner) as { id: string };
    assert.equal(repeatedAgent.id, agent.id, "Agent request idempotency must prevent duplicate execution");
    const completedAgent = await waitAgent(agent.id, ["SUCCEEDED", "FAILED"]);
    assert.equal(completedAgent.status, "SUCCEEDED");
    const agentRecord = await withTenant({ userId }, (tx) => tx.agentRun.findUniqueOrThrow({ where: { id: agent.id }, include: { currentPlanVersion: true, workflowRun: { include: { jobs: { include: { toolExecutions: true } } } } } }));
    assert.equal(agentRecord.currentPlanVersion?.state, "FROZEN");
    assert.equal(agentRecord.workflowRun?.jobs.length, 1);
    assert.equal(agentRecord.workflowRun?.jobs[0].toolExecutions.length, 1);
    assert.equal((agentRecord.evidence as { workflowRunId: string }).workflowRunId, agentRecord.workflowRunId);

    const cancelledAgent = await createAgentRun(userId, { request: "Compress my selected document.", locale: "en", scope: { inputs: { documents: [successInputs[1]] } } }, randomUUID(), randomUUID(), fakePlanner) as { id: string };
    await cancelAgentRun(userId, cancelledAgent.id);
    assert.equal((await waitAgent(cancelledAgent.id, ["CANCELLED"]))?.status, "CANCELLED");

    const brokenInputs = await createInputs("agent-failure", false);
    const failedAgent = await createAgentRun(userId, { request: "Compress my selected document.", locale: "en", scope: { inputs: { documents: [brokenInputs[0]] } } }, randomUUID(), randomUUID(), fakePlanner) as { id: string };
    assert.equal((await waitAgent(failedAgent.id, ["FAILED"]))?.status, "FAILED");

    await enqueueJob({ jobId: records[0].id, toolId: records[0].toolId, idempotencyKey: records[0].idempotencyKey, correlationId: records[0].correlationId!, userId, workflowRunId: successRun.id });
    await new Promise((resolve) => setTimeout(resolve, 500));
    const afterDuplicate = await withTenant({ userId }, (tx) => tx.job.findUniqueOrThrow({ where: { id: records[0].id }, include: { toolExecutions: true } }));
    assert.equal(afterDuplicate.toolExecutions.length, 1);
    assert.deepEqual((afterDuplicate.result as { outputFileIds: string[] }).outputFileIds, firstOutputs);

    const attackerId = randomUUID();
    await owner.user.create({ data: { id: attackerId, email: `workflow-e2e-attacker-${attackerId}@example.invalid` } });
    const auditPrivilege = await db.$queryRaw<Array<{ can_insert: boolean; can_select: boolean; can_update: boolean; can_delete: boolean }>>`
      SELECT has_table_privilege(current_user, 'audit_logs', 'INSERT') AS can_insert,
             has_table_privilege(current_user, 'audit_logs', 'SELECT') AS can_select,
             has_table_privilege(current_user, 'audit_logs', 'UPDATE') AS can_update,
             has_table_privilege(current_user, 'audit_logs', 'DELETE') AS can_delete
    `;
    assert.deepEqual(auditPrivilege, [{ can_insert: true, can_select: false, can_update: false, can_delete: false }]);
    await assert.rejects(
      () => withTenant({ userId: attackerId }, (tx) => tx.$executeRaw`
        INSERT INTO audit_logs(id, user_id, action, resource, resource_id, details)
        VALUES (${randomUUID()}::uuid, ${userId}::uuid, 'agent.cross_tenant.denied', 'agent_run', ${agent.id}::uuid, '{}'::jsonb)
      `),
      /row-level security policy|permission denied/i,
    );
    const victimBeforeAttack = await withTenant({ userId }, (tx) => tx.job.findUniqueOrThrow({ where: { id: records[0].id }, include: { steps: true, toolExecutions: true } }));
    const victimRunBeforeAttack = await withTenant({ userId }, (tx) => tx.workflowRun.findUniqueOrThrow({ where: { id: successRun.id } }));
    const victimOutputBeforeAttack = await withTenant({ userId }, (tx) => tx.file.findUniqueOrThrow({ where: { id: firstOutputs[0] } }));
    const victimObjectBeforeAttack = await storage.head(victimOutputBeforeAttack.storageKey);
    assert.equal(await withTenant({ userId: attackerId }, (tx) => tx.job.findUnique({ where: { id: records[0].id } })), null, "attacker RLS lookup must not reveal the victim job");
    assert.equal(await withTenant({ userId: attackerId }, (tx) => tx.file.findUnique({ where: { id: firstOutputs[0] } })), null, "attacker RLS lookup must not reveal the victim artifact");
    const injected = await getJobQueue().add("merge-pdf", { jobId: records[0].id, toolId: "merge-pdf", idempotencyKey: "cross-tenant-injection", correlationId: randomUUID(), userId: attackerId, workflowRunId: successRun.id }, { jobId: `cross-${randomUUID()}`, attempts: 1, removeOnFail: false });
    for (let index = 0; index < 80 && await injected.getState() !== "failed"; index += 1) await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(await injected.getState(), "failed");
    const failedInjection = await getJobQueue().getJob(injected.id!);
    assert.match(failedInjection?.failedReason ?? "", /JOB_NOT_FOUND/);
    const victimAfterAttack = await withTenant({ userId }, (tx) => tx.job.findUniqueOrThrow({ where: { id: records[0].id }, include: { steps: true, toolExecutions: true } }));
    const victimRunAfterAttack = await withTenant({ userId }, (tx) => tx.workflowRun.findUniqueOrThrow({ where: { id: successRun.id } }));
    const victimOutputAfterAttack = await withTenant({ userId }, (tx) => tx.file.findUniqueOrThrow({ where: { id: firstOutputs[0] } }));
    const victimObjectAfterAttack = await storage.head(victimOutputAfterAttack.storageKey);
    assert.equal(victimAfterAttack.status, victimBeforeAttack.status);
    assert.deepEqual(victimAfterAttack.result, victimBeforeAttack.result, "victim output IDs must not change");
    assert.deepEqual(victimAfterAttack.steps.map(({ id, status }) => ({ id, status })), victimBeforeAttack.steps.map(({ id, status }) => ({ id, status })), "victim JobSteps must not change");
    assert.deepEqual(victimAfterAttack.toolExecutions.map(({ id, errorCode }) => ({ id, errorCode })), victimBeforeAttack.toolExecutions.map(({ id, errorCode }) => ({ id, errorCode })), "victim ToolExecutions must not change");
    assert.equal(victimRunAfterAttack.status, victimRunBeforeAttack.status, "victim workflow run must not change");
    assert.equal(victimOutputAfterAttack.storageKey, victimOutputBeforeAttack.storageKey);
    assert.deepEqual(victimObjectAfterAttack, victimObjectBeforeAttack, "victim object must not be replaced or deleted");
    assert.equal(await withTenant({ userId: attackerId }, (tx) => tx.job.findUnique({ where: { id: records[0].id } })), null);

    const failureInputs = await createInputs("failure", false);
    const failureWorkflow = await createWorkflow(userId, { name: "Phase 7 controlled failure", definition });
    const failureRun = await startWorkflowRun(userId, failureWorkflow.id, { documents: failureInputs }, randomUUID());
    const failed = await waitRun(failureRun.id, ["FAILED"]);
    assert.equal(failed.jobs.length, 1, "dependent node must not be dispatched");
    assert.equal(failed.jobs[0].status, "FAILED");
    const failedJob = await withTenant({ userId }, (tx) => tx.job.findUniqueOrThrow({ where: { id: failed.jobs[0].id }, include: { toolExecutions: true, steps: true } }));
    assert.equal(failedJob.toolExecutions.length, 1, "terminal failure must remain auditable");
    assert.equal(failedJob.steps[0].status, "FAILED");
    assert.equal((await getJobQueue().getJob(failedJob.id))?.attemptsMade, 3);

    await getJobQueue().pause();
    const cancelInputs = await createInputs("cancel");
    const cancelWorkflow = await createWorkflow(userId, { name: "Phase 7 cancellation", definition });
    const cancelRun = await startWorkflowRun(userId, cancelWorkflow.id, { documents: cancelInputs }, randomUUID());
    const cancelled = await cancelWorkflowRun(userId, cancelRun.id);
    assert.equal(cancelled.status, "CANCELLED");
    await getJobQueue().resume();
    await new Promise((resolve) => setTimeout(resolve, 750));
    const cancelledState = await getWorkflowRun(userId, cancelRun.id);
    assert.equal(cancelledState?.status, "CANCELLED");
    assert.equal(cancelledState?.jobs.length, 1);
    assert.equal(cancelledState?.jobs[0].status, "CANCELLED");
    assert.equal((await withTenant({ userId }, (tx) => tx.toolExecution.count({ where: { job: { workflowRunId: cancelRun.id } } }))), 0);

    const stuck = await withTenant({ userId }, (tx) => tx.job.count({ where: { workflowRunId: { in: [successRun.id, failureRun.id, cancelRun.id] }, status: { in: ["QUEUED", "RUNNING", "RETRYING"] } } }));
    assert.equal(stuck, 0);
  } finally {
    await getJobQueue().resume().catch(() => undefined);
    const files = await owner.file.findMany({ where: { document: { userId } }, select: { storageKey: true } }).catch(() => []);
    for (const file of files) objectKeys.add(file.storageKey);
    for (const key of objectKeys) await storage.deleteObject(key).catch(() => undefined);
    await Promise.allSettled([documentWorker.close(), aiWorker.close()]);
    await Promise.allSettled([closeQueueResources(), closeStorage(), db.$disconnect(), owner.$disconnect()]);
  }
});
