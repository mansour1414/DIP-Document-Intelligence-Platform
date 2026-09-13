BEGIN;
CREATE TYPE "WorkflowOrigin" AS ENUM ('USER','AGENT_INTERNAL');
CREATE TYPE "AgentRunStatus" AS ENUM ('REQUESTED','PLANNING','PLAN_VALIDATED','AWAITING_APPROVAL','APPROVED','FROZEN','EXECUTING','VERIFYING','SUCCEEDED','FAILED','CANCELLED');
ALTER TABLE "workflows" ADD COLUMN "origin" "WorkflowOrigin" NOT NULL DEFAULT 'USER';
CREATE TABLE "agent_runs" (
 "id" UUID PRIMARY KEY, "owner_id" UUID NOT NULL, "status" "AgentRunStatus" NOT NULL DEFAULT 'REQUESTED', "locale" VARCHAR(5) NOT NULL, "request" TEXT NOT NULL, "scope" JSONB NOT NULL, "trusted_budget" JSONB NOT NULL, "allowed_tool_ids" JSONB NOT NULL, "correlation_id" UUID NOT NULL, "idempotency_key" VARCHAR(255) NOT NULL, "current_plan_version_id" UUID, "workflow_run_id" UUID, "verification" JSONB, "evidence" JSONB, "error_code" VARCHAR(100), "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP, "updated_at" TIMESTAMP(3) NOT NULL, "completed_at" TIMESTAMP(3),
 CONSTRAINT "agent_runs_owner_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
 CONSTRAINT "agent_runs_workflow_run_id_fkey" FOREIGN KEY ("workflow_run_id") REFERENCES "workflow_runs"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);
CREATE TABLE "agent_plan_versions" (
 "id" UUID PRIMARY KEY, "agent_run_id" UUID NOT NULL, "version" INTEGER NOT NULL, "draft" JSONB NOT NULL, "resolved_scope" JSONB NOT NULL, "budget_preview" JSONB NOT NULL, "approval" JSONB NOT NULL, "state" VARCHAR(30) NOT NULL, "frozen_plan" JSONB, "integrity_hash" VARCHAR(64), "workflow_version_id" UUID, "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CONSTRAINT "agent_plan_versions_agent_run_id_fkey" FOREIGN KEY ("agent_run_id") REFERENCES "agent_runs"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
 CONSTRAINT "agent_plan_versions_workflow_version_id_fkey" FOREIGN KEY ("workflow_version_id") REFERENCES "workflow_versions"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
 CONSTRAINT "agent_plan_frozen_check" CHECK (("state" = 'FROZEN') = ("frozen_plan" IS NOT NULL AND "integrity_hash" IS NOT NULL))
);
ALTER TABLE "agent_runs" ADD CONSTRAINT "agent_runs_current_plan_version_id_fkey" FOREIGN KEY ("current_plan_version_id") REFERENCES "agent_plan_versions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "ai_usage" ADD COLUMN "agent_run_id" UUID;
ALTER TABLE "ai_usage" ADD CONSTRAINT "ai_usage_agent_run_id_fkey" FOREIGN KEY ("agent_run_id") REFERENCES "agent_runs"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
CREATE UNIQUE INDEX "agent_runs_owner_id_idempotency_key_key" ON "agent_runs"("owner_id","idempotency_key");
CREATE UNIQUE INDEX "agent_runs_correlation_id_key" ON "agent_runs"("correlation_id");
CREATE UNIQUE INDEX "agent_runs_current_plan_version_id_key" ON "agent_runs"("current_plan_version_id");
CREATE UNIQUE INDEX "agent_runs_workflow_run_id_key" ON "agent_runs"("workflow_run_id");
CREATE INDEX "agent_runs_owner_id_status_created_at_idx" ON "agent_runs"("owner_id","status","created_at");
CREATE UNIQUE INDEX "agent_plan_versions_agent_run_id_version_key" ON "agent_plan_versions"("agent_run_id","version");
CREATE UNIQUE INDEX "agent_plan_versions_workflow_version_id_key" ON "agent_plan_versions"("workflow_version_id");
CREATE INDEX "agent_plan_versions_agent_run_id_created_at_idx" ON "agent_plan_versions"("agent_run_id","created_at");
CREATE INDEX "ai_usage_agent_run_id_idx" ON "ai_usage"("agent_run_id");
ALTER TABLE "agent_runs" ENABLE ROW LEVEL SECURITY; ALTER TABLE "agent_runs" FORCE ROW LEVEL SECURITY;
ALTER TABLE "agent_plan_versions" ENABLE ROW LEVEL SECURITY; ALTER TABLE "agent_plan_versions" FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_runs_tenant_policy ON "agent_runs" FOR ALL USING ("owner_id"=NULLIF(current_setting('app.current_user_id',true),'')::uuid) WITH CHECK ("owner_id"=NULLIF(current_setting('app.current_user_id',true),'')::uuid);
CREATE POLICY agent_plan_versions_tenant_policy ON "agent_plan_versions" FOR ALL USING (EXISTS(SELECT 1 FROM "agent_runs" a WHERE a.id="agent_plan_versions"."agent_run_id" AND a.owner_id=NULLIF(current_setting('app.current_user_id',true),'')::uuid)) WITH CHECK (EXISTS(SELECT 1 FROM "agent_runs" a WHERE a.id="agent_plan_versions"."agent_run_id" AND a.owner_id=NULLIF(current_setting('app.current_user_id',true),'')::uuid));
GRANT SELECT,INSERT,UPDATE,DELETE ON "agent_runs","agent_plan_versions" TO dip_app;
COMMIT;
