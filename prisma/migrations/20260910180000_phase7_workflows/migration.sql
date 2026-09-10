BEGIN;

CREATE TYPE "WorkflowStatus" AS ENUM ('ACTIVE', 'ARCHIVED');
CREATE TABLE "workflows" (
  "id" UUID NOT NULL, "owner_id" UUID NOT NULL, "name" VARCHAR(120) NOT NULL,
  "status" "WorkflowStatus" NOT NULL DEFAULT 'ACTIVE', "current_version_id" UUID,
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "workflows_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "workflows_owner_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);
CREATE TABLE "workflow_versions" (
  "id" UUID NOT NULL, "workflow_id" UUID NOT NULL, "version" INTEGER NOT NULL, "definition" JSONB NOT NULL,
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "workflow_versions_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "workflow_versions_workflow_id_fkey" FOREIGN KEY ("workflow_id") REFERENCES "workflows"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);
CREATE TABLE "workflow_runs" (
  "id" UUID NOT NULL, "owner_id" UUID NOT NULL, "workflow_version_id" UUID NOT NULL,
  "status" "JobStatus" NOT NULL DEFAULT 'QUEUED', "inputs" JSONB NOT NULL DEFAULT '{}', "result" JSONB, "error" JSONB,
  "error_code" VARCHAR(100), "correlation_id" UUID NOT NULL, "started_at" TIMESTAMP(3), "completed_at" TIMESTAMP(3), "cancelled_at" TIMESTAMP(3),
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP, "updated_at" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "workflow_runs_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "workflow_runs_owner_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT "workflow_runs_workflow_version_id_fkey" FOREIGN KEY ("workflow_version_id") REFERENCES "workflow_versions"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);
ALTER TABLE "workflows" ADD CONSTRAINT "workflows_current_version_id_fkey" FOREIGN KEY ("current_version_id") REFERENCES "workflow_versions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "jobs" ADD COLUMN "workflow_run_id" UUID, ADD COLUMN "workflow_node_id" VARCHAR(100);
ALTER TABLE "jobs" ADD CONSTRAINT "jobs_workflow_run_id_fkey" FOREIGN KEY ("workflow_run_id") REFERENCES "workflow_runs"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE UNIQUE INDEX "workflows_current_version_id_key" ON "workflows"("current_version_id");
CREATE INDEX "workflows_owner_id_status_updated_at_idx" ON "workflows"("owner_id", "status", "updated_at");
CREATE UNIQUE INDEX "workflow_versions_workflow_id_version_key" ON "workflow_versions"("workflow_id", "version");
CREATE INDEX "workflow_versions_workflow_id_created_at_idx" ON "workflow_versions"("workflow_id", "created_at");
CREATE INDEX "workflow_runs_owner_id_status_created_at_idx" ON "workflow_runs"("owner_id", "status", "created_at");
CREATE INDEX "workflow_runs_workflow_version_id_idx" ON "workflow_runs"("workflow_version_id");
CREATE INDEX "jobs_workflow_run_id_status_idx" ON "jobs"("workflow_run_id", "status");
CREATE UNIQUE INDEX "jobs_workflow_run_id_workflow_node_id_key" ON "jobs"("workflow_run_id", "workflow_node_id");

ALTER TABLE "workflows" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "workflow_versions" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "workflow_runs" ENABLE ROW LEVEL SECURITY;
CREATE POLICY workflows_tenant_policy ON "workflows" FOR ALL USING ("owner_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid) WITH CHECK ("owner_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid);
CREATE POLICY workflow_versions_tenant_policy ON "workflow_versions" FOR ALL USING (EXISTS (SELECT 1 FROM "workflows" w WHERE w."id" = "workflow_versions"."workflow_id" AND w."owner_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid)) WITH CHECK (EXISTS (SELECT 1 FROM "workflows" w WHERE w."id" = "workflow_versions"."workflow_id" AND w."owner_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid));
CREATE POLICY workflow_runs_tenant_policy ON "workflow_runs" FOR ALL USING ("owner_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid) WITH CHECK ("owner_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid);

COMMIT;
