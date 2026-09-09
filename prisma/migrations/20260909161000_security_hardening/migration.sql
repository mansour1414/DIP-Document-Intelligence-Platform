-- MVP file lineage and operational correlation; baseline migration remains immutable.
-- Runtime role provisioning is intentionally kept outside schema history.
BEGIN;

CREATE TABLE "file_versions" (
  "id" UUID NOT NULL,
  "file_id" UUID NOT NULL,
  "owner_id" UUID NOT NULL,
  "version" INTEGER NOT NULL,
  "storage_key" VARCHAR(500) NOT NULL,
  "checksum" VARCHAR(64),
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "file_versions_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "file_versions_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "files"("id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "file_versions_owner_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT "file_versions_file_id_version_key" UNIQUE ("file_id", "version")
);
CREATE INDEX "file_versions_owner_id_created_at_idx" ON "file_versions"("owner_id", "created_at");

ALTER TABLE "jobs" ADD COLUMN "correlation_id" UUID, ADD COLUMN "error_code" VARCHAR(100), ADD COLUMN "engine" VARCHAR(100), ADD COLUMN "engine_version" VARCHAR(100);
ALTER TABLE "job_steps" ADD COLUMN "correlation_id" UUID, ADD COLUMN "error_code" VARCHAR(100), ADD COLUMN "engine" VARCHAR(100), ADD COLUMN "engine_version" VARCHAR(100), ADD COLUMN "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE "tool_executions" ADD COLUMN "correlation_id" UUID, ADD COLUMN "error_code" VARCHAR(100), ADD COLUMN "engine" VARCHAR(100), ADD COLUMN "engine_version" VARCHAR(100), ADD COLUMN "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE "job_events" ADD COLUMN "correlation_id" UUID, ADD COLUMN "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;
CREATE INDEX "jobs_requester_id_correlation_id_idx" ON "jobs"("requester_id", "correlation_id");

-- Defaults are temporary for existing rows; Prisma owns @updatedAt values.
ALTER TABLE "job_steps" ALTER COLUMN "updated_at" DROP DEFAULT;
ALTER TABLE "tool_executions" ALTER COLUMN "updated_at" DROP DEFAULT;
ALTER TABLE "job_events" ALTER COLUMN "updated_at" DROP DEFAULT;

REVOKE ALL ON SCHEMA public FROM PUBLIC;

ALTER TABLE "documents" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "files" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "file_versions" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "jobs" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "job_steps" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "tool_executions" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "job_events" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "ai_usage" ENABLE ROW LEVEL SECURITY;

CREATE POLICY documents_tenant_policy ON "documents" FOR ALL USING ("user_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid) WITH CHECK ("user_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid);
CREATE POLICY files_tenant_policy ON "files" FOR ALL USING (EXISTS (SELECT 1 FROM "documents" d WHERE d."id" = "files"."document_id" AND d."user_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid)) WITH CHECK (EXISTS (SELECT 1 FROM "documents" d WHERE d."id" = "files"."document_id" AND d."user_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid));
CREATE POLICY file_versions_tenant_policy ON "file_versions" FOR ALL USING ("owner_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid AND EXISTS (SELECT 1 FROM "files" f JOIN "documents" d ON d."id" = f."document_id" WHERE f."id" = "file_versions"."file_id" AND d."user_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid)) WITH CHECK ("owner_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid AND EXISTS (SELECT 1 FROM "files" f JOIN "documents" d ON d."id" = f."document_id" WHERE f."id" = "file_versions"."file_id" AND d."user_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid));
CREATE POLICY jobs_tenant_policy ON "jobs" FOR ALL USING ("requester_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid) WITH CHECK ("requester_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid);
CREATE POLICY job_steps_tenant_policy ON "job_steps" FOR ALL USING (EXISTS (SELECT 1 FROM "jobs" j WHERE j."id" = "job_steps"."job_id" AND j."requester_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid)) WITH CHECK (EXISTS (SELECT 1 FROM "jobs" j WHERE j."id" = "job_steps"."job_id" AND j."requester_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid));
CREATE POLICY tool_executions_tenant_policy ON "tool_executions" FOR ALL USING (EXISTS (SELECT 1 FROM "jobs" j WHERE j."id" = "tool_executions"."job_id" AND j."requester_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid)) WITH CHECK (EXISTS (SELECT 1 FROM "jobs" j WHERE j."id" = "tool_executions"."job_id" AND j."requester_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid));
CREATE POLICY job_events_tenant_policy ON "job_events" FOR ALL USING (EXISTS (SELECT 1 FROM "jobs" j WHERE j."id" = "job_events"."job_id" AND j."requester_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid)) WITH CHECK (EXISTS (SELECT 1 FROM "jobs" j WHERE j."id" = "job_events"."job_id" AND j."requester_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid));
CREATE POLICY ai_usage_tenant_policy ON "ai_usage" FOR ALL USING ("user_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid) WITH CHECK ("user_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid);

COMMIT;
