-- One-time reconciliation for the partially applied development migration.
-- This preserves all tables, columns, indexes, and data.
BEGIN;

ALTER TABLE "file_versions" DROP CONSTRAINT "file_versions_file_id_fkey";
ALTER TABLE "file_versions" ADD CONSTRAINT "file_versions_file_id_fkey"
  FOREIGN KEY ("file_id") REFERENCES "files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "file_versions" DROP CONSTRAINT "file_versions_owner_id_fkey";
ALTER TABLE "file_versions" ADD CONSTRAINT "file_versions_owner_id_fkey"
  FOREIGN KEY ("owner_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "job_steps" ALTER COLUMN "updated_at" DROP DEFAULT;
ALTER TABLE "tool_executions" ALTER COLUMN "updated_at" DROP DEFAULT;
ALTER TABLE "job_events" ALTER COLUMN "updated_at" DROP DEFAULT;

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
