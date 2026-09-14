-- Phase 9B: bind public API clients to the existing user-owned execution engine,
-- add explicit public-job tenancy, and persist content-free API usage facts.
ALTER TABLE "api_clients" ADD COLUMN "created_by_user_id" UUID;
UPDATE "api_clients" c SET "created_by_user_id" = (
  SELECT m."user_id" FROM "memberships" m
  WHERE m."organization_id" = c."organization_id"
  ORDER BY CASE m."role" WHEN 'OWNER' THEN 0 WHEN 'ADMIN' THEN 1 ELSE 2 END, m."created_at" LIMIT 1
);
DO $$ BEGIN IF EXISTS (SELECT 1 FROM "api_clients" WHERE "created_by_user_id" IS NULL) THEN RAISE EXCEPTION 'API client has no organization member execution identity'; END IF; END $$;
ALTER TABLE "api_clients" ALTER COLUMN "created_by_user_id" SET NOT NULL;
ALTER TABLE "api_clients" ADD CONSTRAINT "api_clients_created_by_user_id_fkey" FOREIGN KEY ("created_by_user_id") REFERENCES "users"("id") ON DELETE RESTRICT;
CREATE INDEX "api_clients_created_by_user_id_idx" ON "api_clients"("created_by_user_id");

ALTER TABLE "jobs" ADD COLUMN "organization_id" UUID;
ALTER TABLE "jobs" ADD COLUMN "api_client_id" UUID;
ALTER TABLE "jobs" ADD CONSTRAINT "jobs_public_scope_check" CHECK (("organization_id" IS NULL AND "api_client_id" IS NULL) OR ("organization_id" IS NOT NULL AND "api_client_id" IS NOT NULL));
ALTER TABLE "jobs" ADD CONSTRAINT "jobs_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE RESTRICT;
ALTER TABLE "jobs" ADD CONSTRAINT "jobs_api_client_organization_fkey" FOREIGN KEY ("api_client_id", "organization_id") REFERENCES "api_clients"("id", "organization_id") ON DELETE RESTRICT;
CREATE INDEX "jobs_organization_id_api_client_id_created_at_idx" ON "jobs"("organization_id", "api_client_id", "created_at");

CREATE TABLE "api_usage" (
  "id" UUID NOT NULL,
  "organization_id" UUID NOT NULL,
  "api_client_id" UUID NOT NULL,
  "request_id" UUID NOT NULL,
  "route" VARCHAR(120) NOT NULL,
  "method" VARCHAR(10) NOT NULL,
  "tool_id" VARCHAR(50),
  "status_code" INTEGER NOT NULL,
  "request_count" INTEGER NOT NULL DEFAULT 1,
  "bytes_in" BIGINT NOT NULL DEFAULT 0,
  "bytes_out" BIGINT NOT NULL DEFAULT 0,
  "credits_used" DECIMAL(12,2) NOT NULL DEFAULT 0,
  "occurred_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "api_usage_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "api_usage_nonnegative_check" CHECK ("request_count" > 0 AND "bytes_in" >= 0 AND "bytes_out" >= 0 AND "credits_used" >= 0),
  CONSTRAINT "api_usage_client_organization_fkey" FOREIGN KEY ("api_client_id", "organization_id") REFERENCES "api_clients"("id", "organization_id") ON DELETE CASCADE,
  CONSTRAINT "api_usage_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE
);
CREATE UNIQUE INDEX "api_usage_request_id_key" ON "api_usage"("request_id");
CREATE INDEX "api_usage_organization_id_occurred_at_idx" ON "api_usage"("organization_id", "occurred_at");
CREATE INDEX "api_usage_api_client_id_occurred_at_idx" ON "api_usage"("api_client_id", "occurred_at");
CREATE INDEX "api_usage_tool_id_occurred_at_idx" ON "api_usage"("tool_id", "occurred_at");
ALTER TABLE "api_usage" ENABLE ROW LEVEL SECURITY; ALTER TABLE "api_usage" FORCE ROW LEVEL SECURITY;
CREATE POLICY api_usage_client_insert ON "api_usage" FOR INSERT WITH CHECK ("organization_id" = NULLIF(current_setting('app.current_organization_id', true), '')::uuid AND "api_client_id" = NULLIF(current_setting('app.current_api_client_id', true), '')::uuid);
CREATE POLICY api_usage_client_select ON "api_usage" FOR SELECT USING ("organization_id" = NULLIF(current_setting('app.current_organization_id', true), '')::uuid AND "api_client_id" = NULLIF(current_setting('app.current_api_client_id', true), '')::uuid);

CREATE POLICY jobs_api_client_policy ON "jobs" FOR ALL USING (
  "organization_id" = NULLIF(current_setting('app.current_organization_id', true), '')::uuid
  AND "api_client_id" = NULLIF(current_setting('app.current_api_client_id', true), '')::uuid
) WITH CHECK (
  "organization_id" = NULLIF(current_setting('app.current_organization_id', true), '')::uuid
  AND "api_client_id" = NULLIF(current_setting('app.current_api_client_id', true), '')::uuid
);

DROP FUNCTION api_key_auth_candidate(text);
CREATE FUNCTION api_key_auth_candidate(p_prefix text)
RETURNS TABLE(key_id uuid, key_hash varchar, key_status "ApiCredentialStatus", expires_at timestamp, api_client_id uuid, client_status "ApiClientStatus", organization_id uuid, organization_status "OrganizationStatus", execution_user_id uuid, scopes jsonb)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT k.id, k.key_hash, k.status, k.expires_at, c.id, c.status, o.id, o.status, c.created_by_user_id, k.scopes
  FROM public.api_keys k JOIN public.api_clients c ON c.id = k.api_client_id JOIN public.organizations o ON o.id = k.organization_id
  WHERE k.key_prefix = p_prefix AND k.organization_id = c.organization_id
$$;
REVOKE ALL ON FUNCTION api_key_auth_candidate(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION api_key_auth_candidate(text) TO dip_app;
GRANT SELECT, INSERT ON "api_usage" TO dip_app;
