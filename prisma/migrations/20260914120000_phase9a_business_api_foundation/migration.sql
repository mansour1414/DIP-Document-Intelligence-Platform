-- Phase 9A: business and API platform foundation. Existing user API keys remain
-- legacy-only; all newly issued keys are bound to an organization API client.
CREATE TYPE "OrganizationStatus" AS ENUM ('ACTIVE', 'SUSPENDED', 'ARCHIVED');
CREATE TYPE "ApiClientStatus" AS ENUM ('ACTIVE', 'INACTIVE');
CREATE TYPE "ApiCredentialStatus" AS ENUM ('ACTIVE', 'REVOKED');

ALTER TABLE "organizations" ADD COLUMN "status" "OrganizationStatus" NOT NULL DEFAULT 'ACTIVE';
ALTER TABLE "memberships" ADD COLUMN "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;

CREATE TABLE "api_clients" (
  "id" UUID NOT NULL,
  "organization_id" UUID NOT NULL,
  "name" VARCHAR(100) NOT NULL,
  "status" "ApiClientStatus" NOT NULL DEFAULT 'ACTIVE',
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "api_clients_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "api_clients_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE
);
CREATE UNIQUE INDEX "api_clients_organization_id_name_key" ON "api_clients"("organization_id", "name");
CREATE UNIQUE INDEX "api_clients_id_organization_id_key" ON "api_clients"("id", "organization_id");
CREATE INDEX "api_clients_organization_id_status_idx" ON "api_clients"("organization_id", "status");

ALTER TABLE "api_keys" ALTER COLUMN "user_id" DROP NOT NULL;
ALTER TABLE "api_keys" ADD COLUMN "organization_id" UUID;
ALTER TABLE "api_keys" ADD COLUMN "api_client_id" UUID;
ALTER TABLE "api_keys" ADD COLUMN "key_prefix" VARCHAR(32);
ALTER TABLE "api_keys" ADD COLUMN "status" "ApiCredentialStatus" NOT NULL DEFAULT 'ACTIVE';
ALTER TABLE "api_keys" ADD COLUMN "revoked_at" TIMESTAMP(3);
ALTER TABLE "api_keys" ADD COLUMN "rotated_from_id" UUID;
ALTER TABLE "api_keys" ADD COLUMN "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE;
ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_api_client_organization_fkey" FOREIGN KEY ("api_client_id", "organization_id") REFERENCES "api_clients"("id", "organization_id") ON DELETE CASCADE;
ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_rotated_from_id_fkey" FOREIGN KEY ("rotated_from_id") REFERENCES "api_keys"("id");
ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_business_scope_check" CHECK (
  ("organization_id" IS NULL AND "api_client_id" IS NULL AND "key_prefix" IS NULL AND "user_id" IS NOT NULL)
  OR ("organization_id" IS NOT NULL AND "api_client_id" IS NOT NULL AND "key_prefix" IS NOT NULL)
);
CREATE UNIQUE INDEX "api_keys_key_prefix_key" ON "api_keys"("key_prefix");
CREATE INDEX "api_keys_organization_id_status_idx" ON "api_keys"("organization_id", "status");
CREATE INDEX "api_keys_api_client_id_status_idx" ON "api_keys"("api_client_id", "status");

CREATE TABLE "api_idempotency_records" (
  "id" UUID NOT NULL,
  "organization_id" UUID NOT NULL,
  "api_client_id" UUID NOT NULL,
  "idempotency_key" VARCHAR(255) NOT NULL,
  "request_hash" VARCHAR(64) NOT NULL,
  "resource_type" VARCHAR(50),
  "resource_id" UUID,
  "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "expires_at" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "api_idempotency_records_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "api_idempotency_records_client_organization_fkey" FOREIGN KEY ("api_client_id", "organization_id") REFERENCES "api_clients"("id", "organization_id") ON DELETE CASCADE,
  CONSTRAINT "api_idempotency_records_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE
);
CREATE UNIQUE INDEX "api_idempotency_records_api_client_id_idempotency_key_key" ON "api_idempotency_records"("api_client_id", "idempotency_key");
CREATE INDEX "api_idempotency_records_organization_id_expires_at_idx" ON "api_idempotency_records"("organization_id", "expires_at");

ALTER TABLE "audit_logs" ADD COLUMN "organization_id" UUID;
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id");
CREATE INDEX "audit_logs_organization_id_created_at_idx" ON "audit_logs"("organization_id", "created_at");

-- Security-definer predicates avoid recursive membership RLS evaluation. They
-- expose booleans only and pin search_path to prevent object-shadowing attacks.
CREATE OR REPLACE FUNCTION app_is_org_member(p_organization_id uuid, p_user_id uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT EXISTS (SELECT 1 FROM public.memberships m WHERE m.organization_id = p_organization_id AND m.user_id = p_user_id)
$$;
CREATE OR REPLACE FUNCTION app_has_org_role(p_organization_id uuid, p_user_id uuid, p_roles "MemberRole"[])
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT EXISTS (SELECT 1 FROM public.memberships m WHERE m.organization_id = p_organization_id AND m.user_id = p_user_id AND m.role = ANY(p_roles))
$$;
REVOKE ALL ON FUNCTION app_is_org_member(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_has_org_role(uuid, uuid, "MemberRole"[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_is_org_member(uuid, uuid), app_has_org_role(uuid, uuid, "MemberRole"[]) TO dip_app;

CREATE OR REPLACE FUNCTION create_organization_with_owner(p_id uuid, p_name text, p_slug text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE actor uuid := NULLIF(current_setting('app.current_user_id', true), '')::uuid;
BEGIN
  IF actor IS NULL OR NOT EXISTS (SELECT 1 FROM public.users WHERE id = actor AND status = 'ACTIVE') THEN RAISE EXCEPTION 'AUTH_REQUIRED'; END IF;
  INSERT INTO public.organizations(id, name, slug, plan, status, created_at, updated_at) VALUES (p_id, p_name, p_slug, 'FREE', 'ACTIVE', now(), now());
  INSERT INTO public.memberships(id, user_id, organization_id, role, created_at, updated_at) VALUES (gen_random_uuid(), actor, p_id, 'OWNER', now(), now());
  RETURN p_id;
END $$;
REVOKE ALL ON FUNCTION create_organization_with_owner(uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION create_organization_with_owner(uuid, text, text) TO dip_app;

CREATE OR REPLACE FUNCTION api_key_auth_candidate(p_prefix text)
RETURNS TABLE(key_id uuid, key_hash varchar, key_status "ApiCredentialStatus", expires_at timestamp, api_client_id uuid, client_status "ApiClientStatus", organization_id uuid, organization_status "OrganizationStatus", scopes jsonb)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT k.id, k.key_hash, k.status, k.expires_at, c.id, c.status, o.id, o.status, k.scopes
  FROM public.api_keys k JOIN public.api_clients c ON c.id = k.api_client_id JOIN public.organizations o ON o.id = k.organization_id
  WHERE k.key_prefix = p_prefix AND k.organization_id = c.organization_id
$$;
REVOKE ALL ON FUNCTION api_key_auth_candidate(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION api_key_auth_candidate(text) TO dip_app;

ALTER TABLE "organizations" ENABLE ROW LEVEL SECURITY; ALTER TABLE "organizations" FORCE ROW LEVEL SECURITY;
ALTER TABLE "memberships" ENABLE ROW LEVEL SECURITY; ALTER TABLE "memberships" FORCE ROW LEVEL SECURITY;
ALTER TABLE "teams" ENABLE ROW LEVEL SECURITY; ALTER TABLE "teams" FORCE ROW LEVEL SECURITY;
ALTER TABLE "api_clients" ENABLE ROW LEVEL SECURITY; ALTER TABLE "api_clients" FORCE ROW LEVEL SECURITY;
ALTER TABLE "api_keys" ENABLE ROW LEVEL SECURITY; ALTER TABLE "api_keys" FORCE ROW LEVEL SECURITY;
ALTER TABLE "api_idempotency_records" ENABLE ROW LEVEL SECURITY; ALTER TABLE "api_idempotency_records" FORCE ROW LEVEL SECURITY;

CREATE POLICY organizations_tenant_select ON "organizations" FOR SELECT USING (id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid AND app_is_org_member(id, NULLIF(current_setting('app.current_user_id', true), '')::uuid));
CREATE POLICY organizations_admin_update ON "organizations" FOR UPDATE USING (id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid AND app_has_org_role(id, NULLIF(current_setting('app.current_user_id', true), '')::uuid, ARRAY['OWNER','ADMIN']::"MemberRole"[])) WITH CHECK (id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);
CREATE POLICY memberships_tenant_select ON "memberships" FOR SELECT USING (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid AND app_is_org_member(organization_id, NULLIF(current_setting('app.current_user_id', true), '')::uuid));
CREATE POLICY memberships_admin_insert ON "memberships" FOR INSERT WITH CHECK (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid AND app_has_org_role(organization_id, NULLIF(current_setting('app.current_user_id', true), '')::uuid, ARRAY['OWNER','ADMIN']::"MemberRole"[]));
CREATE POLICY memberships_admin_update ON "memberships" FOR UPDATE USING (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid AND app_has_org_role(organization_id, NULLIF(current_setting('app.current_user_id', true), '')::uuid, ARRAY['OWNER','ADMIN']::"MemberRole"[])) WITH CHECK (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);
CREATE POLICY memberships_admin_delete ON "memberships" FOR DELETE USING (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid AND app_has_org_role(organization_id, NULLIF(current_setting('app.current_user_id', true), '')::uuid, ARRAY['OWNER','ADMIN']::"MemberRole"[]));
CREATE POLICY teams_tenant ON "teams" FOR ALL USING (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid AND app_is_org_member(organization_id, NULLIF(current_setting('app.current_user_id', true), '')::uuid)) WITH CHECK (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);
CREATE POLICY api_clients_tenant ON "api_clients" FOR ALL USING (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid AND app_is_org_member(organization_id, NULLIF(current_setting('app.current_user_id', true), '')::uuid)) WITH CHECK (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);
CREATE POLICY api_keys_tenant ON "api_keys" FOR ALL USING (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid AND app_is_org_member(organization_id, NULLIF(current_setting('app.current_user_id', true), '')::uuid)) WITH CHECK (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);
CREATE POLICY api_keys_authenticated_client_select ON "api_keys" FOR SELECT USING (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid AND api_client_id = NULLIF(current_setting('app.current_api_client_id', true), '')::uuid);
CREATE POLICY api_keys_authenticated_client_touch ON "api_keys" FOR UPDATE USING (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid AND api_client_id = NULLIF(current_setting('app.current_api_client_id', true), '')::uuid) WITH CHECK (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid AND api_client_id = NULLIF(current_setting('app.current_api_client_id', true), '')::uuid);
CREATE POLICY api_idempotency_tenant ON "api_idempotency_records" FOR ALL USING (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid AND (app_is_org_member(organization_id, NULLIF(current_setting('app.current_user_id', true), '')::uuid) OR api_client_id = NULLIF(current_setting('app.current_api_client_id', true), '')::uuid)) WITH CHECK (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid);

-- Audit remains append-only. Replace the older user-only predicate so permissive
-- policies cannot accidentally OR an organization boundary away.
DROP POLICY IF EXISTS audit_logs_tenant_insert_policy ON "audit_logs";
CREATE POLICY audit_logs_tenant_insert_policy ON "audit_logs" FOR INSERT WITH CHECK (
  (organization_id IS NULL AND user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid)
  OR (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid
      AND (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
           OR (user_id IS NULL AND NULLIF(current_setting('app.current_api_client_id', true), '')::uuid IS NOT NULL)))
);

GRANT SELECT, INSERT, UPDATE, DELETE ON "organizations", "memberships", "teams", "api_clients", "api_keys", "api_idempotency_records" TO dip_app;
