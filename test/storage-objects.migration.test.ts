import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import test from "node:test";

const migrationPath = new URL(
  "../prisma/migrations/20261121120000_n1a_storage_objects_tenant_isolation/migration.sql",
  import.meta.url,
);
const sql = readFileSync(migrationPath, "utf8");
const rolesBootstrap = readFileSync(new URL("../prisma/bootstrap/roles.sql", import.meta.url), "utf8");
const runtimeGrants = readFileSync(new URL("../prisma/bootstrap/dip_app.sql", import.meta.url), "utf8");
const schema = readFileSync(new URL("../prisma/schema.prisma", import.meta.url), "utf8");
const ci = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
const doc = readFileSync(new URL("../docs/n1a-storage-objects-tenant-isolation.md", import.meta.url), "utf8");
const rlsIntegration = readFileSync(new URL("./storage-objects.rls.integration.test.mjs", import.meta.url), "utf8");
const neonRoleCompatTest = readFileSync(new URL("./neon-role-compatibility.rls.integration.test.mjs", import.meta.url), "utf8");

test("N1-A corrective migration preserves all 12 historical migrations and adds one forward-only migration", () => {
  const dirs = readdirSync(new URL("../prisma/migrations", import.meta.url), { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();

  assert.deepEqual(dirs, [
    "20260909155620_init_baseline",
    "20260909161000_security_hardening",
    "20260910120000_phase4_monetization_core",
    "20260910180000_phase7_workflows",
    "20260912170000_cr003_auth_identity_rls",
    "20260913120000_phase8_document_agent",
    "20260913130000_phase8_agent_audit_permissions",
    "20260914120000_phase9a_business_api_foundation",
    "20260914160000_phase9b_public_api",
    "20260915100000_release_a_malware_security_events",
    "20260915110000_release_b_feature_flags_runtime_read",
    "20260923090000_retention_scheduler_least_privilege",
    "20261121120000_n1a_storage_objects_tenant_isolation",
  ]);
});

test("N1-A migration enforces migration-owner preflight, storage-key coordinate preflight/constraints, mixed API-client fail-closed checks, composite FK, and orphan preservation", () => {
  assert.match(sql, /IF current_user IN \('dip_app', 'dip_retention'\) THEN\s+RAISE EXCEPTION 'MIGRATION_ROLE_INVALID/);
  assert.match(sql, /ALTER TABLE "storage_objects"\s+ADD COLUMN "owner_user_id" UUID,\s+ADD COLUMN "organization_id" UUID,\s+ADD COLUMN "api_client_id" UUID;/);
  assert.match(sql, /FILE_STORAGE_OBJECT_REQUIRED_CONFLICT/);
  assert.match(sql, /FILE_EPHEMERAL_STORAGE_OBJECT_CONFLICT/);
  assert.match(sql, /FILE_STORAGE_KEY_MISMATCH_CONFLICT/);
  assert.match(sql, /STORAGE_OBJECT_TENANT_CONFLICT/);
  assert.match(sql, /COUNT\(DISTINCT d\."organization_id"\) = 1 AND BOOL_OR\(d\."organization_id" IS NULL\)/);
  assert.match(sql, /BOOL_OR\(has_api_job AND has_non_api_job\)/);
  assert.match(sql, /BOOL_OR\(resolved_file_api_client_id IS NOT NULL\) AND BOOL_OR\(resolved_file_api_client_id IS NULL\)/);
  assert.match(sql, /j\."params"->'inputFileIds'/);
  assert.match(sql, /j\."result"->'outputFileIds'/);
  assert.match(sql, /STORAGE_OBJECT_API_CLIENT_CONFLICT/);
  assert.doesNotMatch(sql, /DELETE\s+FROM\s+"?storage_objects"?/i, "backfill must never silently delete orphaned storage_objects");
  assert.doesNotMatch(sql, /DELETE\s+FROM\s+"?files"?/i, "preflight must never silently delete files rows");

  assert.match(sql, /CONSTRAINT "files_ephemeral_or_storage_object_check" CHECK/);
  assert.match(sql, /FILE_STORAGE_OBJECT_REQUIRED/);
  assert.match(sql, /FILE_STORAGE_KEY_MISMATCH/);
  assert.match(sql, /FILE_STORAGE_COORDINATES_IMMUTABLE/);
  assert.match(
    sql,
    /IF TG_OP = 'INSERT'\s+OR NEW\."storage_object_id" IS DISTINCT FROM OLD\."storage_object_id" THEN\s+v_ctx_api_client_id := NULLIF\(pg_catalog\.current_setting\('app\.current_api_client_id', true\), ''\)::uuid;/,
    "session api_client_id binding must apply on INSERT and storage_object_id link changes without breaking metadata-only owner UPDATEs",
  );
  assert.match(sql, /CREATE TRIGGER files_storage_object_tenant_guard\s+BEFORE INSERT OR UPDATE ON "files"/);
  assert.match(sql, /so\."object_key" = "files"\."storage_key"/);
  assert.match(sql, /CONSTRAINT "storage_objects_tenant_scope_check" CHECK/);
  assert.match(sql, /CONSTRAINT "storage_objects_owner_user_id_fkey"\s+FOREIGN KEY \("owner_user_id"\) REFERENCES "users"\("id"\)\s+ON DELETE RESTRICT ON UPDATE CASCADE/);
  assert.match(sql, /CONSTRAINT "storage_objects_organization_id_fkey"\s+FOREIGN KEY \("organization_id"\) REFERENCES "organizations"\("id"\)\s+ON DELETE RESTRICT ON UPDATE CASCADE/);
  assert.match(sql, /CONSTRAINT "storage_objects_api_client_organization_fkey"\s+FOREIGN KEY \("api_client_id", "organization_id"\) REFERENCES "api_clients"\("id", "organization_id"\)\s+ON DELETE RESTRICT ON UPDATE CASCADE/);

  assert.match(schema, /model StorageObject \{[\s\S]*ownerUserId\s+String\?\s+@map\("owner_user_id"\)\s+@db\.Uuid/);
  assert.match(schema, /model StorageObject \{[\s\S]*organizationId\s+String\?\s+@map\("organization_id"\)\s+@db\.Uuid/);
  assert.match(schema, /model StorageObject \{[\s\S]*apiClientId\s+String\?\s+@map\("api_client_id"\)\s+@db\.Uuid/);
});

test("N1-A migration scopes all runtime policies explicitly TO dip_app, guards cross-API-client File links, and hardens SECURITY DEFINER privileges", () => {
  assert.match(sql, /ALTER TABLE "storage_objects" ENABLE ROW LEVEL SECURITY;/);
  assert.match(sql, /ALTER TABLE "storage_objects" FORCE ROW LEVEL SECURITY;/);

  for (const policyName of [
    "storage_objects_user_tenant_policy",
    "storage_objects_org_member_select",
    "storage_objects_org_member_insert",
    "storage_objects_org_member_update",
    "storage_objects_api_client_select",
    "storage_objects_api_client_insert",
    "storage_objects_api_client_update",
  ]) {
    assert.match(
      sql,
      new RegExp(`CREATE POLICY ${policyName} ON "storage_objects"\\s+FOR (?:ALL|SELECT|INSERT|UPDATE)\\s+TO dip_app`),
      `${policyName} must be explicitly scoped TO dip_app`,
    );
  }

  assert.match(
    sql,
    /CREATE POLICY files_storage_object_rls_guard ON "files"\s+AS RESTRICTIVE\s+FOR ALL\s+TO dip_app/,
    "files must enforce restrictive cross-table storage_objects RLS guard for dip_app",
  );
  assert.match(sql, /STORAGE_OBJECT_API_CLIENT_MISMATCH/);

  // Ensure no universal permissive policy exists for PUBLIC or dip_app.
  assert.doesNotMatch(sql, /CREATE POLICY\s+\w+\s+ON\s+"storage_objects"\s+FOR\s+\w+\s+USING\s*\(\s*true\s*\)/i);
  assert.match(sql, /CREATE POLICY storage_objects_retention_select ON "storage_objects"\s+FOR SELECT\s+TO dip_retention\s+USING \(true\);/);
  assert.match(sql, /CREATE POLICY storage_objects_retention_update ON "storage_objects"\s+FOR UPDATE\s+TO dip_retention\s+USING \(true\)\s+WITH CHECK \(true\);/);

  // Security-definer functions must lock search_path and revoke PUBLIC/retention execute (and dip_app on trigger functions).
  assert.match(sql, /REVOKE ALL ON FUNCTION app_api_client_matches_tenant\(uuid, uuid, uuid, boolean\) FROM PUBLIC;/);
  assert.match(sql, /REVOKE ALL ON FUNCTION app_api_client_matches_tenant\(uuid, uuid, uuid, boolean\) FROM dip_retention;/);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION app_api_client_matches_tenant\(uuid, uuid, uuid, boolean\) TO dip_app;/);

  for (const triggerFn of [
    "enforce_storage_object_immutability()",
    "enforce_file_storage_object_tenant_match()",
    "enforce_document_storage_object_tenant_match()",
  ]) {
    assert.match(
      sql,
      new RegExp(`REVOKE ALL ON FUNCTION ${triggerFn.replace(/[()]/g, "\\$&")} FROM PUBLIC, dip_app, dip_retention;`),
    );
  }
  assert.equal((sql.match(/SET search_path = pg_catalog, public/g) ?? []).length, 4);

  // Runtime and retention grants remain least-privilege without DELETE or elevated roles.
  assert.match(sql, /GRANT SELECT, INSERT ON "storage_objects" TO dip_app;/);
  assert.match(sql, /GRANT UPDATE \("region", "checksum", "deleted_at"\) ON "storage_objects" TO dip_app;/);
  assert.match(sql, /GRANT SELECT ON "storage_objects" TO dip_retention;/);
  assert.match(sql, /GRANT UPDATE \("deleted_at"\) ON "storage_objects" TO dip_retention;/);
  assert.doesNotMatch(sql, /GRANT[^;]*\bDELETE\b[^;]*ON\s+"?storage_objects"?/i);
  assert.doesNotMatch(sql, /\bSUPERUSER\b|\sBYPASSRLS\b/);

  assert.match(runtimeGrants, /GRANT SELECT, INSERT ON storage_objects TO dip_app;/);
  assert.match(runtimeGrants, /GRANT UPDATE \(region, checksum, deleted_at\) ON storage_objects TO dip_app;/);
  assert.match(runtimeGrants, /app_api_client_matches_tenant\(uuid, uuid, uuid, boolean\)/);
  assert.doesNotMatch(runtimeGrants, /BYPASSRLS|SUPERUSER/);
});

test("CI defines an isolated fail-closed PostgreSQL 18 RLS security gate and docs forbid disabling RLS as standard rollback", () => {
  assert.match(ci, /rls-security:\s+name: RLS Security \(PostgreSQL 18\)/);
  assert.match(ci, /image: postgres:18-alpine/);
  assert.match(ci, /DIP_REQUIRE_PG18: "1"/);
  assert.match(ci, /run: npm run test:rls/);
  assert.doesNotMatch(ci, /neon\.tech/i);

  assert.doesNotMatch(doc, /DISABLE ROW LEVEL SECURITY/i);
  assert.match(doc, /`ENABLE ROW LEVEL SECURITY` without `FORCE ROW LEVEL SECURITY`/);
  assert.match(doc, /separate future security hardening decision requiring explicit owner review/i);
  assert.doesNotMatch(
    rlsIntegration,
    /tx\.file\.create\(\{\s*data:\s*\{[^}]*\bdocumentId\s*:/,
    "RLS integration Prisma file.create calls must use checked relation document: { connect: { id } } when passing nested storageObject",
  );
  assert.match(rlsIntegration, /document:\s*\{\s*connect:\s*\{\s*id:\s*docA\s*\}\s*\}/);
  assert.match(rlsIntegration, /document:\s*\{\s*connect:\s*\{\s*id:\s*docOrgApiA1\s*\}\s*\}/);
});

test("N1-A migration and roles.sql enforce PostgreSQL 18 non-superuser role compatibility without CREATE ROLE or ALTER ROLE in schema DDL", () => {
  assert.doesNotMatch(
    sql,
    /\bCREATE\s+ROLE\b|\bALTER\s+ROLE\b/i,
    "Schema migration must never create or alter cluster roles so non-superuser migration owners (e.g. Neon neondb_owner) succeed on PG18",
  );

  const preflightEndIdx = sql.indexOf('ALTER TABLE "storage_objects"');
  assert.ok(preflightEndIdx > 0);
  const preflightBlock = sql.slice(0, preflightEndIdx);

  assert.match(preflightBlock, /FOREACH v_target_role IN ARRAY ARRAY\['dip_app', 'dip_retention'\]/);
  assert.match(preflightBlock, /FROM pg_catalog\.pg_roles r/);
  assert.match(preflightBlock, /ROLE_PREFLIGHT_MISSING/);
  assert.match(preflightBlock, /rolcanlogin=false \(expected LOGIN\)/);
  assert.match(preflightBlock, /rolsuper=true \(expected NOSUPERUSER\)/);
  assert.match(preflightBlock, /rolbypassrls=true \(expected NOBYPASSRLS\)/);
  assert.match(preflightBlock, /rolinherit=true \(expected NOINHERIT\)/);
  assert.match(preflightBlock, /rolcreatedb=true \(expected NOCREATEDB\)/);
  assert.match(preflightBlock, /rolcreaterole=true \(expected NOCREATEROLE\)/);
  assert.match(preflightBlock, /rolreplication=true \(expected NOREPLICATION\)/);
  assert.match(preflightBlock, /ROLE_PREFLIGHT_INVALID/);
  assert.match(preflightBlock, /FROM pg_catalog\.pg_auth_members membership/);
  assert.match(preflightBlock, /ROLE_PREFLIGHT_MEMBERSHIP_INVALID/);

  assert.match(rolesBootstrap, /ROLE_BOOTSTRAP_CALLER_INVALID/);
  assert.match(rolesBootstrap, /ROLE_BOOTSTRAP_PRIVILEGE_REQUIRED/);
  assert.match(rolesBootstrap, /IF v_caller_is_super AND \(/);
  assert.match(rolesBootstrap, /ROLE_PREFLIGHT_INVALID/);
  assert.match(rolesBootstrap, /ROLE_PREFLIGHT_MEMBERSHIP_INVALID/);

  assert.match(
    ci,
    /CREATE ROLE dip_nonsuper_owner LOGIN PASSWORD '[^']+' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;/,
  );
  assert.match(
    ci,
    /psql "\$DATABASE_URL" --set=ON_ERROR_STOP=1 --command="CREATE DATABASE dip_rls_nonsuper_pg18 OWNER dip_nonsuper_owner"/,
  );
  assert.match(ci, /Verify non-superuser PostgreSQL 18 role preflight, migrate deploy, and grant reconciliation/);
  assert.match(ci, /DIP_PG18_ADMIN_URL: postgresql:\/\/postgres:postgres@localhost:5432\/postgres/);
  assert.match(neonRoleCompatTest, /\["migrate", "deploy"\]/);
  assert.match(neonRoleCompatTest, /ROLE_PREFLIGHT_MEMBERSHIP_INVALID/);
});
