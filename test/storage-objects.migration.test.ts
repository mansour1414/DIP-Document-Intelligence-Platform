import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import test from "node:test";

const migrationPath = new URL(
  "../prisma/migrations/20261121120000_n1a_storage_objects_tenant_isolation/migration.sql",
  import.meta.url,
);
const sql = readFileSync(migrationPath, "utf8");
const runtimeGrants = readFileSync(new URL("../prisma/bootstrap/dip_app.sql", import.meta.url), "utf8");
const schema = readFileSync(new URL("../prisma/schema.prisma", import.meta.url), "utf8");
const ci = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
const doc = readFileSync(new URL("../docs/n1a-storage-objects-tenant-isolation.md", import.meta.url), "utf8");

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

test("N1-A migration enforces migration-owner preflight, mixed API-client fail-closed checks, composite FK, and orphan preservation", () => {
  assert.match(sql, /IF current_user IN \('dip_app', 'dip_retention'\) THEN\s+RAISE EXCEPTION 'MIGRATION_ROLE_INVALID/);
  assert.match(sql, /ALTER TABLE "storage_objects"\s+ADD COLUMN "owner_user_id" UUID,\s+ADD COLUMN "organization_id" UUID,\s+ADD COLUMN "api_client_id" UUID;/);
  assert.match(sql, /STORAGE_OBJECT_TENANT_CONFLICT/);
  assert.match(sql, /COUNT\(DISTINCT d\."organization_id"\) = 1 AND BOOL_OR\(d\."organization_id" IS NULL\)/);
  assert.match(sql, /BOOL_OR\(has_api_job AND has_non_api_job\)/);
  assert.match(sql, /BOOL_OR\(resolved_file_api_client_id IS NOT NULL\) AND BOOL_OR\(resolved_file_api_client_id IS NULL\)/);
  assert.match(sql, /j\."params"->'inputFileIds'/);
  assert.match(sql, /j\."result"->'outputFileIds'/);
  assert.match(sql, /STORAGE_OBJECT_API_CLIENT_CONFLICT/);
  assert.doesNotMatch(sql, /DELETE\s+FROM\s+"?storage_objects"?/i, "backfill must never silently delete orphaned storage_objects");

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
});
