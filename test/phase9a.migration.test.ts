import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
const sql = readFileSync(new URL("../prisma/migrations/20260914120000_phase9a_business_api_foundation/migration.sql", import.meta.url), "utf8");

test("Phase 9A migration scopes business tables and forces RLS", () => {
  for (const table of ["organizations", "memberships", "api_clients", "api_keys", "api_idempotency_records"]) { assert.match(sql, new RegExp(`ALTER TABLE \\\"${table}\\\" ENABLE ROW LEVEL SECURITY`)); assert.match(sql, new RegExp(`ALTER TABLE \\\"${table}\\\" FORCE ROW LEVEL SECURITY`)); }
  assert.match(sql, /app\.current_organization_id/); assert.match(sql, /app\.current_api_client_id/);
});
test("API credentials have client/account constraints without destructive legacy reset", () => { assert.match(sql, /api_keys_api_client_organization_fkey/); assert.match(sql, /api_keys_business_scope_check/); assert.match(sql, /api_idempotency_records_api_client_id_idempotency_key_key/); assert.doesNotMatch(sql, /DROP TABLE|TRUNCATE/i); });
test("authentication candidate is narrow and security-definer functions are locked down", () => { assert.match(sql, /api_key_auth_candidate/); assert.match(sql, /SECURITY DEFINER SET search_path = pg_catalog, public/); assert.match(sql, /REVOKE ALL ON FUNCTION api_key_auth_candidate\(text\) FROM PUBLIC/); });
test("audit policy binds organization context and keeps secrets out of lifecycle metadata", () => { assert.match(sql, /DROP POLICY IF EXISTS audit_logs_tenant_insert_policy/); assert.match(sql, /organization_id = NULLIF\(current_setting\('app.current_organization_id'/); const clients = readFileSync(new URL("../src/lib/api-platform/clients.ts", import.meta.url), "utf8"); assert.doesNotMatch(clients, /details:\s*\{[^}]*keyHash|details:\s*\{[^}]*plaintext/); });
