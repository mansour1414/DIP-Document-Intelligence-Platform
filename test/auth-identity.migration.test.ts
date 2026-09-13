import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const migration = readFileSync(new URL("../prisma/migrations/20260912170000_cr003_auth_identity_rls/migration.sql", import.meta.url), "utf8");
const grants = readFileSync(new URL("../prisma/bootstrap/dip_app.sql", import.meta.url), "utf8");

test("CR-003 enables users RLS with separate authenticated and pre-auth scopes", () => {
  assert.match(migration, /ALTER TABLE "users" ENABLE ROW LEVEL SECURITY/);
  assert.match(migration, /users_authenticated_select/);
  assert.match(migration, /app\.current_user_id/);
  assert.match(migration, /users_auth_email_select/);
  assert.match(migration, /users_auth_email_insert/);
  assert.match(migration, /app\.auth_email/);
  assert.doesNotMatch(migration, /FOR (?:UPDATE|DELETE)/);
});

test("dip_app receives only SELECT and INSERT on users", () => {
  assert.match(grants, /GRANT SELECT, INSERT ON users TO dip_app/);
  assert.doesNotMatch(grants, /GRANT[^;]*(?:UPDATE|DELETE)[^;]*ON users/i);
});
