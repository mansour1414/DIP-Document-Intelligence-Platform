import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

test("feature flags remain global, read-only runtime configuration", async () => {
  const schema = await readFile(new URL("../prisma/schema.prisma", import.meta.url), "utf8");
  const migration = await readFile(new URL("../prisma/migrations/20260915110000_release_b_feature_flags_runtime_read/migration.sql", import.meta.url), "utf8");
  const grants = await readFile(new URL("../prisma/bootstrap/dip_app.sql", import.meta.url), "utf8");
  const model = schema.match(/model FeatureFlag \{[\s\S]*?\n\}/)?.[0] ?? "";
  assert.doesNotMatch(model, /userId|organizationId|tenantId/);
  assert.match(migration, /REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON feature_flags FROM dip_app/);
  assert.match(migration, /GRANT SELECT ON feature_flags TO dip_app/);
  assert.match(grants, /GRANT SELECT ON plans, plan_entitlements, ai_provider_prices, feature_flags TO dip_app/);
  assert.doesNotMatch(migration, /BYPASSRLS|DISABLE ROW LEVEL SECURITY|GRANT ALL/i);
  assert.match(grants, /OR rolbypassrls/);
});
