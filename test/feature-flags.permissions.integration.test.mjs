import assert from "node:assert/strict";
import test from "node:test";
import pg from "pg";

const integration = process.env.DIP_RLS_TEST_DATABASE_URL && process.env.DIP_RLS_TEST_OWNER_URL ? test : test.skip;

integration("dip_app reads global feature flags but cannot mutate system configuration", async () => {
  const owner = new pg.Client({ connectionString: process.env.DIP_RLS_TEST_OWNER_URL });
  const runtime = new pg.Client({ connectionString: process.env.DIP_RLS_TEST_DATABASE_URL });
  const key = `release-b-permission-${Date.now()}`;
  await Promise.all([owner.connect(), runtime.connect()]);
  try {
    await owner.query("INSERT INTO feature_flags (id, key, enabled, updated_at) VALUES (gen_random_uuid(), $1, true, now())", [key]);
    const role = await runtime.query("SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname = current_user");
    assert.deepEqual(role.rows, [{ rolsuper: false, rolbypassrls: false, rolcreatedb: false, rolcreaterole: false }]);
    assert.deepEqual((await runtime.query("SELECT key, enabled FROM feature_flags WHERE key = $1", [key])).rows, [{ key, enabled: true }]);
    for (const statement of [
      "INSERT INTO feature_flags (id, key, enabled, updated_at) VALUES (gen_random_uuid(), 'forbidden', true, now())",
      "UPDATE feature_flags SET enabled = false WHERE key = 'forbidden'",
      "DELETE FROM feature_flags WHERE key = 'forbidden'",
    ]) await assert.rejects(runtime.query(statement), (error) => error?.code === "42501");
    await assert.rejects(runtime.query("SELECT * FROM security_events LIMIT 1"), (error) => error?.code === "42501");
  } finally {
    await owner.query("DELETE FROM feature_flags WHERE key = $1", [key]).catch(() => undefined);
    await Promise.allSettled([runtime.end(), owner.end()]);
  }
});
