import crypto from "node:crypto";
import fs from "node:fs";
import pg from "pg";

const { Client } = pg;
const tenantTables = [
  "ai_usage",
  "documents",
  "file_versions",
  "files",
  "job_events",
  "job_steps",
  "jobs",
  "tool_executions",
];

async function inspect(connectionString, includeRuntimeRole) {
  const client = new Client({ connectionString });
  await client.connect();
  try {
    const migrations = await client.query(`
      SELECT migration_name, checksum,
             finished_at IS NOT NULL AS finished,
             rolled_back_at IS NOT NULL AS rolled_back,
             applied_steps_count
      FROM "_prisma_migrations"
      ORDER BY started_at
    `);
    const rls = await client.query(
      `SELECT relname, relrowsecurity, relforcerowsecurity
       FROM pg_class
       WHERE relnamespace = 'public'::regnamespace
         AND relname = ANY($1::text[])
       ORDER BY relname`,
      [tenantTables],
    );
    const policies = await client.query(`
      SELECT tablename, policyname, cmd, roles::text, qual, with_check
      FROM pg_policies
      WHERE schemaname = 'public'
      ORDER BY tablename, policyname
    `);
    const result = { migrations: migrations.rows, rls: rls.rows, policies: policies.rows };

    if (includeRuntimeRole) {
      result.role = (await client.query(`
        SELECT rolname, rolsuper, rolbypassrls, rolcanlogin, rolcreaterole,
               rolcreatedb, rolreplication, rolinherit
        FROM pg_roles WHERE rolname = 'dip_app'
      `)).rows;
      result.grants = (await client.query(`
        SELECT table_name, privilege_type
        FROM information_schema.role_table_grants
        WHERE grantee = 'dip_app' AND table_schema = 'public'
        ORDER BY table_name, privilege_type
      `)).rows;
      result.ownership = (await client.query(`
        SELECT namespace.nspname AS schema_name, object.relname AS object_name
        FROM pg_class object
        JOIN pg_roles role ON role.oid = object.relowner
        JOIN pg_namespace namespace ON namespace.oid = object.relnamespace
        WHERE role.rolname = 'dip_app'
        ORDER BY namespace.nspname, object.relname
      `)).rows;
    }
    return result;
  } finally {
    await client.end();
  }
}

const dev = await inspect(process.env.DIP_DEV_OWNER_URL, true);
const replay = await inspect(process.env.DIP_REPLAY_OWNER_URL, false);
const fileChecksum = crypto
  .createHash("sha256")
  .update(fs.readFileSync("prisma/migrations/20260909161000_security_hardening/migration.sql"))
  .digest("hex");

console.log(JSON.stringify({
  fileChecksum,
  dev,
  replay,
  rlsEquivalent: JSON.stringify(dev.rls) === JSON.stringify(replay.rls),
  policiesEquivalent: JSON.stringify(dev.policies) === JSON.stringify(replay.policies),
}, null, 2));
