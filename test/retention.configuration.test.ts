import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("retention workflow fails closed before Prisma when required configuration is absent", async () => {
  const workflow = await readFile(new URL("../.github/workflows/retention.yml", import.meta.url), "utf8");
  const scheduler = await readFile(new URL("../scripts/cleanup-expired-jobs.ts", import.meta.url), "utf8");
  for (const name of ["RETENTION_DATABASE_URL", "RETENTION_STORAGE_ENDPOINT", "RETENTION_STORAGE_BUCKET", "RETENTION_STORAGE_ACCESS_KEY", "RETENTION_STORAGE_SECRET_KEY"]) {
    assert.match(workflow, new RegExp(`for name in[\\s\\S]*${name}`));
    assert.match(workflow, new RegExp(`secrets\\.${name}`));
  }
  assert.match(workflow, /\$\{name\}_PRESENT=true/);
  assert.match(workflow, /RETENTION_APPLY_ENABLED=false/);
  assert.match(workflow, /required secret\(s\) or RETENTION_APPLY=1 are missing/);
  assert.match(scheduler, /RETENTION_DATABASE_URL_MISSING/);
  assert.match(scheduler, /\^P\\d\{4\}\$/);
});

test("retention database role remains purpose-bound and cannot bypass RLS", async () => {
  const migration = await readFile(new URL("../prisma/migrations/20260923090000_retention_scheduler_least_privilege/migration.sql", import.meta.url), "utf8");
  assert.match(migration, /CREATE ROLE dip_retention[\s\S]*NOSUPERUSER[\s\S]*NOBYPASSRLS/);
  assert.match(migration, /dip_retention is not a standalone least-privilege role/);
  assert.doesNotMatch(migration, /GRANT\s+ALL[^;]*TO dip_retention/i);
  assert.doesNotMatch(migration, /GRANT[^;]*\bDELETE\b[^;]*TO dip_retention/i);
  assert.match(migration, /GRANT UPDATE \(status, error_code, completed_at, updated_at\) ON jobs TO dip_retention/);
  for (const table of ["users", "subscriptions", "documents", "files", "jobs"]) assert.match(migration, new RegExp(`${table}_retention_`));
});
