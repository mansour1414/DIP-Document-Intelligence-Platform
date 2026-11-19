import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const load = (path: string) => readFile(new URL(`../${path}`, import.meta.url), "utf8");

test("retention workflow fails closed when required credentials are absent", async () => {
  const workflow = await load(".github/workflows/retention.yml");
  const scheduler = await load("scripts/cleanup-expired-jobs.ts");
  for (const name of ["RETENTION_DATABASE_URL", "RETENTION_STORAGE_ENDPOINT", "RETENTION_STORAGE_BUCKET", "RETENTION_STORAGE_ACCESS_KEY", "RETENTION_STORAGE_SECRET_KEY"]) {
    assert.match(workflow, new RegExp(`for name in[\\s\\S]*${name}`));
    assert.match(workflow, new RegExp(`secrets\\.${name}`));
  }
  assert.match(workflow, /\$\{name\}_PRESENT=true/);
  assert.match(workflow, /required credential\(s\) are missing/);
  // The scheduler must refuse to run at all when a credential is missing, and
  // must name the missing variables without echoing values.
  assert.match(scheduler, /missingRetentionCredentials\(process\.env\)/);
  assert.match(scheduler, /RETENTION_CONFIGURATION_MISSING/);
  assert.match(scheduler, /\^P\\d\{4\}\$/);
});

test("retention dry-run does not require RETENTION_APPLY=1 and defaults to disabled", async () => {
  const workflow = await load(".github/workflows/retention.yml");
  const scheduler = await load("scripts/cleanup-expired-jobs.ts");
  const safety = await load("src/lib/retention/safety.ts");
  // A dry-run is a valid, successful mode: the flag selects the mode instead of
  // failing the job.
  assert.match(workflow, /RETENTION_MODE=dry_run/);
  assert.match(workflow, /RETENTION_MODE=apply/);
  assert.doesNotMatch(workflow, /RETENTION_APPLY=1 are missing/);
  assert.match(scheduler, /parseRetentionApply\(process\.env\.RETENTION_APPLY\)/);
  // Only the exact string "1" may enable deletions.
  assert.match(safety, /export function parseRetentionApply\(value: string \| undefined\): boolean \{\s*return value === "1";/);
});

test("retention database role remains purpose-bound and cannot bypass RLS", async () => {
  const migration = await load("prisma/migrations/20260923090000_retention_scheduler_least_privilege/migration.sql");
  assert.match(migration, /CREATE ROLE dip_retention[\s\S]*NOSUPERUSER[\s\S]*NOBYPASSRLS/);
  assert.match(migration, /dip_retention is not a standalone least-privilege role/);
  assert.doesNotMatch(migration, /GRANT\s+ALL[^;]*TO dip_retention/i);
  assert.doesNotMatch(migration, /GRANT[^;]*\bDELETE\b[^;]*TO dip_retention/i);
  assert.match(migration, /GRANT UPDATE \(status, error_code, completed_at, updated_at\) ON jobs TO dip_retention/);
  for (const table of ["users", "subscriptions", "documents", "files", "jobs"]) assert.match(migration, new RegExp(`${table}_retention_`));
});

