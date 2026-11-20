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
  assert.match(workflow, /required dry-run credential\(s\) are missing/);
  // The scheduler must refuse to run at all when a credential is missing, and
  // must name the missing variables without echoing values.
  assert.match(scheduler, /missingRetentionCredentials\(process\.env, apply \? "apply" : "dry_run"\)/);
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
  assert.doesNotMatch(workflow, /RETENTION_APPLY=1 are missing/);
  assert.match(scheduler, /parseRetentionApply\(process\.env\.RETENTION_APPLY\)/);
  // Only the exact string "1" may enable deletions.
  assert.match(safety, /export function parseRetentionApply\(value: string \| undefined\): boolean \{\s*return value === "1";/);
});

test("the scheduled workflow cannot enter apply mode during dry-run preparation", async () => {
  const workflow = await load(".github/workflows/retention.yml");
  const entrypoint = await load("scripts/retention-dry-run.ts");
  const dryRun = await load("src/lib/retention/dry-run.ts");
  const safety = await load("src/lib/retention/safety.ts");

  // 1. The workflow never selects a destructive mode and never passes the switch
  //    to the run step.
  assert.doesNotMatch(workflow, /RETENTION_MODE=apply/);
  assert.doesNotMatch(workflow, /npm run jobs:cleanup/);
  assert.match(workflow, /npm run retention:dry-run/);
  const runStep = workflow.slice(workflow.indexOf("name: Run retention dry-run"));
  assert.equal(/RETENTION_APPLY:\s/.test(runStep), false, "the run step must not receive RETENTION_APPLY");

  // 2. A non-dry-run variable value fails the workflow instead of enabling apply.
  assert.match(workflow, /Retention apply is disabled during dry-run preparation/);
  assert.match(workflow, /exit 1/);

  // 3. Least privilege for a job that only reads.
  assert.match(workflow, /permissions:\s*\n\s*contents: read/);

  // 4. The entrypoint itself refuses apply, before importing anything that can
  //    open a connection.
  assert.match(entrypoint, /assertDryRunAllowed\(process\.env\)/);
  assert.match(entrypoint, /parseDryRunArgs\(process\.argv\.slice\(2\)\)/);
  assert.match(safety, /RETENTION_APPLY_FORBIDDEN_IN_DRY_RUN/);
  assert.match(dryRun, /assertDryRunAllowed\(env\)/);
  assert.match(dryRun, /dryRun: true/);
});

test("the dry-run workflow requires only the read-only configuration subset", async () => {
  const workflow = await load(".github/workflows/retention.yml");
  const runStep = workflow.slice(workflow.indexOf("name: Run retention dry-run"));
  // The run receives the database URL and the bucket, and no S3 credential.
  assert.match(runStep, /DATABASE_URL: \$\{\{ secrets\.RETENTION_DATABASE_URL \}\}/);
  assert.match(runStep, /STORAGE_BUCKET: \$\{\{ secrets\.RETENTION_STORAGE_BUCKET \}\}/);
  for (const forbidden of ["STORAGE_ACCESS_KEY", "STORAGE_SECRET_KEY", "STORAGE_ENDPOINT"]) {
    assert.equal(runStep.includes(forbidden), false, `a dry-run must not be handed ${forbidden}`);
  }
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

