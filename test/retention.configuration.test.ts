import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const load = (path: string) => readFile(new URL(`../${path}`, import.meta.url), "utf8");

test("retention workflow fails closed when required credentials are absent", async () => {
  const workflow = await load(".github/workflows/retention.yml");
  const scheduler = await load("scripts/cleanup-expired-jobs.ts");
  // A dry-run needs exactly the read-only subset: a database to read and the
  // configured bucket to compare stored metadata against.
  for (const name of ["RETENTION_DATABASE_URL", "RETENTION_STORAGE_BUCKET"]) {
    assert.match(workflow, new RegExp(`secrets\\.${name}`));
  }
  assert.match(workflow, /for name in RETENTION_DATABASE_URL RETENTION_STORAGE_BUCKET; do/);
  assert.match(workflow, /\$\{name\}_PRESENT=true/);
  assert.match(workflow, /required dry-run credential\(s\) are missing/);
  // The apply path keeps the full five-name gate: this is the behaviour the
  // dry-run relaxation must not weaken.
  assert.match(scheduler, /missingRetentionCredentials\(process\.env, apply \? "apply" : "dry_run"\)/);
  assert.match(scheduler, /RETENTION_CONFIGURATION_MISSING/);
  assert.match(scheduler, /\^P\\d\{4\}\$/);
  const safety = await load("src/lib/retention/safety.ts");
  for (const name of ["STORAGE_ENDPOINT", "STORAGE_ACCESS_KEY", "STORAGE_SECRET_KEY"]) {
    assert.match(safety, new RegExp(`"${name}"`), `the apply credential gate must still require ${name}`);
  }
});

test("the dry-run workflow references no S3 endpoint or credential anywhere", async () => {
  const workflow = await load(".github/workflows/retention.yml");
  // Not "not passed to the run step" — absent from the file entirely. A value
  // that is never injected anywhere cannot leak into a log, an artifact or a
  // child process.
  for (const forbidden of ["RETENTION_STORAGE_ENDPOINT", "RETENTION_STORAGE_ACCESS_KEY", "RETENTION_STORAGE_SECRET_KEY"]) {
    assert.equal(workflow.includes(forbidden), false, `the dry-run workflow must not reference ${forbidden}`);
  }
  for (const forbidden of ["STORAGE_ENDPOINT", "STORAGE_ACCESS_KEY", "STORAGE_SECRET_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]) {
    assert.equal(workflow.includes(forbidden), false, `the runner must not receive ${forbidden}`);
  }
  // What it does need, it needs exactly once, by name only.
  assert.equal((workflow.match(/secrets\.RETENTION_DATABASE_URL/g) ?? []).length, 2);
  assert.equal((workflow.match(/secrets\.RETENTION_STORAGE_BUCKET/g) ?? []).length, 2);
});

test("the dry-run workflow is inactive by default and needs explicit owner activation", async () => {
  const workflow = await load(".github/workflows/retention.yml");

  // 1. No automatic trigger: every cron line in the file is commented out, so
  //    merging this workflow cannot start a production-connected run.
  const activeCron = workflow
    .split("\n")
    .filter((line) => /cron:/.test(line))
    .filter((line) => !/^\s*#/.test(line));
  assert.deepEqual(activeCron, [], `no active schedule trigger may exist during preparation: ${activeCron.join(" | ")}`);
  assert.match(workflow, /#\s*schedule:/);
  assert.match(workflow, /workflow_dispatch:/);

  // 2. A fail-closed operational gate that does not depend on any credential:
  //    even with every secret present, an unset variable stops the job.
  assert.match(workflow, /vars\.RETENTION_DRY_RUN_ENABLED/);
  assert.match(workflow, /if \[ "\$RETENTION_DRY_RUN_ENABLED" != "true" \]; then/);
  assert.match(workflow, /RETENTION_DRY_RUN_ACTIVATED=false/);
  assert.match(workflow, /exit 1/);

  // 3. The gate runs before anything can touch a dependency: before checkout,
  //    before install, before any step that receives a secret.
  const gateIndex = workflow.indexOf("name: Require owner activation");
  assert.ok(gateIndex > 0, "the activation gate must exist");
  for (const later of ["actions/checkout", "npm ci", "npx prisma generate", "secrets."]) {
    assert.ok(workflow.indexOf(later) > gateIndex, `${later} must come after the activation gate`);
  }
  assert.equal(workflow.slice(0, gateIndex).includes("secrets."), false, "no credential may be injected before the gate");
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

