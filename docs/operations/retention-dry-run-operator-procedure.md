# Retention Dry-Run — Operator Readiness Procedure (read-only)

Status: **operator procedure, not an approval.** It describes how to establish that a dry-run is
meaningful *before* anyone considers deletion. Nothing here enables apply, creates a credential, or
connects to production on your behalf. Do not paste any credential value into a ticket, PR, chat or log.

Applies to: `npm run retention:dry-run` (`scripts/retention-dry-run.ts`) and, if the owner selects
Option B in [CR-005](../cr-005-retention-dry-run-execution.md), the scheduled
`Retention Dry-Run` workflow.

---

## 0. Safety contract you can rely on

| Property | Guarantee |
| --- | --- |
| Mode | The entrypoint has no apply mode. `RETENTION_APPLY=1` aborts it (`RETENTION_APPLY_FORBIDDEN_IN_DRY_RUN`); any apply-shaped CLI argument is rejected (`RETENTION_DRY_RUN_ARGUMENT_REJECTED:…`). |
| Database writes | None. The planner only reads; a non-zero mutation counter aborts the run (`RETENTION_DRY_RUN_MUTATED`). |
| Object storage | Never contacted, and no S3 client is constructed. An S3 endpoint/key pair is not required. |
| Job lifecycle | Dry-run plans expiry and applies nothing (`jobs_expired_applied: 0`; `expired_jobs` is a **plan** count). |
| Scope | Deletions would only ever target objects whose `provider`/`bucket` match `STORAGE_BUCKET` — checked from metadata even in a dry-run, so a mismatch is visible now (`scope_blocked_documents`). |

---

## 1. Configuration names (names only — never values)

A dry-run requires **two** values. Apply additionally requires the three object-storage values, which are
deliberately **not** needed here.

| Variable | Dry-run | Apply | Purpose |
| --- | --- | --- | --- |
| `DATABASE_URL` | **required** | required | Connects as `dip_retention` (never the owner, never `dip_app`). |
| `STORAGE_BUCKET` | **required** | required | The one bucket a deletion would be allowed to touch; used for metadata scope checks. |
| `STORAGE_ENDPOINT` | not needed | required | S3 endpoint. |
| `STORAGE_ACCESS_KEY` | not needed | required | S3 access key (delete-capable today). |
| `STORAGE_SECRET_KEY` | not needed | required | S3 secret key. |
| `STORAGE_REGION` | not needed | optional | S3 signature region (default `us-east-2`). |
| `REDIS_URL` | optional | optional | Queue liveness evidence. **Absent ⇒ `unknown` ⇒ nothing may expire.** |
| `RETENTION_APPLY` | must be unset/`0` | `1` | Not passed to the dry-run entrypoint. |
| `NODE_ENV` | leave unset | leave unset | Setting `production` makes the app env contract require `REDIS_URL` **and** `NEXT_PUBLIC_APP_URL`, and the run fails if either is missing. |

The GitHub workflow supplies `RETENTION_DATABASE_URL` → `DATABASE_URL` and
`RETENTION_STORAGE_BUCKET` → `STORAGE_BUCKET`; it prints `*_PRESENT=true|false` for all five names so you can
see what exists without any value being shown.

---

## 2. Pre-flight: identity and least privilege (read-only SQL)

Run as the database owner, not as `dip_retention`. Every query below is a catalog read.

```sql
-- 2.1 The role exists, can log in, and is not privileged.
SELECT rolname, rolcanlogin, rolsuper, rolbypassrls, rolinherit, rolcreatedb, rolcreaterole
FROM pg_roles WHERE rolname = 'dip_retention';
-- expect: canlogin=t, super=f, bypassrls=f, inherit=f, createdb=f, creatrole=f

-- 2.2 No role memberships (a membership would leak other privileges).
SELECT granted.rolname AS granted_role
FROM pg_auth_members m
JOIN pg_roles granted ON granted.oid = m.roleid
JOIN pg_roles member ON member.oid = m.member
WHERE member.rolname = 'dip_retention';
-- expect: zero rows

-- 2.3 Exactly the reads and column updates the sweep needs.
SELECT
  has_table_privilege('dip_retention','documents','SELECT')       AS documents_select,      -- t
  has_table_privilege('dip_retention','documents','UPDATE')       AS documents_update,      -- t
  has_table_privilege('dip_retention','jobs','SELECT')            AS jobs_select,           -- t
  has_table_privilege('dip_retention','storage_objects','SELECT') AS storage_objects_select,-- t
  has_table_privilege('dip_retention','jobs','DELETE')            AS jobs_delete,           -- f
  has_table_privilege('dip_retention','documents','DELETE')       AS documents_delete,      -- f
  has_table_privilege('dip_retention','api_keys','SELECT')        AS api_keys_select;       -- f

-- 2.4 Column-level grants are limited to what cleanup writes.
SELECT table_name, privilege_type, column_name
FROM information_schema.column_privileges
WHERE grantee = 'dip_retention'
ORDER BY table_name, privilege_type, column_name;

-- 2.5 The cross-tenant policies exist and apply to this role.
SELECT tablename, policyname, cmd
FROM pg_policies
WHERE schemaname = 'public' AND 'dip_retention' = ANY(roles)
ORDER BY tablename, cmd;
```

If 2.1–2.5 do not match the expectations above, **stop**: the credential is not the least-privilege one the
runbook requires, and a dry-run would produce evidence that does not describe the apply path.

## 3. Pre-flight: connectivity (read-only, no secrets printed)

**Rule for every command in this section:** nothing here may write, and no credential may appear in a
command line. A URL passed as an argument is visible in `ps`/process listings, in shell history and in
terminal scrollback; use environment variables or a credentials file instead.

### 3.1 Database reachability and identity

Prefer the discrete `PG*` variables over `psql "$DATABASE_URL"`, so the password never enters `argv`:

```bash
# The values come from the secret manager, never from this document.
# PGPASSWORD=<scheduler password>  PGHOST/PGPORT/PGUSER/PGDATABASE=<scope values>
psql -X -A -t -c "select current_user, current_database();"
```

`psql` prints the role and the database, never the credential. If your environment only provides a single
URL, `psql -X -A -t "$DATABASE_URL" -c …` is acceptable for an interactive session but leaks the password to
the process table; do not use it in anything recorded, scripted or shared.

### 3.2 The retention query path works under RLS with this role (counts only)

```bash
psql -X -A -t -c "select count(*) from documents where status = 'ACTIVE';"
psql -X -A -t -c "select count(*) from jobs where status in ('QUEUED','RUNNING','RETRYING');"
```

### 3.3 Redis, if configured — non-mutating only

```bash
# Authentication is supplied by environment, not by an argument:
#   REDISCLI_AUTH=<read-only password>  redis-cli -h <host> -p <port> --user <read-only user>
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" --user "$REDIS_USER" PING
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" --user "$REDIS_USER" ACL WHOAMI
```

What these establish: `PING` proves a bounded round trip reaches Redis (this is exactly the probe the sweep
performs, so a green `PING` is what `redis.connectivity: "VERIFIED"` will mean); `ACL WHOAMI` proves which
principal is in use, without printing a credential.

**Deliberately absent — do not add these to a production procedure:**

- `SET`, `DEL`, `FLUSH*`, `EXPIRE`, `EVAL`, `FUNCTION LOAD` or any other write: a "probe" that writes is a
  production mutation, and it is the one operation that turns a connectivity check into an incident when an
  ACL is misconfigured.
- `SCAN`/`KEYS` output pasted into a ticket: live job keys are tenant work items. The sweep never prints a
  key, and neither should the operator.
- `SET …` (or any write) as an **ACL-denial test**: denial must be proven in isolated test infrastructure,
  never against production. In an isolated environment only, `ACL DRYRUN <user> SET probe 1` (Redis 7.0+)
  evaluates permissions without executing the command; it is still not a production command.
- `redis-cli -u "$REDIS_URL"`: the URL carries the password into `argv`.

If a read-only principal cannot run `PING`, the sweep reports `redis.connectivity: "UNAVAILABLE"` rather
than claiming health. `PING` is not a data command; grant it (`+ping`) instead of weakening the procedure.

Two-queue coverage matters: the sweep reads `bull:dip.document-processing.v1:*` **and**
`bull:dip.ai-processing.v1:*`. If the Redis principal cannot read both, evidence is `INCOMPLETE` or
`UNAVAILABLE` and the run, while safe, is not meaningful.

### 3.4 What the sweep will report about its own evidence

The report separates *reachability* from *completeness*, because they answer different questions:

| `redis.connectivity` | Meaning |
| --- | --- |
| `VERIFIED` | A bounded `PING` round trip succeeded. |
| `UNAVAILABLE` | Unconfigured, unreachable, or the probe was denied/timed out. |
| `NOT_CHECKED` | The provider has no probe (test seam only). |

| `redis.queue_evidence` | Meaning |
| --- | --- |
| `VERIFIED` | Every configured queue (2) was read to completion in this run. |
| `INCOMPLETE` | A queue read failed, or fewer queues answered than expected. |
| `NOT_CHECKED` | There were zero job candidates, so no queue read was needed — reachability may still be `VERIFIED`. |
| `UNAVAILABLE` | No usable connection: unconfigured, or the probe failed. |

`queues_read` counts reads that **completed**, never readers that were constructed. During a quiet window
expect `queue_evidence: "NOT_CHECKED"` with `reads_attempted: 0`; that is honest, not a success.

## 4. Run the dry-run

```bash
# Interactive, capturing the aggregate report as evidence:
npm run retention:dry-run -- --summary-json=/tmp/retention-dry-run-$(date -u +%Y%m%dT%H%M%SZ).json
```

The report is aggregate-only: counts, policy constants and fixed status strings. It contains no document
id, file id, object key, filename, owner, email, host, URL or credential, so it is safe to attach to a
ticket. Expected exit codes: `0` clean dry-run, `1` any failure (configuration, connectivity, or the
mutation self-check).

Baseline capture for the zero-mutation check (run immediately before and after, in a quiet window):

```sql
SELECT 'documents' AS t, status::text, count(*) FROM documents GROUP BY 1,2
UNION ALL SELECT 'jobs', status::text, count(*) FROM jobs GROUP BY 1,2
UNION ALL SELECT 'storage_objects_deleted', 'deleted', count(*) FROM storage_objects WHERE deleted_at IS NOT NULL;
```

## 5. Acceptance criteria

A dry-run is meaningful only when **all** of these hold. Anything else is a finding, not a pass.

### A. Identity and configuration
- [ ] `current_user` is `dip_retention`; §2 checks match.
- [ ] Run exits `0`; `mode: "dry_run"`.
- [ ] `policy_version: 2026-09-provisional-v2`, `retention_days: { free: 7, pro: 30 }` (unchanged periods).

### B. Redis evidence completeness
- [ ] `redis.redis_configured: true` and `redis.connectivity: "VERIFIED"`.
- [ ] `redis.queue_evidence` is `"VERIFIED"` — i.e. `redis.queues_expected: 2`, `redis.reads_attempted: 2`,
      `redis.queues_read: 2`, `redis.failed_reads: 0`.
- [ ] If `redis.queue_evidence` is `"NOT_CHECKED"` because `redis.candidates_scanned: 0`, the run proves
      reachability only. Record it as *connectivity verified, queue completeness not exercised*, and repeat
      after a window in which at least one job exists if queue completeness must be demonstrated.
- [ ] `redis.queue_evidence` of `"INCOMPLETE"` or `"UNAVAILABLE"` is a finding: the run is **safe but not
      meaningful**, `queue.queue_unknown` will be non-zero, and zero candidates must not be read as proof
      that nothing needs cleanup.
- [ ] `queue.queue_unknown: 0`.
- [ ] `queue.planned_expiry: 0` on a healthy fleet (any non-zero value must be explainable job-by-job).
- [ ] If `redis_configured` is `false`: record the run as `queue evidence unknown`; it establishes document
      retention candidates only.

### C. Retention candidates
- [ ] `candidates.scanned_documents` equals an independent `select count(*) from documents where status='ACTIVE'`.
- [ ] `scanned_documents = candidate_documents + skipped_documents`.
- [ ] `candidate_documents = candidate_documents_free + candidate_documents_pro`.
- [ ] `candidate_documents` and the per-plan split reproduce an independent owner-side recount (same quiet window).
- [ ] `missing_object_documents` is `0` or explained: a file without a `storage_object_id` can never be reclaimed.
- [ ] `scope_blocked_documents` is `0`. Non-zero means `STORAGE_BUCKET` no longer matches what the application
      writes — resolve before any thought of apply.
- [ ] `retained_documents`, `protected_documents`, `missing_object_documents` and `scope_blocked_documents`
      are read as **document** counts (the legacy `*_files` names in the plan are per-document counters).

### D. Zero mutations
- [ ] `mutations.objects_deleted`, `documents_tombstoned`, `storage_operations`, `metadata_mutations` and
      `jobs_expired_applied` are all `0`, and `zero_mutations: true`.
- [ ] No `jobs.expired_cleanup` event appears (that event only exists on the apply path).
- [ ] Before/after snapshot from §4 is identical **after** attributing any difference to concurrent
      application traffic. Prefer a quiet window; if the environment is busy, prefer the structural proof
      below.
- [ ] **Structural proof (preferred):** run the same dry-run against a SELECT-only variant of the credential
      (or with `UPDATE` temporarily revoked from `dip_retention` in a non-production replica). The run must
      still succeed, which proves no write was attempted. This is stronger than observing unchanged counts.

### E. Diagnostics quality
- [ ] Report contains `redis`, `queue`, `candidates`, `mutations`, `zero_mutations`, `policy_version`,
      `retention_days`, `duration_ms`.
- [ ] No Prisma `query`-level logging (only active when `NODE_ENV=development`).
- [ ] No identifiers or secrets anywhere in the report or logs.
- [ ] `duration_ms` and `scanned_documents` recorded as the first signal for scan-cost planning.

## 6. Abort conditions

Stop and treat the run as failed if any of the following appears:

- `zero_mutations: false`, `RETENTION_DRY_RUN_MUTATED`, or any non-zero mutation counter.
- `RETENTION_APPLY_FORBIDDEN_IN_DRY_RUN` (something in the environment is asking for apply).
- `jobs.expired_cleanup` in the logs.
- `scope_blocked_documents > 0` with no explanation.
- `current_user` is anything other than `dip_retention`.
- `redis.connectivity: "UNAVAILABLE"` when a Redis principal was supposed to be provisioned.
- The activation gate was bypassed (a run whose log does not contain `RETENTION_DRY_RUN_ACTIVATED=true`).
- The process exceeds the job timeout without emitting `retention.dry_run_summary`.

## 7. Activating the scheduled workflow (documented; **not executed** by this PR)

The scheduled workflow is **inactive by default** and merging code does not activate it. Two independent
things must be true before a production-connected run can happen:

1. **The cron is disabled in the workflow file.** During preparation the `schedule:` trigger is commented
   out, so no automatic run exists at all. Re-enabling it is a reviewed change, not a variable edit.
2. **The owner-activation variable is absent.** The job's first step requires the repository variable
   `RETENTION_DRY_RUN_ENABLED` to equal `true`; anything else (including "not created") fails the job before
   checkout and before any credential is injected. No variable is created by this PR.

Activation sequence — performed **only** by the owner, after CR-005 is approved:

- [ ] Record approval in `docs/cr-005-retention-dry-run-execution.md` (the approval block is intentionally blank).
- [ ] Confirm §2 (identity/privileges) and §3 (connectivity) pass from the chosen execution location.
- [ ] Create repository variable `RETENTION_DRY_RUN_ENABLED=true` (a *variable*, never a secret; it carries no value).
- [ ] For a manually triggered run: **Actions → Retention Dry-Run → Run workflow** — nothing is dispatched automatically.
- [ ] For a scheduled run: merge a reviewed change that re-enables the `schedule:` block.
- [ ] After the first run, confirm the log contains `RETENTION_DRY_RUN_ACTIVATED=true` and a
      `retention.dry_run_summary` with `zero_mutations: true`.

Deactivation is the reverse and takes effect immediately: delete or set `RETENTION_DRY_RUN_ENABLED` to any
value other than `true`. The workflow then fails closed at step one.

## 8. What this procedure does **not** establish

Completing it proves the dry-run is safe, complete and interpretable. It does **not**:

- approve apply, or any retention period;
- select an execution location (that is CR-005);
- prove the production dataset is small enough for the single-pass scan (record `scanned_documents` and
  `duration_ms` and review them against the job timeout);
- replace the separate decision that enabling apply requires, which must be its own approved change request
  after at least three green dry-runs.
