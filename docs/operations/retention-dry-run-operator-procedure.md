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

## 3. Pre-flight: connectivity (no secrets printed)

```bash
# 3.1 Database reachability and identity. `psql` prints the role, never the URL.
psql "$DATABASE_URL" -Atc "select current_user, current_database(), version();"

# 3.2 The retention query path works under RLS with this role (counts only).
psql "$DATABASE_URL" -Atc "select count(*) from documents where status = 'ACTIVE';"
psql "$DATABASE_URL" -Atc "select count(*) from jobs where status in ('QUEUED','RUNNING','RETRYING');"

# 3.3 Redis, if configured. A read-only principal must be able to read and not write.
redis-cli -u "$REDIS_URL" PING
redis-cli -u "$REDIS_URL" --scan --pattern 'bull:dip.document-processing.v1:*' | head -n 5
redis-cli -u "$REDIS_URL" SET dip:retention:probe 1   # must be denied by a read-only ACL
```

Two-queue coverage matters: the sweep reads `bull:dip.document-processing.v1:*` **and**
`bull:dip.ai-processing.v1:*`. If the Redis principal cannot read both, evidence is `unknown` for every
candidate and the run, while safe, is not meaningful.

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
- [ ] `redis.redis_configured: true`.
- [ ] `redis.queues_expected: 2`, `redis.queues_read: 2`, `redis.failed_reads: 0`.
- [ ] `queue.queue_unknown: 0`.
- [ ] `queue.planned_expiry: 0` on a healthy fleet (any non-zero value must be explainable job-by-job).
- [ ] If `redis_configured` is `false`: the run is **safe but not meaningful** — record it as `queue evidence
      unknown` and do not treat zero candidates as evidence that nothing needs cleanup.

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
- The process exceeds the job timeout without emitting `retention.dry_run_summary`.

## 7. What this procedure does **not** establish

Completing it proves the dry-run is safe, complete and interpretable. It does **not**:

- approve apply, or any retention period;
- select an execution location (that is CR-005);
- prove the production dataset is small enough for the single-pass scan (record `scanned_documents` and
  `duration_ms` and review them against the job timeout);
- replace the separate decision that enabling apply requires, which must be its own approved change request
  after at least three green dry-runs.
