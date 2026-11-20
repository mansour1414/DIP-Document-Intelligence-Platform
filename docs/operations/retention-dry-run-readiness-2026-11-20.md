# Retention Dry-Run — Operational Readiness Audit

**Date:** 2026-11-20
**Scope:** first production-connected **Retention DRY-RUN** (no apply, no deletion)
**Verified `main`:** `2afc3684fd92dcd70723f66dbd5c35e1d390d1bc`

> **Readiness record — pre-change audit.** This document captures the state of `main` at
> `2afc368` before the dry-run preparation change. Its *code-readiness* findings (V2–V4: no Redis
> wiring, an apply-only S3 credential demanded by a read-only path, no dry-run-only entrypoint) are
> implemented in the pull request that adds `docs/cr-005-retention-dry-run-execution.md`; the
> *operational-readiness* blockers (V1, V5, V6 and the unknown list) are unchanged and remain open.
> The proposed change request is **CR-005**; `CR-004` is unrelated and already assigned.

**Status:** read-only audit artifact. It records findings and a proposed plan only. Nothing in it has been provisioned, enabled, dispatched, deployed, committed or merged. Nothing in it changes an approved policy or architecture.

---

## 1. Verdict

### **NO-GO** for a production-connected dry-run today.

The *code path* is ready and provably non-mutating. The *operational envelope* is not: the credential set is incomplete, the queue-evidence input is not wired at all, the dry-run demands a write-capable object-storage credential it never uses, and there is no human gate between a "safe" scheduled run and a destructive one.

**GO** for the preparatory work in §10 (provisioning + one small hardening PR + one CR). Re-assess when the six verified blockers in §9 are closed.

**No dry-run has ever executed in this repository.** 54 of 54 scheduled runs since `2026-09-27T08:18:59Z` failed at the step *"Validate retention configuration"* (`gh run list --workflow=retention.yml`, read-only; spot-checked run `44505962524`, `42795199945`, `42996138107` — all fail at step 6, and *"Run npm run jobs:cleanup"* is skipped). There are zero `workflow_dispatch` runs. The fail-closed gate is therefore working exactly as designed — but it also means the "review at least one successful dry run before enabling apply" requirement in `docs/operator-runbook.md:28` has **never** been satisfiable to date.

---

## 2. What was inspected, and how

| Artifact | Method |
| --- | --- |
| `.github/workflows/retention.yml` | full read |
| `src/lib/retention/*` (config, service, safety, job-expiry, expiry-write, plan, policy, queue-connection, queue-activity) | full read |
| `scripts/cleanup-expired-jobs.ts`, `scripts/configure-role-password.mjs` | full read |
| `src/lib/env.ts`, `src/lib/db/index.ts`, `src/lib/storage/index.ts`, `src/lib/logging`, `src/lib/observability/metrics.ts`, `src/lib/runtime/config.ts`, `src/lib/queue/index.ts` | full read |
| `prisma/migrations/20260923090000_retention_scheduler_least_privilege`, RLS migrations, `prisma/bootstrap/*.sql`, `prisma/schema.prisma` | full read |
| `docs/operator-runbook.md`, `docs/phase-6-operations.md`, `docs/production-readiness.md`, `docs/phase-6-report.md`, `workers/README.md`, `.env.example` | read |
| CI workflows | read |
| GitHub state | read-only API: repo metadata, workflow run list/jobs, environments, secret **names** (403) |

Not executed: the scheduler, the workflow, any cleanup, any migration, any SQL against a real database, any object-storage call. No credential value was read or written. No file in this repository was modified except this new document.

---

## 3. Verified facts

Each item is a statement that follows directly from the code or from read-only GitHub data.

| # | Fact | Evidence |
| --- | --- | --- |
| F1 | Dry-run is strictly read-only. `runRetentionCleanup` builds the plan, logs an aggregate summary and `return`s before any `updateMany`, `storageObject.update`, `document.update` or `deleteObject`. `planStalledJobExpiry` only reads. | `src/lib/retention/service.ts:170-197`, `scripts/cleanup-expired-jobs.ts:198-214, 256-279` |
| F2 | Apply is opt-in on the exact string `"1"`. Unset, empty, `"0"`, `"true"` all resolve to dry-run. | `src/lib/retention/safety.ts:38-40` |
| F3 | The scheduler **requires** five environment variables before it touches Prisma or storage, and fails with `RETENTION_CONFIGURATION_MISSING:<names>` — names only, never values. | `src/lib/retention/safety.ts:19-31`, `scripts/cleanup-expired-jobs.ts:256-258, 281-292` |
| F4 | Three of those five are object-storage credentials, but **the dry-run never calls the object store**. `runRetentionCleanup` still constructs the storage client (`getStorage()`) *before* branching on `dryRun`. | `service.ts:174`; `src/lib/storage/index.ts:22-26, 54` |
| F5 | **`REDIS_URL` is not supplied by the workflow.** With it absent, `openRetentionRedis()` returns `connection: null`, logs `retention.redis_not_configured`, and every job candidate becomes `unknown`. `unknown` can never authorise expiry. | `.github/workflows/retention.yml:52-61`; `src/lib/retention/queue-connection.ts:63-74`; `src/lib/retention/job-expiry.ts:157-186` |
| F6 | The graceful "degrade to unknown" behaviour of F5 only exists while `NODE_ENV` is **not** `production`. `readEnvironment()` throws in production if `DATABASE_URL`, `REDIS_URL` or `NEXT_PUBLIC_APP_URL` is missing, and it is called from both `openRetentionRedis()` and `createS3Storage()`. So adding `NODE_ENV=production` to the workflow without wiring `REDIS_URL` and `NEXT_PUBLIC_APP_URL` converts a degraded dry-run into a hard failure. | `src/lib/env.ts:1-10`; `queue-connection.ts:64`; `storage/index.ts:23`; `retention.yml` (no `NODE_ENV`, no `REDIS_URL`, no `NEXT_PUBLIC_APP_URL`) |
| F7 | `expired_jobs` in `retention.scheduler_result` is the **planned** count, not an applied count — in dry-run *and* in apply. It must not be read as "rows mutated". | `scripts/cleanup-expired-jobs.ts:262-278` |
| F8 | `candidate_documents = candidate_documents_free + candidate_documents_pro` and `scanned_documents = candidate_documents + skipped_documents` are structural invariants of `planRetention`. | `src/lib/retention/safety.ts:181-226` |
| F9 | `retained_files`, `protected_files`, `missing_object_files` and `scope_blocked_files` are incremented **once per skipped document**, not per file, despite the names. `candidate_files` *is* per file. Any acceptance threshold must read these four as document counts. | `safety.ts:211-218` vs `:223` |
| F10 | Only **input** retention is implemented. `failedJobDays`, `tempHours`, `auditDays`, `billingDays` and `outputDays` are declared in the policy object and asserted in tests but are never read by any runtime code path. A "retention dry-run" today covers *expired ACTIVE document inputs* plus *stuck-job expiry*. | `src/lib/retention/config.ts:7-14`; `plan.ts:31-40`; grep across `src`, `scripts`, `workers` |
| F11 | The dedicated role `dip_retention` is created least-privilege and revalidated on every migration: `LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION`, no role memberships, no `DELETE`, no blanket grants, column-scoped `UPDATE` on exactly `jobs`, `documents`, `storage_objects`. | `prisma/migrations/20260923090000_.../migration.sql:4-39` |
| F12 | Cross-tenant reads are granted by six explicitly named policies (`users`, `subscriptions`, `documents` SELECT+UPDATE, `files`, `jobs` SELECT+UPDATE). `storage_objects` has **no** RLS and a plain `SELECT` grant, so scope classification can read `provider`/`bucket`. `plans` has no RLS. | same migration `:41-54`; `prisma/schema.prisma:266-282` |
| F13 | `dip_retention` has **no password-provisioning tool**. The only provisioning script hardcodes `ALTER ROLE dip_app` and refuses to run unless the database is `neondb` and the operator is `neondb_owner`. | `scripts/configure-role-password.mjs:14-20` |
| F14 | The migration that creates `dip_retention` must be applied by a role with `CREATEROLE` (the bootstrap flow assumes `neondb_owner`). Whether it has been applied in production is not observable from this repository. | migration `:4-10`; `scripts/configure-role-password.mjs:15` |
| F15 | The scheduler is **not present in the worker image**. `Dockerfile.worker` copies `src`, `workers` and exactly two `scripts/*` files; `scripts/cleanup-expired-jobs.ts` is not among them. `tsx` is a production dependency, so only the copy step is missing. | `Dockerfile.worker:49-56`; `package.json:22, 47` |
| F16 | The workflow has no `permissions:` block, no `environment:`, no `workflow_dispatch` inputs, and actions pinned by moving tag (`@v5`), while holding production credentials. | `retention.yml:1-61` |
| F17 | The repository has **zero GitHub Environments** (no required reviewers, no environment-scoped secrets). Apply is toggled solely by the repository variable `vars.RETENTION_APPLY`. One variable edit flips the *scheduled* run from dry-run to destructive, with no approval step and no PR trail. | `gh api .../environments` → `{"total_count":0}`; `retention.yml:45-51, 61` |
| F18 | The repository is **public**. Workflow logs are therefore public, and the workflow/its config contract is public. | `gh repo view --json isPrivate` → `false` |
| F19 | Secrets are repo-scoped: they are readable by any workflow in the repository, and `workflow_dispatch` executes the workflow file **from the selected branch**, so a dispatch from a feature branch runs that branch's code with production secrets. | `retention.yml:6`; GitHub dispatch semantics |
| F20 | `loadDocuments` reads **every** `ACTIVE` document with all files, storage objects, users, subscriptions and plans in a single un-paginated Prisma query, and `loadCandidates` reads jobs the same way. Cost grows linearly with tenant data inside a 20-minute job timeout. | `service.ts:68-89`; `scripts/cleanup-expired-jobs.ts:50-74`; `retention.yml:17` |
| F21 | Earlier evidence (PR #26) reports the dry-run verified end-to-end against real PostgreSQL 17.5 replaying all 12 migrations **as `dip_retention`**, with `STATE_UNCHANGED: true` and zero storage calls. That is schema/behaviour evidence, not production evidence. | PR #26 body |
| F22 | The retention policy is still explicitly provisional (`2026-09-provisional-v2`, `provisional: true`). | `config.ts:3-6`; `docs/phase-6-report.md:15` |

---

## 4. Execution contract

### 4.1 Environment variables the scheduler actually consumes

| Variable | Consumed by | Required? | Provided today by `retention.yml` | Notes |
| --- | --- | --- | --- | --- |
| `DATABASE_URL` | Prisma (`src/lib/db/index.ts:12`) | **yes** (gate) | ✅ `secrets.RETENTION_DATABASE_URL` | must be `dip_retention`, not owner/`dip_app` |
| `REDIS_URL` | `openRetentionRedis()` | **effectively yes** for a meaningful run; nominally optional | ❌ **absent** | see F5/F6 |
| `STORAGE_ENDPOINT` | `readEnvironment().storage` | yes (gate) | ✅ | unused in dry-run (F4) |
| `STORAGE_BUCKET` | scope + adapter | yes (gate) | ✅ | unused in dry-run |
| `STORAGE_ACCESS_KEY` | S3 client | yes (gate) | ✅ | **delete-capable today** |
| `STORAGE_SECRET_KEY` | S3 client | yes (gate) | ✅ | **delete-capable today** |
| `STORAGE_REGION` | S3 signature | no (default `us-east-2`) | `vars.RETENTION_STORAGE_REGION` | silently wrong region = apply-time signature errors, not dry-run |
| `RETENTION_APPLY` | mode switch | no | `vars.RETENTION_APPLY` | must stay unset/`0` |
| `NODE_ENV` | `readEnvironment` gate, Prisma log level | no | ❌ absent | unset ⇒ env fail-fast disabled (F6) |
| `NEXT_PUBLIC_APP_URL` | `readEnvironment` | only under `NODE_ENV=production` | ❌ absent | blocks F6 remediation |

Note: `readEnvironment()` also accepts `AWS_*` / `S3_DOCUMENTS_BUCKET` aliases, but the credential gate in `safety.ts` checks only the `STORAGE_*` names — do not mix them, or the gate passes while the adapter silently reads different values.

### 4.2 Roles and permissions

| Principal | Needed now | Needed for apply | State |
| --- | --- | --- | --- |
| PostgreSQL `dip_retention` | CONNECT, USAGE on `public`, SELECT on `users, plans, subscriptions, documents, files, jobs, storage_objects` | + column `UPDATE` on `jobs(status, error_code, completed_at, updated_at)`, `documents(status, updated_at)`, `storage_objects(deleted_at)` — **already granted** | granted by migration; **no password provisioning path** (F13), **apply status unknown** (F14) |
| Redis principal | `HMGET bull:<queue>:<id> {timestamp,processedOn,finishedOn}`, `EXISTS bull:<queue>:<id>:lock` on `bull:dip.document-processing.v1:*` and `bull:dip.ai-processing.v1:*` | same (read-only is sufficient) | ❌ no Redis credential, no ACL design, no read-only user defined anywhere |
| Object storage principal | **none** for a correct dry-run | `DeleteObject` on the one configured bucket prefix | ❌ dry-run demands a delete-capable key (F4) |
| GitHub | repo secrets ×5, repo variable ×1 | + approval gate | ❌ ≥1 secret missing (54/54 failures); 0 environments (F17) |

### 4.3 Network dependencies

1. `runner → PostgreSQL` over TLS (Prisma `@prisma/adapter-pg`).
2. `runner → Redis` over TLS (ioredis; bounded: 3 s connect, 2 s command, 1 retry, no reconnect loop — `queue-connection.ts:53-86`).
3. `runner → npm registry` (`npm ci`) and `github.com` (checkout) — today's only *successful* egress.
4. `runner → object storage`: **not used in dry-run**, but the endpoint value must be syntactically present.
5. No ingress to the runner is required. Nothing in the scheduler listens on a port.

---

## 5. Can a GitHub-hosted runner reach these safely and reliably?

| Dependency | Reachability from a hosted runner | Assessment |
| --- | --- | --- |
| PostgreSQL | **Likely yes** if the baseline is Neon (serverless, public TLS endpoint, password + optional "trusted sources" allowlist). Hosted-runner egress IPs are dynamic and shared, so IP allowlisting cannot be relied on — either allow-all-with-password+TLS, or a proxy. | acceptable **if** the DB endpoint is internet-facing and the credential is scoped to `dip_retention`. A private/VPC-only PostgreSQL makes hosted execution impossible without a tunnel. |
| Redis | **Unknown and the highest risk.** The provider is not recorded anywhere in the repository (no IaC, no deployment manifest; `workers/README.md:152` only says "the platform scheduler"). If Redis is VPC-private, a hosted runner cannot reach it *at all*, and the dry-run silently degrades to zero queue evidence. If it is internet-facing (e.g. Upstash/TLS), it must additionally have an ACL user that can only read BullMQ keys. | **blocking unknown** |
| Object storage | Likely reachable (S3-compatible public endpoint), but **irrelevant** — dry-run makes no storage call. What matters is that a delete-capable key would be handed to a hosted runner for no operational benefit. | **avoidable exposure** |
| Supply chain | `actions/checkout@v5` + `actions/setup-node@v5` are moving tags and `npm ci` runs the public registry, all with production secrets in the environment, on a **public** repository. Tags can move; a compromised action would see every secret. | needs SHA pinning + `permissions: contents: read` |

Reliability, independent of network: F20 (single un-paginated scan) plus `timeout-minutes: 20` means a large tenant corpus can exceed the budget. GitHub-hosted `ubuntu-latest` gives a public repo 4 vCPU / 16 GB, which is adequate for the current query shape at moderate data volume — unknown at production scale.

---

## 6. Execution location: GitHub Actions vs. existing private worker infrastructure

| Dimension | GitHub Actions (hosted, current) | Private worker infrastructure (one-shot scheduler container) |
| --- | --- | --- |
| **Blast radius of credentials** | Production DB + Redis + (delete-capable) S3 held as **repo secrets**, reachable by any workflow in a **public** repo; secrets are exposed to `npm ci` and to tag-pinned actions | Credentials stay in the existing secret manager, injected at container start only; the container is already the trust boundary for DB/Redis/storage |
| **Network** | Requires prod DB **and Redis** to be internet-reachable from dynamic, unallowlistable egress IPs. New standing attack surface for every attacker on the internet, not just GitHub | Already inside the allowlisted egress path (`docs/phase-6-operations.md:19`); no new ingress, no new exposure |
| **Approval gate** | None today (0 environments). Must be built. | Whoever schedules the job = the existing ops/deploy control; can be gated by the same change process |
| **Log exposure** | Public (public repo). Aggregate counters are harmless, but DB errors, hostnames and role names become public | Private log store, same as worker logs |
| **Cost** | $0 — public-repo hosted minutes are free | Marginal: ~1 min CPU/day on already-paid-for capacity, plus log storage |
| **Complexity / lead time** | Low to schedule (exists), **high to secure**: environment protection, SHA pinning, Redis ACL, IP/TLS decisions, two new secrets | Medium: one Dockerfile copy line, one schedule entry, one log-shipping decision. No new secret store |
| **Baseline compatibility** | Node 22 on `ubuntu-latest` satisfies `engines >=22.13.0`; `tsx` + generated Prisma client work; already proven green through `npm run jobs:cleanup` steps 1–5 | Image is `node:22.20.0` with `tsx` in prod deps and a generated client; `NODE_ENV=production` is already set, so `REDIS_URL` and `NEXT_PUBLIC_APP_URL` must be present (they are, in the worker env) — **but the scheduler script is not in the image** (F15) |
| **Approved-architecture status** | This is the documented scheduler (`docs/operator-runbook.md:27-29`) | Running it here is a **change of execution location**, i.e. an architecture change → needs owner approval |

### Recommendation

**Run the first production-connected dry-run as a one-shot job inside the existing private worker network boundary**, and keep `retention.yml` as the hermetic CI contract (it already validates config and tests the workflow contract).

Rationale: it removes the two largest risks at once — no production Redis/DB reachability change, and no delete-capable storage credential handed to a public-repo hosted runner — while requiring a one-line Dockerfile change rather than a security exception. Cost is negligible and the credential inventory shrinks.

**This is an architecture change and must be approved by the owner before implementation (CR-005, §10).** If the owner declines it, the fallback is GitHub Actions with the hardening in §11; that path is only viable if production Redis is already reachable over TLS with an ACL-capable auth model, and it then also requires a security sign-off for the new internet exposure.

**Decision rule:** if production Redis has no public endpoint, GitHub Actions cannot produce queue evidence at all, and only the private-infra path can satisfy acceptance criterion B (§8).

---

## 7. `dip_retention` least-privilege review (no credential values read)

**Already correct.** Role attributes are revalidated on every migration run; the role is standalone (membership check raises); grants are table- and column-scoped; `DELETE`/`INSERT` are absent; cross-tenant visibility is explicit and per-table rather than via `BYPASSRLS`; `REVOKE`s run before grants so re-provisioning is idempotent (F11, F12). The migration is covered by a contract test (`test/retention.configuration.test.ts`) and an RLS integration test (`test/retention.rls.integration.test.mjs`) that proves cross-tenant `SELECT`/`UPDATE` succeed while `DELETE` and unrelated-table access are denied.

**Gaps (all provisioning/verification, not privilege widening):**

1. **No password path.** `configure-role-password.mjs` is `dip_app`-specific and hard-refuses any database other than `neondb` (F13). Provisioning `dip_retention` is currently a manual, unaudited `ALTER ROLE` by a DBA. *Do this in the secret manager / DBA console, never in this repo, and never paste the value into a PR, issue or chat.*
2. **No application-side identity assertion.** Nothing verifies that `RETENTION_DATABASE_URL` actually authenticates as `dip_retention`. Pointing it at the owner or `dip_app` URL is a documented prohibition (`docs/operator-runbook.md:27`) with **zero enforcement**; the sweep would then run with write-anywhere privileges and a fully permissive RLS posture.
3. **No privilege self-check.** There is no preflight asserting "I can `UPDATE jobs` but I cannot `DELETE` or read `api_keys`". The integration test asserts it; production does not.
4. **Redis has no least-privilege story at all** — no user, no ACL, no key pattern documented (see §4.2). If a shared `REDIS_URL` is wired, the sweep inherits the worker's full Redis authority.
5. **Dry-run does not get a read-only credential.** It must present a delete-capable S3 key (F4). The database side has the same weakness: `dip_retention` holds `UPDATE` during a run that must not update.

**Recommended read-only verification (owner/DBA, values never printed):**

```sql
-- attributes
SELECT rolname, rolsuper, rolbypassrls, rolinherit, rolcanlogin, rolcreatedb, rolcreaterole
FROM pg_roles WHERE rolname = 'dip_retention';
-- no memberships
SELECT r.rolname AS granted FROM pg_auth_members m
JOIN pg_roles r ON r.oid = m.roleid
JOIN pg_roles u ON u.oid = m.member WHERE u.rolname = 'dip_retention';
-- expected privilege shape
SELECT has_table_privilege('dip_retention','documents','SELECT') AS doc_select,
       has_table_privilege('dip_retention','documents','UPDATE') AS doc_update,
       has_table_privilege('dip_retention','jobs','DELETE')      AS job_delete,   -- expect false
       has_table_privilege('dip_retention','api_keys','SELECT')  AS api_keys_read; -- expect false
-- policies that actually apply to the role
SELECT tablename, policyname, cmd FROM pg_policies
WHERE schemaname='public' AND 'dip_retention' = ANY(roles) ORDER BY tablename, cmd;
```

---

## 8. Acceptance criteria for a *meaningful* read-only dry-run

A dry-run is accepted only if **all** of A–E hold in a single run, on `main`, with `RETENTION_APPLY` unset.

### A. Configuration and identity
- [ ] Run is green and the configuration step prints `RETENTION_APPLY_ENABLED=false`, `RETENTION_MODE=dry_run`.
- [ ] `retention.mode` log line: `apply:false`, `bucket_configured:true`.
- [ ] `retention.scheduler_result.dry_run === true`.
- [ ] The connection authenticates as `dip_retention` (asserted, not assumed) and the role still has `NOSUPERUSER`, `NOBYPASSRLS`, `NOINHERIT` and no memberships.

### B. Redis evidence completeness
- [ ] No `retention.redis_not_configured` event.
- [ ] `jobs.expiry_planned`: `queues_expected=2`, `queues_read=2`, `failed_reads=0`.
- [ ] `queue_unknown=0` — i.e. every job candidate's liveness was **established**, not defaulted.
- [ ] `expired=0` (dry-run never expires anything), `scanned ≥ 0` and, if `scanned>0`, the split across `within_grace / running_still_active / retry_queue_present / abandoned_running / stale_queue` is explainable against the queue depth.
- [ ] The process exits by itself (bounded connect/command timeouts, no reconnect loop).

### C. Retention candidate counts
- [ ] `scanned_documents` equals an independent `SELECT count(*) FROM documents WHERE status='ACTIVE'` taken immediately before the run.
- [ ] `candidate_documents = candidate_documents_free + candidate_documents_pro` and `scanned_documents = candidate_documents + skipped_documents` (F8).
- [ ] `candidate_documents` and per-plan split reproduce an **independent owner-side SQL recount** (§8.1) to the row, in a quiet window.
- [ ] `missing_object_files` is `0`, or every non-zero case is explained (files without a `storage_object_id` can **never** be reclaimed — that is a policy decision, not a dry-run success).
- [ ] `scope_blocked_files` is `0`. A non-zero value means the configured `STORAGE_BUCKET`/provider no longer matches what the application writes; that must be resolved **before** any apply.
- [ ] `retained_files`, `protected_files`, `missing_object_files`, `scope_blocked_files` are read as **document** counts (F9).
- [ ] Policy line shows `policy_version=2026-09-provisional-v2`, `retention_days_free=7`, `retention_days_pro=30`.

### D. Zero mutations
- [ ] `deleted_objects=0`, `deleted_documents=0`, `failures=0`, `blocked_objects=0`.
- [ ] `expired_jobs` is treated as a **planned** count, not a mutation count (F7); `jobs.expired_cleanup` must not appear in the log at all.
- [ ] **Structural proof (preferred):** the evidence run uses a credentials-only SELECT variant of the role (or the dry-run is executed with `UPDATE` temporarily revoked); any write attempt would then error loudly, and the run still succeeds. This is the only criterion that proves non-mutation rather than observing it.
- [ ] **Observational proof (fallback, quiet window):** before/after, with identical anchors — `documents` and `jobs` counts by `status`, `count(*) WHERE updated_at >= :run_start` for both, and `count(*) FROM storage_objects WHERE deleted_at IS NOT NULL` — all unchanged. Attribute any difference to concurrent application traffic before drawing conclusions.
- [ ] No object-storage mutating call. Because the dry-run makes **no** storage calls at all, a bucket access log (or provider audit log) for the run window must be empty.

### E. Useful, safe diagnostics
- [ ] Structured JSON only (`{timestamp, level, event, ...}`), aggregate counters only: no document ids, file ids, object keys, filenames, titles, emails, URLs, hostnames or credentials.
- [ ] Required events present: `retention.dry_run`, `retention.dry_run_completed`, `retention.scheduler_result`, `jobs.expiry_planned`, `retention.mode`.
- [ ] No Prisma `query`-level logging (it is off unless `NODE_ENV=development` — `src/lib/db/index.ts:14-17`; do not enable it for this run).
- [ ] The aggregate summary is retained as run evidence (step summary/artifact or the private log store) with owner and timestamp, so the "review one successful dry-run" gate has an artifact rather than a transient log.
- [ ] Data-volume sanity is recorded: `scanned_documents`, run duration, peak memory — the first real signal for F20.

### 8.1 Independent recount (owner-side, read-only, policy-identical)

```sql
-- run as the database owner, read-only
WITH active_sub AS (
  SELECT DISTINCT ON (s.user_id) s.user_id, p.code
  FROM subscriptions s JOIN plans p ON p.id = s.plan_id
  WHERE s.status IN ('ACTIVE','TRIALING') AND s.starts_at <= now()
    AND (s.current_period_end IS NULL OR s.current_period_end > now())
  ORDER BY s.user_id, s.created_at DESC
), protected AS (
  SELECT input_file_id AS file_id FROM jobs
   WHERE status IN ('QUEUED','RUNNING','RETRYING') AND input_file_id IS NOT NULL
  UNION SELECT output_file_id FROM jobs
   WHERE status IN ('QUEUED','RUNNING','RETRYING') AND output_file_id IS NOT NULL
  UNION SELECT (jsonb_array_elements_text(params->'inputFileIds'))::uuid FROM jobs
   WHERE status IN ('QUEUED','RUNNING','RETRYING') AND jsonb_typeof(params->'inputFileIds') = 'array'
), facts AS (
  SELECT d.id, coalesce(a.code,'FREE') AS plan_code,
         bool_and(f.created_at < now() - CASE WHEN coalesce(a.code,'FREE')='PRO'
                                              THEN interval '30 days' ELSE interval '7 days' END
                  AND f.id NOT IN (SELECT file_id FROM protected)
                  AND so.id IS NOT NULL AND so.provider = 's3'
                  AND so.bucket = :'retention_bucket') AS candidate
  FROM documents d
  JOIN files f ON f.document_id = d.id
  LEFT JOIN storage_objects so ON so.id = f.storage_object_id
  LEFT JOIN active_sub a ON a.user_id = d.user_id
  WHERE d.status = 'ACTIVE'
  GROUP BY d.id, a.code
)
SELECT count(*) FILTER (WHERE candidate) AS candidate_documents,
       count(*) FILTER (WHERE candidate AND plan_code='PRO') AS candidate_pro
FROM facts;
```

Compare with `candidate_documents` and `candidate_documents_pro`. Both dry-run and recount must be computed in the same quiet window; the plan is time-anchored to `now()`, so a document crossing a cutoff between the two reads is an expected ±1.

---

## 9. Blockers: verified vs unknown

### 9.1 Verified blockers (must be closed to reach GO)

| ID | Blocker | Why it blocks | Evidence |
| --- | --- | --- | --- |
| **V1** | At least one of the five `RETENTION_*` secrets is absent. Every scheduled run since 2026-09-27 fails at the credential gate; 0 successes, 0 manual dispatches. | No dry-run has ever executed; the runbook's own precondition is unmet. Secret **names** could not be enumerated (API 403), so the exact missing subset is unknown. | `gh run list` (54/54 failure), step-level jobs API |
| **V2** | `REDIS_URL` is never supplied to the scheduler. | Queue evidence is unconditionally `not_configured` ⇒ `queue_unknown` = every job candidate ⇒ criterion B can never pass. Aggravated by F6: it cannot be fixed by adding `NODE_ENV=production` alone. | F5, F6 |
| **V3** | The dry-run requires a delete-capable object-storage credential it never uses. | Forces write-capable S3 authority into the run (and into a public repo's secrets) for zero benefit; contradicts "least privilege" and any evidence-run design. | F4 |
| **V4** | No way to provision the `dip_retention` password within the repo's own tooling, and no proof the role exists in production. | Without a working `dip_retention` credential there is no compliant `RETENTION_DATABASE_URL`; nothing else can start. | F13, F14 |
| **V5** | No human gate between dry-run and apply (0 environments; apply = one repo variable). | Turning on apply is a single, unaudited variable edit that takes effect on the next **scheduled** run. This is a governance blocker independent of the dry-run, and it must be closed while attention is on this system. | F17 |
| **V6** | No documented production topology and no infrastructure-as-code in the repository. | Whether a hosted runner can reach production PostgreSQL and Redis — and whether that would require new internet exposure — is undecidable from the repository. | §5; repo has no deploy/IaC directory |

### 9.2 Unknowns (facts the owner must supply; do not guess)

| ID | Unknown | Why it matters |
| --- | --- | --- |
| U1 | Is migration `20260923090000_retention_scheduler_least_privilege` applied in production? Was it applied by a `CREATEROLE`-capable role? | If not, the role does not exist and its creation is itself a production schema change requiring a change process. |
| U2 | Production Redis provider, address class (public/VPC), TLS, and whether ACL users are supported. | Decides GitHub Actions vs. private infra (§6 decision rule). |
| U3 | Production storage provider (README says R2; `neon.ts` says Neon Object Storage baseline; docs say "private S3-compatible"). | Determines whether a read-only key is even obtainable, and whether `STORAGE_REGION` default `us-east-2` is correct. |
| U4 | Which `RETENTION_*` secrets exist (names are not visible to this session). | Scope of V1. |
| U5 | Production data volume: `count(*)` of ACTIVE documents / files / storage objects, and current queue depth. | F20 timeout/memory risk and the plausibility check in C. |
| U6 | Whether the private infrastructure has a scheduler (cron / CronJob / systemd timer) and where worker logs are shipped. | Determines the effort of the recommended path. |
| U7 | Owner's decision on execution location (private infra vs. hosted workflow). | Gated by CR-005. |

---

## 10. Smallest sequence to a first successful, production-connected dry-run

**Prerequisite: CR-005 (owner).** Nothing below may start before it is approved (`docs/cr-005-retention-dry-run-execution.md`). CR-005 must approve exactly four things:

1. Provisioning a production **`dip_retention`** login and a **read-only Redis** principal (or the decision to defer Redis evidence, which would make the run non-meaningful — not recommended).
2. The **execution location** and its network path (private infra recommended; hosted workflow = new internet exposure that needs separate security sign-off).
3. The **mode governance**: a dry-run-only gate that cannot be flipped to apply by editing a variable.
4. An explicit re-affirmation that **`RETENTION_APPLY` stays disabled**; enabling it is a *future, separate* CR after ≥3 green dry-runs.

| Step | Owner | Work | Gate |
| --- | --- | --- | --- |
| 1 | DBA/Owner | Confirm migration applied; create/rotate `dip_retention` password **in the secret manager only**; record role attributes from §7 queries | §7 checks return the expected privilege shape |
| 2 | Owner | Provision the Redis read principal: `HMGET`/`EXISTS` (plus `PING`, and `CLIENT` if the ioredis client issues `CLIENT SETINFO` on connect) restricted to `bull:dip.document-processing.v1:*` and `bull:dip.ai-processing.v1:*`; TLS only | a read-only probe returns data; a `SET` is rejected |
| 3 | Dev | **PR-1 (hardening, no behaviour change to apply):** defer `getStorage()` into the apply branch so the dry-run needs no storage credential; wire `REDIS_URL` from a new secret; set `NODE_ENV` and `NEXT_PUBLIC_APP_URL` consistently with F6; add `permissions: contents: read`; pin actions to SHAs; add the dry-run/apply gate (environment or hard-coded mode assertion); add a preflight that asserts role identity and privilege shape; publish the aggregate summary as run evidence; contract tests for each | CI green, no change to apply semantics |
| 4 | Owner | Provision the remaining secrets/variables **for the approved location only**; `RETENTION_APPLY` remains unset | secrets present, variable unset |
| 5 | Dev | Execute the dry-run **once**, manually (never on schedule until accepted), during a quiet window, capturing the pre/post snapshots in §8-D | run green, `dry_run:true` |
| 6 | Dev | Cross-check counts against §8.1; fill the §8 checklist; store the signed-off evidence | all A–E ticked |
| 7 | Owner | Review evidence; decide whether to schedule the dry-run daily and whether to open the *apply* CR | explicit written decision |
| 8 | — | Apply remains disabled. Repeating the dry-run daily is safe only after step 3's mode gate exists | — |

If the owner keeps GitHub Actions, add between steps 3 and 4: environment with required reviewers for an `apply` environment only, SHA-pinned actions, and a security sign-off for making production Redis reachable over TLS.

---

## 11. Proposed next PR scope (small, reviewable, no production effect)

**Branch/PR title:** `Retention dry-run readiness: wire queue evidence, drop unused storage credential, gate the mode`

1. `src/lib/retention/service.ts` — move `getStorage()` inside the apply branch (≈3 lines). Dry-run stops constructing an S3 client; apply is byte-for-byte unchanged. Update the header comment to state that dry-run touches PostgreSQL + Redis only.
2. `.github/workflows/retention.yml`
   - `permissions: contents: read`;
   - pin `actions/checkout` and `actions/setup-node` to commit SHAs;
   - new `REDIS_URL: ${{ secrets.RETENTION_REDIS_URL }}` (name only until provisioned);
   - `NODE_ENV: production` **and** `NEXT_PUBLIC_APP_URL` in the same step, so F6 cannot fire;
   - explicit mode guard: fail the job unless `RETENTION_MODE=dry_run` (apply reachable only through a separately approved path);
   - publish the JSON aggregate summary to `$GITHUB_STEP_SUMMARY` (counters only).
3. `scripts/verify-retention-role.ts` *(new, ~40 lines, read-only)* — asserts `current_user = 'dip_retention'`, `NOSUPERUSER`/`NOBYPASSRLS`/no memberships, `has_table_privilege` shape from §7, and that `DELETE` and `api_keys` are denied. Prints booleans only. Wire it as a preflight step.
4. `Dockerfile.worker` — `COPY --chown=dipworker:dipworker scripts/cleanup-expired-jobs.ts ./scripts/cleanup-expired-jobs.ts` (needed only for the private-infra path; harmless otherwise). No new packages, no entrypoint change.
5. `docs/operator-runbook.md` — add the dry-run procedure, the §8 acceptance checklist, the "`expired_jobs` is planned, not applied" and "`*_files` are document counts" notes, the Redis requirement, and "storage credential not required for dry-run".
6. `test/retention.configuration.test.ts` — extend the existing workflow-contract tests: `REDIS_URL` wired, `permissions` block present, `NODE_ENV`/`NEXT_PUBLIC_APP_URL` paired, mode guard present, dry-run branch has no `getStorage()` call.
7. *(Optional, separate)* `prisma/migrations/*_retention_readonly_evidence_role` — a SELECT-only sibling role for the evidence run, which turns acceptance criterion D into a structural guarantee. Only if the owner prefers that over the snapshot method.

Out of scope for that PR: any change to retention periods, RLS, grants of `dip_retention`, the storage-scope rules, `RETENTION_APPLY`, or where the scheduler runs.

---

## 12. Abort / kill switch (recommendations for the owner; nothing executed here)

- `RETENTION_APPLY` must remain unset. If it is ever observed as `1`, treat it as an incident: the next *scheduled* run is destructive and there is no approval gate (F17). Disable the workflow before investigating.
- Rotate any `RETENTION_*` secret that was ever pasted into an issue, PR, chat or log — the repository is public (F18).
- A dry-run must be aborted if: `scope_blocked_files > 0`, `missing_object_files` is unexplained, `deleted_objects`/`deleted_documents` are non-zero, `jobs.expired_cleanup` appears, or the run exceeds the timeout without reaching `retention.scheduler_result`.
- Because the scheduler is *destructive when misconfigured*, keep the credential gate fail-closed even after the dry-run works; do not "fix" a red run by relaxing `missingRetentionCredentials`.

---

## 13. Evidence appendix

Read-only commands used (no mutation, no secret values):

```bash
gh repo view --json defaultBranchRef,isPrivate
gh run list --workflow=retention.yml --limit 100 --json conclusion,createdAt,event,headBranch
gh run view <id> --json jobs            # step-level conclusions
gh api repos/<owner>/<repo>/environments
gh secret list                          # names only -> 403 (no admin)
git status --short                      # clean before/after this audit
```

Run log bodies could not be downloaded from this environment (the log host is outside the allowed egress set), so per-secret `*_PRESENT` values remain unknown — this is U4, not an inference.
