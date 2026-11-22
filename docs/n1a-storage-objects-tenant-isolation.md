# N1-A: `storage_objects` Tenant Isolation — Analysis, Architecture, Rollout & Verification

## 1. Phase 1 — Code-Path & Data-Model Mapping

### 1.1 Ownership & Entity Model (`Document` → `File` → `StorageObject`)
- **`Document` (`documents`)**: Root tenant-owned metadata record (`user_id UUID NOT NULL`, `organization_id UUID NULL`, `status "DocumentStatus"`). Protected by `ENABLE` + `FORCE ROW LEVEL SECURITY` (`documents_tenant_policy` for personal scope and `documents_org_member_policy` for active organization members).
- **`File` (`files`)**: Versioned/stored artifact metadata (`document_id UUID NOT NULL`, `storage_object_id UUID NULL`, `storage_key VARCHAR(500) NOT NULL`). Protected by `ENABLE` + `FORCE ROW LEVEL SECURITY` (`files_tenant_policy` and `files_org_member_policy` joining `documents`).
- **`StorageObject` (`storage_objects`)**: Physical S3/R2 object catalog (`id`, `provider`, `bucket`, `object_key`, `region`, `size`, `checksum`, `created_at`, `deleted_at`) with `UNIQUE ("provider", "bucket", "object_key")`. Prior to N1-A, `storage_objects` had **no tenant ownership columns and no PostgreSQL RLS policies**, while `dip_app` held `SELECT, INSERT, UPDATE ON storage_objects`.

### 1.2 Exact Creation, Read, Update & Retention Paths
| Path | Module | Behavior Before N1-A | Behavior After N1-A |
| --- | --- | --- | --- |
| Web / Workflow / Agent upload job creation | `src/lib/jobs/orchestrator.ts` (`createToolJob`) | Wrote S3 object under `input/<userId>/<ts>-<uuid>-<name>`, then inside `withTenant({ userId })` ran `tx.file.create({ ..., storageObject: { connectOrCreate: ... } })` | Runs inside `withTenantScope({ userId, organizationId, apiClientId })` and binds `(ownerUserId, organizationId, apiClientId)` via `buildStorageObjectConnectOrCreate` |
| Public API v1 job submission | `src/lib/public-api/jobs.ts` (`submitPublicJob`) → `createToolJob` | Passed `{ userId: principal.executionUserId, organizationId: principal.organizationId, apiClientId: principal.apiClientId }`, but `createToolJob` only called `withTenant({ userId })` | Sets full `(userId, organizationId, apiClientId)` GUC context and persists all three ownership attributes on `storage_objects` |
| Worker output commit (`document-worker`) | `src/lib/jobs/document-pipeline.ts` (`processDocumentJob`) | Screened outputs, wrote S3 keys under `output/<requesterId>/<jobId>/<attemptId>/<idx>-<name>`, and committed `Document` + `File` + `StorageObject` (`connectOrCreate`) inside `withTenant` | Fails closed if `job.requesterId` is null; commits output `Document`, `File`, and `StorageObject` inside `withTenantScope({ userId: job.requesterId, organizationId: job.organizationId, apiClientId: job.apiClientId })` |
| Client-side ephemeral usage history | `src/lib/jobs/history.ts` (`recordClientJobUsage`) | Creates `File` with `storageKey = ephemeral/...` and `storageObjectId = null` | Unchanged (`storageObjectId IS NULL` remains explicitly permitted) |
| Web output file download | `src/lib/jobs/access.ts` (`findOutputFileForUser`) & `src/app/api/files/[fileId]/route.ts` | Checked `document: { userId }` without checking `storageObject` ownership or `deletedAt` | Enforces `document: { userId, organizationId: null, status: "ACTIVE" }` and non-deleted personal `storageObject` ownership |
| Public API v1 result listing & download | `src/lib/public-api/jobs.ts` (`getPublicJobResult`, `downloadPublicJobResult`) | Used `withTenant({ userId: principal.executionUserId })` | Uses `withTenantScope({ userId: principal.executionUserId, organizationId: principal.organizationId, apiClientId: principal.apiClientId })` and verifies active, non-deleted org/API-client `storageObject` |
| Retention cleanup & job-expiry sweep | `src/lib/retention/repository.ts`, `src/lib/retention/expiry-write.ts`, `scripts/cleanup-expired-jobs.ts` | Connects as dedicated `dip_retention` (`NOBYPASSRLS`, `NOINHERIT`) without tenant GUC; `SELECT`s `storage_objects` and `UPDATE`s `deleted_at` | Preserved via narrow `TO dip_retention` `SELECT` + `UPDATE` RLS policies paired with `GRANT SELECT` and column-only `GRANT UPDATE ("deleted_at")` |

### 1.3 Answers to Phase 1 Investigation Questions
1. **Owner of a `StorageObject`**: Every runtime-created `StorageObject` has an owning user (`owner_user_id = Document.user_id / Job.requester_id`), an optional owning organization (`organization_id = Document.organization_id`), and — when created through Public API v1 — an optional `api_client_id` (`Job.api_client_id`) bound to `organization_id`.
2. **Creation timing relative to `Document` and `File`**: S3 bytes are uploaded first; inside a single DB transaction, `Document` is inserted first, then `File` is created with nested `storageObject: { connectOrCreate }`, which executes `SELECT FROM storage_objects WHERE provider=... AND bucket=... AND object_key=...` followed by `INSERT INTO storage_objects (...)` *before* `INSERT INTO files (...)`!
3. **Can one `StorageObject` link to multiple `File` rows?**: Schema allows `1:N` (`StorageObject.files`), though runtime keys include per-upload/per-attempt UUIDs so distinct uploads never intentionally share a `StorageObject` across tenants; `createToolJobFromFiles` reuses existing `File` IDs rather than creating new `StorageObject`s.
4. **Can one `StorageObject` legitimately cross tenants?**: **No.** Cross-tenant sharing of a `StorageObject` is never legitimate in DIP.
5. **Upload & worker behavior under RLS**: Both paths run inside transaction-local GUC scopes (`withTenantScope`) as `dip_app` (`NOBYPASSRLS`).
6. **Prisma `connectOrCreate` under PostgreSQL RLS**: Prisma expands `connectOrCreate` into (1) `SELECT` by unique key `(provider, bucket, object_key)`, (2) if 0 rows visible under RLS, `INSERT` (catching `23505` unique violation and retrying `SELECT`), and (3) `INSERT INTO files` referencing the resolved `storage_object_id`.
7. **Unique `(provider, bucket, object_key)` cross-tenant collision**: If Tenant B collides on Tenant A's key, RLS hides Tenant A's row during `SELECT`, Prisma attempts `INSERT`, PostgreSQL raises `23505` on the global unique index, Prisma's retry `SELECT` still sees 0 rows under RLS, and the operation **fails closed** without ever linking Tenant B to Tenant A's `StorageObject` or leaking Tenant A's metadata.
8. **Orphaned / unlinked records & failed attempts**: Failed S3 uploads in `orchestrator.ts` and superseded/rolled-back worker commits in `document-pipeline.ts` compensate by deleting unreferenced S3 keys; historical unlinked `storage_objects` rows (`NOT EXISTS (SELECT 1 FROM files ...)`) can exist from prior partial manual/test operations and must be quarantined (`NULL` ownership) rather than silently deleted or assigned fabricated owners.
9. **Available GUC contexts**: `app.current_user_id`, `app.current_organization_id`, and `app.current_api_client_id` (plus narrow auth-only `app.auth_*` GUCs).
10. **Legitimate cross-tenant access**: Strictly limited to `dip_retention` (`SELECT` + `UPDATE (deleted_at)`). No application route, worker, workflow, or agent has legitimate cross-tenant `StorageObject` access.

---

## 2. Phase 2 — Architectural Comparison: Option A vs Option B

| Criterion | Option A: Explicit Ownership Metadata on `StorageObject` + Cross-Table Triggers (**Selected**) | Option B: Relationship-Derived Authorization via `File` → `Document` (`EXISTS` Subquery) |
| --- | --- | --- |
| **Correctness & Prisma `connectOrCreate`** | **Works natively.** `StorageObject` carries `owner_user_id`, `organization_id`, `api_client_id` at `INSERT` time, BEFORE `files` is inserted. | **Broken on `INSERT` / `connectOrCreate`!** Prisma inserts `storage_objects` *before* `files`. At `storage_objects` `INSERT` + `RETURNING` time, zero `files` rows reference `storage_objects.id`, so a pure `EXISTS (SELECT 1 FROM files ...)` policy rejects every `connectOrCreate`! |
| **Security & Pre-Link Window** | Zero unattributed window: every runtime `INSERT` must satisfy `WITH CHECK` against current session GUCs immediately. | Making pre-link `INSERT` work requires allowing unlinked `storage_objects` to be visible/insertable, creating a cross-tenant pre-link hijack/read window! |
| **PostgreSQL RLS (`INSERT`/`SELECT`/`UPDATE`)** | Simple, index-backed column predicates + `app_is_org_member` / `app_api_client_matches_tenant` helpers. | Every `SELECT`/`UPDATE` on `storage_objects` executes correlated `files -> documents` joins subject to nested RLS evaluation. |
| **Pre-Link & Orphaned Records** | Historical unlinked orphans keep `(NULL, NULL, NULL)` ownership: preserved on disk, invisible to all `dip_app` tenants, and blocked from tenant linking by trigger, while `dip_retention` can still audit/tombstone them. | Orphans are either completely invisible forever without schema state distinguishing orphan vs pre-link, or dangerously exposed if unlinked rows are permitted. |
| **Shared-Object & Collision Edge Cases** | `enforce_file_storage_object_tenant_match` and `enforce_document_storage_object_tenant_match` triggers forbid cross-tenant `File -> StorageObject` links; cross-tenant key collisions fail closed. | Relies on `files` links *defining* ownership — if a bug ever inserted a cross-tenant `files.storage_object_id` link, Tenant B would retroactively gain RLS read/update access to Tenant A's `StorageObject`! |
| **Multi-Tenant Access (User / Org / API Client)** | First-class support for personal user (`owner_user_id`), active org member (`organization_id` + `app_is_org_member` — revoked members lose access immediately), and API client (`(api_client_id, organization_id)` composite FK). | `documents` has no `api_client_id` column, so Option B cannot isolate API Client 1 vs API Client 2 within the same organization at the `storage_objects` layer! |
| **Backfill Safety** | Deterministic single-pass backfill from `files -> documents` (+ unambiguous `jobs.api_client_id`) with pre-flight conflict checks (`RAISE EXCEPTION` on multi-user/multi-org/multi-client ambiguity). | No column backfill, but cannot detect or quarantine pre-existing multi-tenant link anomalies at migration time. |
| **Performance, Concurrency & Maintainability** | B-tree indexes on `(owner_user_id)`, `(organization_id)`, and `(api_client_id, organization_id)`; zero extra join per `SELECT`; matches `jobs`, `api_keys`, `api_usage` patterns across Phases 9A/9B. | Correlated multi-table joins under nested RLS on every query; harder to reason about lock/plan behavior under concurrent `connectOrCreate` retries. |
| **Retention & Rollback** | `dip_retention` policies (`TO dip_retention`) + column `UPDATE (deleted_at)` work identically on attributed and quarantined orphan rows; forward-safe policy/trigger rollback preserves all data. | Couples retention queries to `files` join behavior or still requires separate `TO dip_retention` policies without solving `INSERT`. |

### Selection Decision
**Option A (Explicit Ownership Metadata on `StorageObject` paired with Cross-Table Tenant-Match & Immutability Triggers)** is unambiguously required by DIP's real runtime architecture because Prisma's nested `tx.file.create({ storageObject: { connectOrCreate } })` inserts and `RETURNING`-reads `storage_objects` **before** inserting `files`. Option B cannot authorize `INSERT ... RETURNING` safely without opening an unattributed pre-link loophole and cannot enforce per-`api_client_id` isolation within an organization.

---

## 3. Phase 3 — Database Hardening, Staged Rollout & Rollback Plan

### 3.1 Summary of Schema, Constraint, Trigger & RLS Controls
Implemented in forward-only migration `prisma/migrations/20261121120000_n1a_storage_objects_tenant_isolation/migration.sql`:
1. **Columns**: Nullable `owner_user_id UUID`, `organization_id UUID`, `api_client_id UUID` on `storage_objects`.
2. **Constraints & Composite FK**:
   - `storage_objects_tenant_scope_check`: Either all three columns are `NULL` (quarantined historical unlinked orphan) OR `owner_user_id IS NOT NULL AND (api_client_id IS NULL OR organization_id IS NOT NULL)`.
   - `storage_objects_owner_user_id_fkey`: `FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE CASCADE`.
   - `storage_objects_organization_id_fkey`: `FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE RESTRICT ON UPDATE CASCADE`.
   - `storage_objects_api_client_organization_fkey`: Composite `FOREIGN KEY (api_client_id, organization_id) REFERENCES api_clients(id, organization_id) ON DELETE RESTRICT ON UPDATE CASCADE`.
3. **Immutability & Cross-Table Triggers (`SECURITY DEFINER`, `SET search_path = pg_catalog, public`)**:
   - `storage_objects_immutability_guard`: Blocks mutating `(provider, bucket, object_key)` and blocks reassigning `(owner_user_id, organization_id, api_client_id)` once attributed.
   - `files_storage_object_tenant_guard`: Blocks linking any `File` to an unattributed (`owner_user_id IS NULL`) or differently owned `(owner_user_id, organization_id)` `StorageObject`.
   - `documents_storage_object_tenant_guard`: Blocks mutating `documents.(user_id, organization_id)` while linked to `storage_objects` of another tenant.
4. **RLS & `FORCE ROW LEVEL SECURITY` + Least-Privilege Grants**:
   - `ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY` on `storage_objects`.
   - Separate explicit policies for personal user scope, active org-member scope (`app_is_org_member`), direct API-client scope (`app_api_client_matches_tenant`), and `TO dip_retention` (`SELECT` + `UPDATE`).
   - `dip_app`: `SELECT, INSERT` + column-scoped `UPDATE (region, checksum, deleted_at)` (no `DELETE`).
   - `dip_retention`: `SELECT` + column-scoped `UPDATE (deleted_at)` (no `INSERT`, `DELETE`, or other column updates).

### 3.2 Staged Production Rollout Runbook (Not Executed in N1-A)
1. **Stage 0 — Pre-Deployment Read-Only Audit (Maintenance Check)**:
   Run as read-only admin against target database *before* scheduling deployment:
   ```sql
   -- Must return 0 rows; any row indicates a historical cross-tenant link requiring manual incident triage.
   SELECT so.id, COUNT(DISTINCT d.user_id) AS users, COUNT(DISTINCT d.organization_id) AS orgs
   FROM storage_objects so
   JOIN files f ON f.storage_object_id = so.id
   JOIN documents d ON d.id = f.document_id
   GROUP BY so.id
   HAVING COUNT(DISTINCT d.user_id) > 1
       OR COUNT(DISTINCT d.organization_id) > 1
       OR (COUNT(DISTINCT d.organization_id) = 1 AND BOOL_OR(d.organization_id IS NULL));

   -- Count historical unlinked orphan rows that will remain quarantined (owner_user_id IS NULL).
   SELECT COUNT(*) AS unlinked_orphans
   FROM storage_objects so
   WHERE NOT EXISTS (SELECT 1 FROM files f WHERE f.storage_object_id = so.id);
   ```
2. **Stage 1 — Brief Drain / Coordinated Deploy**:
   - Pause document/AI queue intake briefly (or drain active in-flight commits for <30s) because once RLS is enabled on `storage_objects`, old app/worker instances that omit `owner_user_id` on `INSERT` will rightly be rejected by RLS (`42501`).
   - Deploy updated web + worker image (containing `withTenantScope` and `buildStorageObjectConnectOrCreate`) together with `npx prisma migrate deploy` and `psql --set=ON_ERROR_STOP=1 -f prisma/bootstrap/dip_app.sql`.
3. **Stage 2 — Post-Migration Smoke & Catalog Verification**:
   ```sql
   SELECT relrowsecurity, relforcerowsecurity
   FROM pg_class WHERE oid = 'public.storage_objects'::regclass;
   -- Expect: t, t
   ```
   Verify one authenticated personal upload/download, one Public API v1 job submission/result download, and `npm run retention:dry-run`.

### 3.3 Forward-Safe Rollback Plan
- **Never delete or edit applied migration history**, and **never drop `owner_user_id`, `organization_id`, or `api_client_id` columns** during an emergency rollback (retaining nullable populated columns is backward-compatible with previous application code and preserves all attribution data).
- If an unexpected runtime regression occurs immediately post-deploy and application binaries must revert to the prior release, apply a **new forward-only emergency mitigation migration** that:
  1. Drops `files_storage_object_tenant_guard` on `files`,
  2. Disables `FORCE`/`ENABLE ROW LEVEL SECURITY` on `storage_objects` temporarily while keeping the populated nullable columns and indexes intact, and
  3. Preserves all rows without deleting or altering customer ownership while root cause is investigated.

---

## 4. Phase 4 — Security Verification Matrix & Gate Status

| # | Required Security Scenario | Static DDL Test (`test/storage-objects.migration.test.ts`) | Unit / Synthetic Pipeline Test (`test/storage-objects.security.unit.test.ts`) | Real PostgreSQL 18 RLS Test (`test/storage-objects.rls.integration.test.mjs`) |
| --- | --- | --- | --- | --- |
| 1 | Tenant A can access its own metadata | Policy & grant assertions | PASS | Implemented (**BLOCKED locally**) |
| 2 | Tenant A cannot read Tenant B metadata | Policy predicate assertions | PASS | Implemented (**BLOCKED locally**) |
| 3 | Tenant A cannot update Tenant B metadata | Policy + column grant assertions | PASS | Implemented (**BLOCKED locally**) |
| 4 | Unauthorized `INSERT` is rejected | `WITH CHECK` assertions | PASS | Implemented (**BLOCKED locally**) |
| 5 | Missing or invalid tenant context fails closed | `NULLIF(current_setting(...),'')` assertions | PASS | Implemented (**BLOCKED locally**) |
| 6 | User-owned document access works | `storage_objects_user_tenant_policy` | PASS | Implemented (**BLOCKED locally**) |
| 7 | Organization-owned document access works (incl. revoked member denial) | `app_is_org_member` policy assertions | PASS | Implemented (**BLOCKED locally**) |
| 8 | API-client context cannot escape its organization | Composite FK + API-client policy assertions | PASS | Implemented (**BLOCKED locally**) |
| 9 | Worker output creation remains correct | Schema + helper wiring | PASS (`processDocumentJob`) | Implemented (**BLOCKED locally**) |
| 10 | `connectOrCreate` respects isolation | Unique + policy assertions | PASS | Implemented (**BLOCKED locally**) |
| 11 | Concurrent retries do not produce duplicate side effects | Immutability + CAS preservation | PASS (concurrent `processDocumentJob`) | Covered by `pr1-output-screening.integration.test.ts` (**BLOCKED locally**) |
| 12 | Object-key collisions cannot link unrelated tenants | Unique + trigger assertions | PASS | Implemented (**BLOCKED locally**) |
| 13 | Unlinked and orphaned records are handled safely | No-DELETE backfill + trigger check | PASS | Implemented (**BLOCKED locally**) |
| 14 | Authorized download and metadata operations remain compatible | Column/select compatibility | PASS (`findOutputFileForUser`, Public API v1) | Covered by E2E/RLS suites (**BLOCKED locally**) |
| 15 | Retention has only its necessary independent privileges | `TO dip_retention` + `UPDATE (deleted_at)` | PASS | Implemented (**BLOCKED locally**) |
| 16 | RLS and `FORCE` behavior is explicitly verified | `ENABLE` + `FORCE ROW LEVEL SECURITY` | PASS (simulated `forceRls` toggle) | `pg_class` `relrowsecurity` & `relforcerowsecurity` (**BLOCKED locally**) |

> **Explicit Gate Honesty Statement**: Local verification in this sandbox confirmed static SQL contracts, Prisma schema/client generation, TypeScript compilation, ESLint, and synthetic/unit security tests. Because no local PostgreSQL 18 runtime or Docker daemon is installed in this sandbox—and external/Neon databases are strictly off-limits—**real PostgreSQL 18 RLS execution (`DIP_RLS_TEST_DATABASE_URL`) is marked `BLOCKED` locally** and must run in an isolated disposable PostgreSQL 18 environment (`rls-security` job) before production promotion or RLS acceptance sign-off.
