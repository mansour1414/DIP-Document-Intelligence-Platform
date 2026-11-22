# N1-A Phase 5 — Separate Prisma vs PostgreSQL Contract-Drift Assessment

> **Governance Rule**: Per N1-A scope boundaries, this assessment inspects and classifies existing contract differences between `prisma/schema.prisma` and the authoritative PostgreSQL migration chain (`prisma/migrations/*`). **No unrelated historical differences were auto-reconciled in N1-A**, because several differences are deliberate security/tenant-integrity or backward-compatibility controls enforced below the ORM layer.

---

## 1. Composite API-Client Tenant-Integrity Foreign Keys (4 Historical + 1 Added in N1-A)

### 1.1 Exact Inventory
In `prisma/schema.prisma`, models holding both `organizationId` and `apiClientId` declare two single-column Prisma `@relation` fields (`organization -> Organization.id` and `apiClient -> ApiClient.id`). In PostgreSQL, Phase 9A (`20260914120000_phase9a_business_api_foundation`) added `CREATE UNIQUE INDEX "api_clients_id_organization_id_key" ON "api_clients"("id", "organization_id")`, and Phases 9A/9B replaced the single-column `api_client_id` foreign keys with **composite tenant-binding foreign keys**:

| # | Table | SQL Constraint Name | Migration | PostgreSQL SQL Definition | `schema.prisma` Relation | Classification |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `api_keys` | `api_keys_api_client_organization_fkey` | `20260914120000_phase9a_business_api_foundation` | `FOREIGN KEY ("api_client_id", "organization_id") REFERENCES "api_clients"("id", "organization_id") ON DELETE CASCADE ON UPDATE NO ACTION` | `apiClient ApiClient? @relation(fields: [apiClientId], references: [id], onDelete: Cascade)` | **Intentional security hardening — DO NOT reconcile to single-column FK** |
| 2 | `api_idempotency_records` | `api_idempotency_records_client_organization_fkey` | `20260914120000_phase9a_business_api_foundation` | `FOREIGN KEY ("api_client_id", "organization_id") REFERENCES "api_clients"("id", "organization_id") ON DELETE CASCADE ON UPDATE NO ACTION` | `apiClient ApiClient @relation(fields: [apiClientId], references: [id], onDelete: Cascade)` | **Intentional security hardening — DO NOT reconcile to single-column FK** |
| 3 | `jobs` | `jobs_api_client_organization_fkey` | `20260914160000_phase9b_public_api` | `FOREIGN KEY ("api_client_id", "organization_id") REFERENCES "api_clients"("id", "organization_id") ON DELETE RESTRICT ON UPDATE NO ACTION` | `apiClient ApiClient? @relation(fields: [apiClientId], references: [id], onDelete: Restrict)` | **Intentional security hardening — DO NOT reconcile to single-column FK** |
| 4 | `api_usage` | `api_usage_client_organization_fkey` | `20260914160000_phase9b_public_api` | `FOREIGN KEY ("api_client_id", "organization_id") REFERENCES "api_clients"("id", "organization_id") ON DELETE CASCADE ON UPDATE NO ACTION` | `apiClient ApiClient @relation(fields: [apiClientId], references: [id], onDelete: Cascade)` | **Intentional security hardening — DO NOT reconcile to single-column FK** |
| *(N1-A)* | `storage_objects` | `storage_objects_api_client_organization_fkey` | `20261121120000_n1a_storage_objects_tenant_isolation` | `FOREIGN KEY ("api_client_id", "organization_id") REFERENCES "api_clients"("id", "organization_id") ON DELETE RESTRICT ON UPDATE CASCADE` | `apiClient ApiClient? @relation(fields: [apiClientId], references: [id], onDelete: Restrict, onUpdate: Cascade)` | **Intentional security hardening aligned with Phases 9A/9B** |

### 1.2 Why This Difference Exists & Operational Guidance
- **Security purpose**: A single-column FK `api_client_id -> api_clients(id)` would allow a row with `organization_id = OrgB` to reference an `api_client_id` owned by `OrgA`. The composite FK makes cross-organization API-client attribution structurally impossible in PostgreSQL (`23503`), even if an application bug or privileged query omits validation (`test/phase9a.migration.test.ts` and `test/phase9b.migration.test.ts` explicitly assert these composite FKs).
- **Risk warning**: Running `prisma migrate dev` unreviewed would propose dropping the 4 composite FKs and replacing them with weaker single-column `(api_client_id) -> api_clients(id)` FKs. Always author/review SQL migrations explicitly and keep static migration contract tests active.

---

## 2. Twenty (20) Prisma vs PostgreSQL Single-Column Referential-Action Differences

Comparing Prisma's effective defaults (`ON DELETE SET NULL` for optional relations, `ON DELETE RESTRICT` for required relations, and `ON UPDATE CASCADE` when unspecified in `schema.prisma`) against PostgreSQL's defaults (`ON DELETE NO ACTION ON UPDATE NO ACTION` when hand-authored DDL omits explicit clauses) yields **exact 20 single-column FK referential-action differences**:

| # | Table & Column | SQL Constraint | Migration | Prisma (`ON DELETE` / `ON UPDATE`) | PostgreSQL (`ON DELETE` / `ON UPDATE`) | Assessment |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `api_keys(user_id)` | `api_keys_user_id_fkey` | `20260909155620` + `20260914120000` | `SET NULL` / `CASCADE` | `RESTRICT` / `CASCADE` | **Intentional audit/credential safety**: baseline had `NOT NULL` + `RESTRICT`; Phase 9A dropped `NOT NULL` for org-scoped keys while keeping `ON DELETE RESTRICT` so deleting a user with personal API keys is blocked until keys are explicitly handled. |
| 2 | `api_keys(organization_id)` | `api_keys_organization_id_fkey` | `20260914120000` | `CASCADE` / `CASCADE` | `CASCADE` / `NO ACTION` | Benign (`organizations.id` UUID PK is immutable). |
| 3 | `api_keys(rotated_from_id)` | `api_keys_rotated_from_id_fkey` | `20260914120000` | `SET NULL` / `CASCADE` | `NO ACTION` / `NO ACTION` | **Minor behavioral drift**: deleting a historical rotated `api_keys` row fails in PG unless child `rotated_from_id` is cleared first (runtime revokes keys via `status = 'REVOKED'`, never `DELETE`). |
| 4 | `api_clients(organization_id)` | `api_clients_organization_id_fkey` | `20260914120000` | `CASCADE` / `CASCADE` | `CASCADE` / `NO ACTION` | Benign (UUID PK immutable). |
| 5 | `api_clients(created_by_user_id)` | `api_clients_created_by_user_id_fkey` | `20260914120000` | `RESTRICT` / `CASCADE` | `RESTRICT` / `NO ACTION` | Benign (`ON DELETE RESTRICT` matches; UUID PK immutable). |
| 6 | `api_idempotency_records(organization_id)` | `api_idempotency_records_organization_id_fkey` | `20260914120000` | `CASCADE` / `CASCADE` | `CASCADE` / `NO ACTION` | Benign (UUID PK immutable). |
| 7 | `jobs(organization_id)` | `jobs_organization_id_fkey` | `20260914160000` | `RESTRICT` / `CASCADE` | `RESTRICT` / `NO ACTION` | Benign (`ON DELETE RESTRICT` matches; UUID PK immutable). |
| 8 | `plan_entitlements(plan_id)` | `plan_entitlements_plan_id_fkey` | `20260910120000` | `CASCADE` / `CASCADE` | `CASCADE` / `NO ACTION` | Benign (UUID PK immutable). |
| 9 | `subscriptions(plan_id)` | `subscriptions_plan_id_fkey` | `20260910120000` | `RESTRICT` / `CASCADE` | `NO ACTION` / `NO ACTION` | Functionally equivalent for non-deferred immediate checks (`NO ACTION` blocks deleting referenced `plans`). |
| 10 | `invoices(user_id)` | `invoices_user_id_fkey` | `20260910120000` | `RESTRICT` / `CASCADE` | `NO ACTION` / `NO ACTION` | Functionally equivalent immediate delete block on financial records. |
| 11 | `invoices(subscription_id)` | `invoices_subscription_id_fkey` | `20260910120000` | `SET NULL` / `CASCADE` | `NO ACTION` / `NO ACTION` | **Protective financial ledger guard**: PG prevents deleting a `subscriptions` row referenced by `invoices`, whereas Prisma schema implies `SET NULL`. Preserving PG `NO ACTION`/`RESTRICT` is safer for billing auditability. |
| 12 | `payments(user_id)` | `payments_user_id_fkey` | `20260910120000` | `RESTRICT` / `CASCADE` | `NO ACTION` / `NO ACTION` | Functionally equivalent immediate delete block. |
| 13 | `payments(invoice_id)` | `payments_invoice_id_fkey` | `20260910120000` | `SET NULL` / `CASCADE` | `NO ACTION` / `NO ACTION` | **Protective financial ledger guard**: PG blocks deleting an `invoices` row referenced by `payments`. |
| 14 | `credit_purchases(user_id)` | `credit_purchases_user_id_fkey` | `20260910120000` | `RESTRICT` / `CASCADE` | `NO ACTION` / `NO ACTION` | Functionally equivalent immediate delete block. |
| 15 | `credit_purchases(invoice_id)` | `credit_purchases_invoice_id_fkey` | `20260910120000` | `SET NULL` / `CASCADE` | `NO ACTION` / `NO ACTION` | **Protective financial ledger guard**: PG blocks deleting referenced `invoices`. |
| 16 | `credit_purchases(payment_id)` | `credit_purchases_payment_id_fkey` | `20260910120000` | `SET NULL` / `CASCADE` | `NO ACTION` / `NO ACTION` | **Protective financial ledger guard**: PG blocks deleting referenced `payments`. |
| 17 | `usage_events(user_id)` | `usage_events_user_id_fkey` | `20260910120000` | `RESTRICT` / `CASCADE` | `NO ACTION` / `NO ACTION` | Functionally equivalent immediate delete block. |
| 18 | `api_usage(organization_id)` | `api_usage_organization_id_fkey` | `20260914160000` | `CASCADE` / `CASCADE` | `CASCADE` / `NO ACTION` | Benign (UUID PK immutable). |
| 19 | `billing_events(user_id)` | `billing_events_user_id_fkey` | `20260910120000` | `SET NULL` / `CASCADE` | `NO ACTION` / `NO ACTION` | **Audit preservation**: PG blocks deleting `users` referenced by `billing_events` instead of silently orphaning billing history (`dip_app` has no `DELETE` on `users` anyway). |
| 20 | `audit_logs(organization_id)` | `audit_logs_organization_id_fkey` | `20260914120000` | `SET NULL` / `CASCADE` | `NO ACTION` / `NO ACTION` | **Audit preservation**: PG blocks deleting `organizations` that have immutable `audit_logs` (`audit_logs` is append-only under `dip_app`). |

### 2.1 Recommendation for Referential-Action Drift
- **Do not alter PostgreSQL constraints** on financial/audit tables (`#1, #11, #13, #15, #16, #19, #20`) to `SET NULL` — PostgreSQL's stricter refusal to orphan billing/audit records is the safer behavior.
- If a future schema-hygiene PR is chartered purely to align `prisma/schema.prisma` annotations without generating runtime DDL changes, those annotations should be updated in `schema.prisma` (`onDelete: NoAction, onUpdate: NoAction`) rather than weakening PostgreSQL's constraints.

---

## 3. Two (2) SQL Timestamp-Default Differences

In `20260914120000_phase9a_business_api_foundation/migration.sql` (lines 11–14), `updated_at` was added to two existing baseline tables using `DEFAULT CURRENT_TIMESTAMP` without subsequently running `ALTER COLUMN "updated_at" DROP DEFAULT` (unlike `20260909161000_security_hardening` lines 16–18, which dropped defaults on `job_steps`, `tool_executions`, and `job_events`):

| # | Table & Column | PostgreSQL DDL (`20260914120000`) | `prisma/schema.prisma` | Risk & Recommendation |
| --- | --- | --- | --- | --- |
| 1 | `memberships.updated_at` | `TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP` | `updatedAt DateTime @updatedAt @map("updated_at")` (no DB `@default`) | **Intentional / Helpful for SQL functions**: `create_organization_with_owner` in SQL inserts into `memberships` directly; keeping `DEFAULT CURRENT_TIMESTAMP` prevents raw SQL inserts from failing if `updated_at` is omitted, while Prisma Client still supplies explicit timestamps on ORM writes. Keep as-is. |
| 2 | `api_keys.updated_at` | `TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP` | `updatedAt DateTime @updatedAt @map("updated_at")` (no DB `@default`) | **Low risk / Harmless**: Prisma supplies `updated_at` on `create`/`update`, and raw SQL test seeds rely on or tolerate the DB default. Keep as-is unless paired with `@default(now()) @updatedAt` in a dedicated schema-alignment review. |

---

## 4. Legacy Subscription Compatibility & Enum Ordering

Introduced in `20260910120000_phase4_monetization_core/migration.sql` (lines 4–9 and 66–88) and explicitly guarded by `test/monetization.migration.test.ts`:

1. **`SubscriptionStatusLegacy` enum & `subscriptions.legacy_plan` / `subscriptions.legacy_status` columns**:
   - Baseline `SubscriptionStatus` (`'ACTIVE', 'CANCELLED', 'PAST_DUE', 'INACTIVE'`) was renamed to `"SubscriptionStatusLegacy"` rather than dropped.
   - Baseline columns `subscriptions.plan` and `subscriptions.status` were renamed to `legacy_plan "Plan" NOT NULL DEFAULT 'FREE'` and `legacy_status "SubscriptionStatusLegacy" NOT NULL DEFAULT 'ACTIVE'`.
   - Neither legacy column nor `SubscriptionStatusLegacy` appears in `prisma/schema.prisma`. Because both columns have `NOT NULL DEFAULT ...` in PostgreSQL, Prisma `INSERT`s omitting them succeed seamlessly while preserving pre-Phase-4 subscription history on disk.
   - **Verdict**: **Intentional non-destructive migration compatibility** (explicitly tested in `test/monetization.migration.test.ts`). Must **not** be dropped without a formal data-retirement sign-off.
2. **`SubscriptionStatus` enum value ordering**:
   - **PostgreSQL (`20260910120000_phase4_monetization_core`, line 5)**: `('TRIALING', 'ACTIVE', 'PAST_DUE', 'CANCELLED', 'EXPIRED')`
   - **`prisma/schema.prisma` (lines 1005–1011)**: `TRIALING, ACTIVE, CANCELLED, PAST_DUE, EXPIRED` (`PAST_DUE` and `CANCELLED` transposed in ordinal position).
   - **Impact**: Equality/membership predicates (`status = 'ACTIVE'`, `IN (...)`) are unaffected because PostgreSQL compares enum labels by value; only raw SQL `<` / `>` / `ORDER BY subscriptions.status` uses enum OID sort order (no query in `src/` orders by `subscriptions.status`).
   - **Verdict**: **Low runtime risk, high migration hazard if auto-reconciled** (reordering PostgreSQL enum labels requires type recreation + table rewrite across `subscriptions`). Leave PostgreSQL enum intact; if aligned later, reorder the two lines in `prisma/schema.prisma` only.
