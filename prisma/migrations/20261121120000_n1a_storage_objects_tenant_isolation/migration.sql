-- N1-A: StorageObject tenant isolation, ownership invariants, least-privilege RLS, and cross-table guards.
-- Historical migrations remain immutable; this forward-only migration closes the storage_objects RLS gap.

BEGIN;

-- 1. Read-only, fail-closed role preflight (PostgreSQL 18 non-superuser compatible, e.g. Neon neondb_owner):
--    - Never provisions or mutates cluster roles inside a schema migration.
--    - Rejects execution as dip_app or dip_retention so SECURITY DEFINER functions are owned by the schema owner.
--    - Verifies dip_app and dip_retention already exist with exact least-privilege attributes
--      (LOGIN, NOSUPERUSER, NOBYPASSRLS, NOINHERIT, NOCREATEDB, NOCREATEROLE, NOREPLICATION)
--      and zero unsafe role memberships (e.g. neon_superuser, pg_read_all_data, pg_write_all_data).
DO $$
DECLARE
  v_target_role text;
  v_rolcanlogin boolean;
  v_rolsuper boolean;
  v_rolbypassrls boolean;
  v_rolinherit boolean;
  v_rolcreatedb boolean;
  v_rolcreaterole boolean;
  v_rolreplication boolean;
  v_bad_attrs text[];
  v_memberships text;
BEGIN
  IF current_user IN ('dip_app', 'dip_retention') THEN
    RAISE EXCEPTION 'MIGRATION_ROLE_INVALID: N1-A migration must not execute as runtime or retention role (%).', current_user
      USING ERRCODE = '42501';
  END IF;

  FOREACH v_target_role IN ARRAY ARRAY['dip_app', 'dip_retention'] LOOP
    SELECT
      r.rolcanlogin,
      r.rolsuper,
      r.rolbypassrls,
      r.rolinherit,
      r.rolcreatedb,
      r.rolcreaterole,
      r.rolreplication
    INTO
      v_rolcanlogin,
      v_rolsuper,
      v_rolbypassrls,
      v_rolinherit,
      v_rolcreatedb,
      v_rolcreaterole,
      v_rolreplication
    FROM pg_catalog.pg_roles r
    WHERE r.rolname = v_target_role;

    IF NOT FOUND THEN
      RAISE EXCEPTION 'ROLE_PREFLIGHT_MISSING: required database role "%" does not exist; provision least-privilege roles via prisma/bootstrap/roles.sql before running migrations',
        v_target_role
        USING ERRCODE = '42501';
    END IF;

    v_bad_attrs := ARRAY[]::text[];
    IF NOT v_rolcanlogin THEN v_bad_attrs := array_append(v_bad_attrs, 'rolcanlogin=false (expected LOGIN)'); END IF;
    IF v_rolsuper THEN v_bad_attrs := array_append(v_bad_attrs, 'rolsuper=true (expected NOSUPERUSER)'); END IF;
    IF v_rolbypassrls THEN v_bad_attrs := array_append(v_bad_attrs, 'rolbypassrls=true (expected NOBYPASSRLS)'); END IF;
    IF v_rolinherit THEN v_bad_attrs := array_append(v_bad_attrs, 'rolinherit=true (expected NOINHERIT)'); END IF;
    IF v_rolcreatedb THEN v_bad_attrs := array_append(v_bad_attrs, 'rolcreatedb=true (expected NOCREATEDB)'); END IF;
    IF v_rolcreaterole THEN v_bad_attrs := array_append(v_bad_attrs, 'rolcreaterole=true (expected NOCREATEROLE)'); END IF;
    IF v_rolreplication THEN v_bad_attrs := array_append(v_bad_attrs, 'rolreplication=true (expected NOREPLICATION)'); END IF;

    IF coalesce(array_length(v_bad_attrs, 1), 0) > 0 THEN
      RAISE EXCEPTION 'ROLE_PREFLIGHT_INVALID: role "%" violates least-privilege attributes [%]; remediate via privileged role bootstrap before running migrations',
        v_target_role,
        array_to_string(v_bad_attrs, ', ')
        USING ERRCODE = '42501';
    END IF;

    SELECT string_agg(granted_role.rolname, ', ' ORDER BY granted_role.rolname)
      INTO v_memberships
      FROM pg_catalog.pg_auth_members membership
      JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member
      JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = membership.roleid
     WHERE member_role.rolname = v_target_role;

    IF v_memberships IS NOT NULL THEN
      RAISE EXCEPTION 'ROLE_PREFLIGHT_MEMBERSHIP_INVALID: role "%" has unsafe role memberships [%]; runtime and retention roles must be standalone least-privilege roles',
        v_target_role,
        v_memberships
        USING ERRCODE = '42501';
    END IF;
  END LOOP;
END
$$;

-- 2. Add explicit nullable ownership columns to storage_objects.
-- Nullable columns allow unlinked historical orphan rows to remain quarantined (NULL)
-- without fabricating fake customer ownership or silently deleting data.
ALTER TABLE "storage_objects"
  ADD COLUMN "owner_user_id" UUID,
  ADD COLUMN "organization_id" UUID,
  ADD COLUMN "api_client_id" UUID;

-- 3. Fail closed if any existing files or storage_objects row violates coordinate integrity
-- (missing storage_object_id on non-ephemeral files, storage_object_id attached to ephemeral/*,
-- or files.storage_key != storage_objects.object_key) or has conflicting user, organization,
-- or mixed/conflicting API-client attribution across any linked files or jobs (including multi-file JSONB arrays).
-- Never delete or silently reassign existing rows; require explicit operator remediation first.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM "files" f
    WHERE f."storage_object_id" IS NULL
      AND (
        f."storage_key" IS NULL
        OR f."storage_key" NOT LIKE 'ephemeral/%'
        OR pg_catalog.char_length(f."storage_key") <= pg_catalog.char_length('ephemeral/')
      )
  ) THEN
    RAISE EXCEPTION 'FILE_STORAGE_OBJECT_REQUIRED_CONFLICT: non-ephemeral files row is missing storage_object_id; run explicit preflight backfill before applying migration'
      USING ERRCODE = '23514';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM "files" f
    WHERE f."storage_object_id" IS NOT NULL
      AND (
        f."storage_key" IS NULL
        OR pg_catalog.btrim(f."storage_key") = ''
        OR f."storage_key" LIKE 'ephemeral/%'
      )
  ) THEN
    RAISE EXCEPTION 'FILE_EPHEMERAL_STORAGE_OBJECT_CONFLICT: ephemeral or blank files.storage_key cannot link to a physical storage_objects row'
      USING ERRCODE = '23514';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM "files" f
    JOIN "storage_objects" so ON so."id" = f."storage_object_id"
    WHERE f."storage_key" IS DISTINCT FROM so."object_key"
  ) THEN
    RAISE EXCEPTION 'FILE_STORAGE_KEY_MISMATCH_CONFLICT: files.storage_key does not match linked storage_objects.object_key; remediate mismatched rows before applying migration'
      USING ERRCODE = '23514';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM "storage_objects" so
    JOIN "files" f ON f."storage_object_id" = so."id"
    JOIN "documents" d ON d."id" = f."document_id"
    GROUP BY so."id"
    HAVING COUNT(DISTINCT d."user_id") > 1
        OR COUNT(DISTINCT d."organization_id") > 1
        OR (COUNT(DISTINCT d."organization_id") = 1 AND BOOL_OR(d."organization_id" IS NULL))
  ) THEN
    RAISE EXCEPTION 'STORAGE_OBJECT_TENANT_CONFLICT: storage_objects row is linked to multiple users or organizations'
      USING ERRCODE = '23514';
  END IF;

  IF EXISTS (
    WITH file_job_links AS (
      SELECT
        so."id" AS storage_object_id,
        f."id" AS file_id,
        d."organization_id" AS doc_organization_id,
        j."id" AS job_id,
        j."organization_id" AS job_organization_id,
        j."api_client_id" AS job_api_client_id
      FROM "storage_objects" so
      JOIN "files" f ON f."storage_object_id" = so."id"
      JOIN "documents" d ON d."id" = f."document_id"
      LEFT JOIN "jobs" j
        ON j."input_file_id" = f."id"
        OR j."output_file_id" = f."id"
        OR (jsonb_typeof(j."params"->'inputFileIds') = 'array' AND (j."params"->'inputFileIds') ? (f."id"::text))
        OR (jsonb_typeof(j."result"->'outputFileIds') = 'array' AND (j."result"->'outputFileIds') ? (f."id"::text))
    ),
    per_file_attribution AS (
      SELECT
        storage_object_id,
        file_id,
        doc_organization_id,
        BOOL_OR(job_api_client_id IS NOT NULL AND (doc_organization_id IS NULL OR job_organization_id IS DISTINCT FROM doc_organization_id)) AS has_org_mismatch,
        COUNT(DISTINCT job_api_client_id) AS distinct_api_clients,
        BOOL_OR(job_id IS NOT NULL AND job_api_client_id IS NOT NULL) AS has_api_job,
        BOOL_OR(job_id IS NOT NULL AND job_api_client_id IS NULL) AS has_non_api_job,
        MAX(job_api_client_id::text)::uuid AS resolved_file_api_client_id
      FROM file_job_links
      GROUP BY storage_object_id, file_id, doc_organization_id
    )
    SELECT 1
    FROM per_file_attribution
    GROUP BY storage_object_id
    HAVING BOOL_OR(has_org_mismatch)
        OR BOOL_OR(distinct_api_clients > 1)
        OR BOOL_OR(has_api_job AND has_non_api_job)
        OR COUNT(DISTINCT resolved_file_api_client_id) > 1
        OR (BOOL_OR(resolved_file_api_client_id IS NOT NULL) AND BOOL_OR(resolved_file_api_client_id IS NULL))
  ) THEN
    RAISE EXCEPTION 'STORAGE_OBJECT_API_CLIENT_CONFLICT: storage_objects row has conflicting or mixed API client attribution'
      USING ERRCODE = '23514';
  END IF;
END
$$;

-- 4. Deterministically backfill unambiguous ownership from files -> documents (+ verified jobs).
-- Unlinked orphan rows are intentionally left with NULL ownership so they stay quarantined under RLS.
WITH resolved_ownership AS (
  SELECT
    so."id" AS storage_object_id,
    d."user_id" AS owner_user_id,
    d."organization_id" AS organization_id,
    CASE
      WHEN d."organization_id" IS NOT NULL
       AND COUNT(DISTINCT j."api_client_id") = 1
      THEN MAX(j."api_client_id"::text)::uuid
      ELSE NULL
    END AS api_client_id
  FROM "storage_objects" so
  JOIN "files" f ON f."storage_object_id" = so."id"
  JOIN "documents" d ON d."id" = f."document_id"
  LEFT JOIN "jobs" j
    ON j."organization_id" = d."organization_id"
   AND (
     j."input_file_id" = f."id"
     OR j."output_file_id" = f."id"
     OR (jsonb_typeof(j."params"->'inputFileIds') = 'array' AND (j."params"->'inputFileIds') ? (f."id"::text))
     OR (jsonb_typeof(j."result"->'outputFileIds') = 'array' AND (j."result"->'outputFileIds') ? (f."id"::text))
   )
  GROUP BY so."id", d."user_id", d."organization_id"
)
UPDATE "storage_objects" so
SET
  "owner_user_id" = ro.owner_user_id,
  "organization_id" = ro.organization_id,
  "api_client_id" = ro.api_client_id
FROM resolved_ownership ro
WHERE so."id" = ro.storage_object_id
  AND so."owner_user_id" IS NULL;

-- 5. Enforce ownership invariants, file coordinate integrity, referential integrity, composite API-client binding, and lookup indexes.
ALTER TABLE "files"
  ADD CONSTRAINT "files_ephemeral_or_storage_object_check" CHECK (
    (
      "storage_object_id" IS NULL
      AND "storage_key" LIKE 'ephemeral/%'
      AND char_length("storage_key") > 10
    )
    OR (
      "storage_object_id" IS NOT NULL
      AND btrim("storage_key") <> ''
      AND "storage_key" NOT LIKE 'ephemeral/%'
    )
  );

ALTER TABLE "storage_objects"
  ADD CONSTRAINT "storage_objects_tenant_scope_check" CHECK (
    ("owner_user_id" IS NULL AND "organization_id" IS NULL AND "api_client_id" IS NULL)
    OR ("owner_user_id" IS NOT NULL AND ("api_client_id" IS NULL OR "organization_id" IS NOT NULL))
  );

ALTER TABLE "storage_objects"
  ADD CONSTRAINT "storage_objects_owner_user_id_fkey"
  FOREIGN KEY ("owner_user_id") REFERENCES "users"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "storage_objects"
  ADD CONSTRAINT "storage_objects_organization_id_fkey"
  FOREIGN KEY ("organization_id") REFERENCES "organizations"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "storage_objects"
  ADD CONSTRAINT "storage_objects_api_client_organization_fkey"
  FOREIGN KEY ("api_client_id", "organization_id") REFERENCES "api_clients"("id", "organization_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE INDEX "storage_objects_owner_user_id_idx"
  ON "storage_objects"("owner_user_id");

CREATE INDEX "storage_objects_organization_id_idx"
  ON "storage_objects"("organization_id");

CREATE INDEX "storage_objects_api_client_id_organization_id_idx"
  ON "storage_objects"("api_client_id", "organization_id");

-- 6. Narrow boolean helper verifying that an API client belongs to the caller's active GUC scope
-- and execution user (cannot be used as a cross-tenant existence oracle).
CREATE OR REPLACE FUNCTION app_api_client_matches_tenant(
  p_organization_id uuid,
  p_api_client_id uuid,
  p_user_id uuid,
  p_require_active boolean DEFAULT false
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT
    p_organization_id IS NOT NULL
    AND p_api_client_id IS NOT NULL
    AND p_user_id IS NOT NULL
    AND p_organization_id = NULLIF(pg_catalog.current_setting('app.current_organization_id', true), '')::uuid
    AND (
      NULLIF(pg_catalog.current_setting('app.current_api_client_id', true), '') IS NULL
      OR p_api_client_id = NULLIF(pg_catalog.current_setting('app.current_api_client_id', true), '')::uuid
    )
    AND EXISTS (
      SELECT 1
      FROM public.api_clients c
      JOIN public.organizations o ON o.id = c.organization_id
      WHERE c.id = p_api_client_id
        AND c.organization_id = p_organization_id
        AND c.created_by_user_id = p_user_id
        AND (NOT p_require_active OR (c.status = 'ACTIVE' AND o.status = 'ACTIVE'))
    )
$$;

REVOKE ALL ON FUNCTION app_api_client_matches_tenant(uuid, uuid, uuid, boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_api_client_matches_tenant(uuid, uuid, uuid, boolean) FROM dip_retention;
GRANT EXECUTE ON FUNCTION app_api_client_matches_tenant(uuid, uuid, uuid, boolean) TO dip_app;

-- 7. Guard storage_objects coordinate & attributed-ownership immutability and cross-table tenant/API-client alignment.
CREATE OR REPLACE FUNCTION enforce_storage_object_immutability()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW."provider" IS DISTINCT FROM OLD."provider"
     OR NEW."bucket" IS DISTINCT FROM OLD."bucket"
     OR NEW."object_key" IS DISTINCT FROM OLD."object_key" THEN
    RAISE EXCEPTION 'STORAGE_OBJECT_COORDINATES_IMMUTABLE: provider, bucket, and object_key cannot be modified'
      USING ERRCODE = '23514';
  END IF;

  IF OLD."owner_user_id" IS NOT NULL AND (
     NEW."owner_user_id" IS DISTINCT FROM OLD."owner_user_id"
     OR NEW."organization_id" IS DISTINCT FROM OLD."organization_id"
     OR NEW."api_client_id" IS DISTINCT FROM OLD."api_client_id"
  ) THEN
    RAISE EXCEPTION 'STORAGE_OBJECT_OWNERSHIP_IMMUTABLE: attributed storage_object ownership cannot be reassigned'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION enforce_storage_object_immutability() FROM PUBLIC, dip_app, dip_retention;

CREATE TRIGGER storage_objects_immutability_guard
  BEFORE UPDATE ON "storage_objects"
  FOR EACH ROW
  EXECUTE FUNCTION enforce_storage_object_immutability();

CREATE OR REPLACE FUNCTION enforce_file_storage_object_tenant_match()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_doc_user_id uuid;
  v_doc_org_id uuid;
  v_obj_owner_user_id uuid;
  v_obj_org_id uuid;
  v_obj_api_client_id uuid;
  v_obj_object_key text;
  v_obj_deleted_at timestamp(3);
  v_ctx_api_client_id uuid;
BEGIN
  IF NEW."storage_object_id" IS NULL THEN
    IF NEW."storage_key" IS NULL
       OR NEW."storage_key" NOT LIKE 'ephemeral/%'
       OR pg_catalog.char_length(NEW."storage_key") <= pg_catalog.char_length('ephemeral/') THEN
      RAISE EXCEPTION 'FILE_STORAGE_OBJECT_REQUIRED: non-ephemeral files must reference an authorized storage_object'
        USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'UPDATE'
       AND (
         NEW."storage_key" IS DISTINCT FROM OLD."storage_key"
         OR NEW."document_id" IS DISTINCT FROM OLD."document_id"
         OR NEW."storage_object_id" IS DISTINCT FROM OLD."storage_object_id"
       ) THEN
      RAISE EXCEPTION 'FILE_STORAGE_COORDINATES_IMMUTABLE: file document_id, storage_object_id, and storage_key are immutable'
        USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
  END IF;

  SELECT d."user_id", d."organization_id"
    INTO v_doc_user_id, v_doc_org_id
    FROM public."documents" d
   WHERE d."id" = NEW."document_id";

  IF NOT FOUND THEN
    RAISE EXCEPTION 'FILE_DOCUMENT_NOT_FOUND: parent document does not exist'
      USING ERRCODE = '23503';
  END IF;

  SELECT so."owner_user_id", so."organization_id", so."api_client_id", so."object_key", so."deleted_at"
    INTO v_obj_owner_user_id, v_obj_org_id, v_obj_api_client_id, v_obj_object_key, v_obj_deleted_at
    FROM public."storage_objects" so
   WHERE so."id" = NEW."storage_object_id";

  IF NOT FOUND THEN
    RAISE EXCEPTION 'FILE_STORAGE_OBJECT_NOT_FOUND: referenced storage_object does not exist'
      USING ERRCODE = '23503';
  END IF;

  IF v_obj_owner_user_id IS NULL
     OR v_obj_owner_user_id IS DISTINCT FROM v_doc_user_id
     OR v_obj_org_id IS DISTINCT FROM v_doc_org_id THEN
    RAISE EXCEPTION 'STORAGE_OBJECT_TENANT_MISMATCH: file document tenant does not match storage_object ownership'
      USING ERRCODE = '42501';
  END IF;

  IF TG_OP = 'INSERT'
     OR NEW."storage_object_id" IS DISTINCT FROM OLD."storage_object_id" THEN
    v_ctx_api_client_id := NULLIF(pg_catalog.current_setting('app.current_api_client_id', true), '')::uuid;
    IF v_obj_api_client_id IS DISTINCT FROM v_ctx_api_client_id THEN
      RAISE EXCEPTION 'STORAGE_OBJECT_API_CLIENT_MISMATCH: file session api_client_id does not match storage_object api_client_id'
        USING ERRCODE = '42501';
    END IF;
  END IF;

  IF TG_OP = 'UPDATE'
     AND (
       NEW."storage_key" IS DISTINCT FROM OLD."storage_key"
       OR NEW."document_id" IS DISTINCT FROM OLD."document_id"
       OR NEW."storage_object_id" IS DISTINCT FROM OLD."storage_object_id"
     ) THEN
    RAISE EXCEPTION 'FILE_STORAGE_COORDINATES_IMMUTABLE: file document_id, storage_object_id, and storage_key are immutable'
      USING ERRCODE = '23514';
  END IF;

  IF TG_OP = 'INSERT' AND v_obj_deleted_at IS NOT NULL THEN
    RAISE EXCEPTION 'FILE_STORAGE_OBJECT_DELETED: cannot link file to a tombstoned storage_object'
      USING ERRCODE = '23514';
  END IF;

  IF NEW."storage_key" IS NULL
     OR pg_catalog.btrim(NEW."storage_key") = ''
     OR NEW."storage_key" LIKE 'ephemeral/%'
     OR NEW."storage_key" IS DISTINCT FROM v_obj_object_key THEN
    RAISE EXCEPTION 'FILE_STORAGE_KEY_MISMATCH: file storage_key does not match linked storage_object object_key'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION enforce_file_storage_object_tenant_match() FROM PUBLIC, dip_app, dip_retention;

CREATE TRIGGER files_storage_object_tenant_guard
  BEFORE INSERT OR UPDATE ON "files"
  FOR EACH ROW
  EXECUTE FUNCTION enforce_file_storage_object_tenant_match();

CREATE OR REPLACE FUNCTION enforce_document_storage_object_tenant_match()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF (NEW."user_id" IS DISTINCT FROM OLD."user_id"
      OR NEW."organization_id" IS DISTINCT FROM OLD."organization_id")
     AND EXISTS (
       SELECT 1
       FROM public."files" f
       JOIN public."storage_objects" so ON so."id" = f."storage_object_id"
       WHERE f."document_id" = NEW."id"
         AND (
           so."owner_user_id" IS DISTINCT FROM NEW."user_id"
           OR so."organization_id" IS DISTINCT FROM NEW."organization_id"
         )
     ) THEN
    RAISE EXCEPTION 'DOCUMENT_STORAGE_OBJECT_TENANT_MISMATCH: cannot change document tenant while linked to storage_objects of another tenant'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION enforce_document_storage_object_tenant_match() FROM PUBLIC, dip_app, dip_retention;

CREATE TRIGGER documents_storage_object_tenant_guard
  BEFORE UPDATE OF "user_id", "organization_id" ON "documents"
  FOR EACH ROW
  EXECUTE FUNCTION enforce_document_storage_object_tenant_match();

-- 8. Enable and FORCE Row-Level Security on storage_objects, scoped explicitly to dip_app and dip_retention.
ALTER TABLE "storage_objects" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "storage_objects" FORCE ROW LEVEL SECURITY;

-- Personal user-scoped storage objects (requires empty organization and API-client GUCs).
CREATE POLICY storage_objects_user_tenant_policy ON "storage_objects"
  FOR ALL
  TO dip_app
  USING (
    "owner_user_id" IS NOT NULL
    AND "organization_id" IS NULL
    AND "api_client_id" IS NULL
    AND "owner_user_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    AND NULLIF(current_setting('app.current_organization_id', true), '') IS NULL
    AND NULLIF(current_setting('app.current_api_client_id', true), '') IS NULL
  )
  WITH CHECK (
    "owner_user_id" IS NOT NULL
    AND "organization_id" IS NULL
    AND "api_client_id" IS NULL
    AND "owner_user_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    AND NULLIF(current_setting('app.current_organization_id', true), '') IS NULL
    AND NULLIF(current_setting('app.current_api_client_id', true), '') IS NULL
  );

-- Organization member / execution-user scope (strictly binds api_client_id to app.current_api_client_id).
CREATE POLICY storage_objects_org_member_select ON "storage_objects"
  FOR SELECT
  TO dip_app
  USING (
    "owner_user_id" IS NOT NULL
    AND "organization_id" IS NOT NULL
    AND "organization_id" = NULLIF(current_setting('app.current_organization_id', true), '')::uuid
    AND app_is_org_member(
      "organization_id",
      NULLIF(current_setting('app.current_user_id', true), '')::uuid
    )
    AND "api_client_id" IS NOT DISTINCT FROM NULLIF(current_setting('app.current_api_client_id', true), '')::uuid
  );

CREATE POLICY storage_objects_org_member_insert ON "storage_objects"
  FOR INSERT
  TO dip_app
  WITH CHECK (
    "owner_user_id" IS NOT NULL
    AND "organization_id" IS NOT NULL
    AND "owner_user_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    AND "organization_id" = NULLIF(current_setting('app.current_organization_id', true), '')::uuid
    AND app_is_org_member(
      "organization_id",
      NULLIF(current_setting('app.current_user_id', true), '')::uuid
    )
    AND "api_client_id" IS NOT DISTINCT FROM NULLIF(current_setting('app.current_api_client_id', true), '')::uuid
    AND (
      "api_client_id" IS NULL
      OR app_api_client_matches_tenant("organization_id", "api_client_id", "owner_user_id", false)
    )
  );

CREATE POLICY storage_objects_org_member_update ON "storage_objects"
  FOR UPDATE
  TO dip_app
  USING (
    "owner_user_id" IS NOT NULL
    AND "organization_id" IS NOT NULL
    AND "organization_id" = NULLIF(current_setting('app.current_organization_id', true), '')::uuid
    AND app_is_org_member(
      "organization_id",
      NULLIF(current_setting('app.current_user_id', true), '')::uuid
    )
    AND "api_client_id" IS NOT DISTINCT FROM NULLIF(current_setting('app.current_api_client_id', true), '')::uuid
  )
  WITH CHECK (
    "owner_user_id" IS NOT NULL
    AND "organization_id" IS NOT NULL
    AND "organization_id" = NULLIF(current_setting('app.current_organization_id', true), '')::uuid
    AND app_is_org_member(
      "organization_id",
      NULLIF(current_setting('app.current_user_id', true), '')::uuid
    )
    AND "api_client_id" IS NOT DISTINCT FROM NULLIF(current_setting('app.current_api_client_id', true), '')::uuid
  );

-- Direct API-client context (withApiTenant: organization_id + api_client_id without app.current_user_id).
CREATE POLICY storage_objects_api_client_select ON "storage_objects"
  FOR SELECT
  TO dip_app
  USING (
    "owner_user_id" IS NOT NULL
    AND "organization_id" IS NOT NULL
    AND "api_client_id" IS NOT NULL
    AND NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    AND "organization_id" = NULLIF(current_setting('app.current_organization_id', true), '')::uuid
    AND "api_client_id" = NULLIF(current_setting('app.current_api_client_id', true), '')::uuid
  );

CREATE POLICY storage_objects_api_client_insert ON "storage_objects"
  FOR INSERT
  TO dip_app
  WITH CHECK (
    "owner_user_id" IS NOT NULL
    AND "organization_id" IS NOT NULL
    AND "api_client_id" IS NOT NULL
    AND NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    AND "organization_id" = NULLIF(current_setting('app.current_organization_id', true), '')::uuid
    AND "api_client_id" = NULLIF(current_setting('app.current_api_client_id', true), '')::uuid
    AND app_api_client_matches_tenant("organization_id", "api_client_id", "owner_user_id", true)
  );

CREATE POLICY storage_objects_api_client_update ON "storage_objects"
  FOR UPDATE
  TO dip_app
  USING (
    "owner_user_id" IS NOT NULL
    AND "organization_id" IS NOT NULL
    AND "api_client_id" IS NOT NULL
    AND NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    AND "organization_id" = NULLIF(current_setting('app.current_organization_id', true), '')::uuid
    AND "api_client_id" = NULLIF(current_setting('app.current_api_client_id', true), '')::uuid
  )
  WITH CHECK (
    "owner_user_id" IS NOT NULL
    AND "organization_id" IS NOT NULL
    AND "api_client_id" IS NOT NULL
    AND NULLIF(current_setting('app.current_user_id', true), '') IS NULL
    AND "organization_id" = NULLIF(current_setting('app.current_organization_id', true), '')::uuid
    AND "api_client_id" = NULLIF(current_setting('app.current_api_client_id', true), '')::uuid
    AND app_api_client_matches_tenant("organization_id", "api_client_id", "owner_user_id", true)
  );

-- Restrictive cross-table policy on files so dip_app can never SELECT, INSERT, or UPDATE a File
-- (including reading File.storage_key) when its linked StorageObject is inaccessible in the active scope,
-- when a non-ephemeral File is missing storage_object_id, or when File.storage_key != StorageObject.object_key.
CREATE POLICY files_storage_object_rls_guard ON "files"
  AS RESTRICTIVE
  FOR ALL
  TO dip_app
  USING (
    (
      "storage_object_id" IS NULL
      AND "storage_key" LIKE 'ephemeral/%'
      AND char_length("storage_key") > 10
    )
    OR (
      "storage_object_id" IS NOT NULL
      AND "storage_key" NOT LIKE 'ephemeral/%'
      AND EXISTS (
        SELECT 1
        FROM "storage_objects" so
        WHERE so."id" = "files"."storage_object_id"
          AND so."object_key" = "files"."storage_key"
      )
    )
  )
  WITH CHECK (
    (
      "storage_object_id" IS NULL
      AND "storage_key" LIKE 'ephemeral/%'
      AND char_length("storage_key") > 10
    )
    OR (
      "storage_object_id" IS NOT NULL
      AND "storage_key" NOT LIKE 'ephemeral/%'
      AND EXISTS (
        SELECT 1
        FROM "storage_objects" so
        WHERE so."id" = "files"."storage_object_id"
          AND so."object_key" = "files"."storage_key"
      )
    )
  );

-- Dedicated least-privilege retention role policies (paired with column-only UPDATE(deleted_at) grant).
CREATE POLICY storage_objects_retention_select ON "storage_objects"
  FOR SELECT
  TO dip_retention
  USING (true);

CREATE POLICY storage_objects_retention_update ON "storage_objects"
  FOR UPDATE
  TO dip_retention
  USING (true)
  WITH CHECK (true);

-- 9. Reconcile least-privilege table/column grants for dip_app and dip_retention.
REVOKE ALL PRIVILEGES ON "storage_objects" FROM dip_app;
GRANT SELECT, INSERT ON "storage_objects" TO dip_app;
GRANT UPDATE ("region", "checksum", "deleted_at") ON "storage_objects" TO dip_app;

REVOKE ALL PRIVILEGES ON "storage_objects" FROM dip_retention;
GRANT SELECT ON "storage_objects" TO dip_retention;
GRANT UPDATE ("deleted_at") ON "storage_objects" TO dip_retention;

COMMIT;
