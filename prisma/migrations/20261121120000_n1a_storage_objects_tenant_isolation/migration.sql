-- N1-A: StorageObject tenant isolation, ownership invariants, least-privilege RLS, and cross-table guards.
-- Historical migrations remain immutable; this forward-only migration closes the storage_objects RLS gap.

BEGIN;

-- 1. Ensure non-bypass runtime and retention roles remain least-privilege.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dip_app') THEN
    CREATE ROLE dip_app NOLOGIN NOBYPASSRLS NOINHERIT;
  END IF;
  ALTER ROLE dip_app NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;

  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dip_retention') THEN
    CREATE ROLE dip_retention NOLOGIN NOBYPASSRLS NOINHERIT;
  END IF;
  ALTER ROLE dip_retention NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
END
$$;

-- 2. Add explicit nullable ownership columns to storage_objects.
-- Nullable columns allow unlinked historical orphan rows to remain quarantined (NULL)
-- without fabricating fake customer ownership or silently deleting data.
ALTER TABLE "storage_objects"
  ADD COLUMN "owner_user_id" UUID,
  ADD COLUMN "organization_id" UUID,
  ADD COLUMN "api_client_id" UUID;

-- 3. Fail closed if any existing storage_objects row is linked across conflicting tenants
-- or conflicting API clients. Never guess or overwrite ambiguous customer ownership.
DO $$
BEGIN
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
    SELECT 1
    FROM "storage_objects" so
    JOIN "files" f ON f."storage_object_id" = so."id"
    JOIN "documents" d ON d."id" = f."document_id"
    JOIN "jobs" j ON (j."input_file_id" = f."id" OR j."output_file_id" = f."id")
    WHERE j."api_client_id" IS NOT NULL
    GROUP BY so."id", d."organization_id"
    HAVING d."organization_id" IS NULL
        OR BOOL_OR(j."organization_id" IS DISTINCT FROM d."organization_id")
        OR COUNT(DISTINCT j."api_client_id") > 1
  ) THEN
    RAISE EXCEPTION 'STORAGE_OBJECT_API_CLIENT_CONFLICT: storage_objects row has conflicting API client or organization attribution'
      USING ERRCODE = '23514';
  END IF;
END
$$;

-- 4. Deterministically backfill unambiguous ownership from files -> documents (and single-client jobs).
-- Unlinked orphan rows are intentionally left with NULL ownership so they stay quarantined under RLS.
WITH resolved_ownership AS (
  SELECT
    so."id" AS storage_object_id,
    d."user_id" AS owner_user_id,
    d."organization_id" AS organization_id,
    CASE
      WHEN d."organization_id" IS NOT NULL
       AND COUNT(DISTINCT j."api_client_id") = 1
       AND NOT BOOL_OR(j."id" IS NOT NULL AND j."api_client_id" IS NULL)
      THEN MAX(j."api_client_id"::text)::uuid
      ELSE NULL
    END AS api_client_id
  FROM "storage_objects" so
  JOIN "files" f ON f."storage_object_id" = so."id"
  JOIN "documents" d ON d."id" = f."document_id"
  LEFT JOIN "jobs" j
    ON j."organization_id" = d."organization_id"
   AND (j."input_file_id" = f."id" OR j."output_file_id" = f."id")
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

-- 5. Enforce ownership invariants, referential integrity, composite API-client binding, and lookup indexes.
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

-- 6. Narrow boolean helper verifying that an API client belongs to an organization and execution user.
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
  SELECT EXISTS (
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
GRANT EXECUTE ON FUNCTION app_api_client_matches_tenant(uuid, uuid, uuid, boolean) TO dip_app;

-- 7. Guard storage_objects coordinate & attributed-ownership immutability and cross-table tenant alignment.
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

REVOKE ALL ON FUNCTION enforce_storage_object_immutability() FROM PUBLIC;

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
BEGIN
  IF NEW."storage_object_id" IS NULL THEN
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

  SELECT so."owner_user_id", so."organization_id"
    INTO v_obj_owner_user_id, v_obj_org_id
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

  RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION enforce_file_storage_object_tenant_match() FROM PUBLIC;

CREATE TRIGGER files_storage_object_tenant_guard
  BEFORE INSERT OR UPDATE OF "document_id", "storage_object_id" ON "files"
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

REVOKE ALL ON FUNCTION enforce_document_storage_object_tenant_match() FROM PUBLIC;

CREATE TRIGGER documents_storage_object_tenant_guard
  BEFORE UPDATE OF "user_id", "organization_id" ON "documents"
  FOR EACH ROW
  EXECUTE FUNCTION enforce_document_storage_object_tenant_match();

-- 8. Enable and FORCE Row-Level Security on storage_objects.
ALTER TABLE "storage_objects" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "storage_objects" FORCE ROW LEVEL SECURITY;

-- Personal user-scoped storage objects (requires empty organization and API-client GUCs).
CREATE POLICY storage_objects_user_tenant_policy ON "storage_objects"
  FOR ALL
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

-- Organization member / execution-user scope (optionally constrained to a specific API client).
CREATE POLICY storage_objects_org_member_select ON "storage_objects"
  FOR SELECT
  USING (
    "owner_user_id" IS NOT NULL
    AND "organization_id" IS NOT NULL
    AND "organization_id" = NULLIF(current_setting('app.current_organization_id', true), '')::uuid
    AND app_is_org_member(
      "organization_id",
      NULLIF(current_setting('app.current_user_id', true), '')::uuid
    )
    AND (
      NULLIF(current_setting('app.current_api_client_id', true), '') IS NULL
      OR "api_client_id" = NULLIF(current_setting('app.current_api_client_id', true), '')::uuid
    )
  );

CREATE POLICY storage_objects_org_member_insert ON "storage_objects"
  FOR INSERT
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
  USING (
    "owner_user_id" IS NOT NULL
    AND "organization_id" IS NOT NULL
    AND "organization_id" = NULLIF(current_setting('app.current_organization_id', true), '')::uuid
    AND app_is_org_member(
      "organization_id",
      NULLIF(current_setting('app.current_user_id', true), '')::uuid
    )
    AND (
      NULLIF(current_setting('app.current_api_client_id', true), '') IS NULL
      OR "api_client_id" = NULLIF(current_setting('app.current_api_client_id', true), '')::uuid
    )
  )
  WITH CHECK (
    "owner_user_id" IS NOT NULL
    AND "organization_id" IS NOT NULL
    AND "organization_id" = NULLIF(current_setting('app.current_organization_id', true), '')::uuid
    AND app_is_org_member(
      "organization_id",
      NULLIF(current_setting('app.current_user_id', true), '')::uuid
    )
    AND (
      NULLIF(current_setting('app.current_api_client_id', true), '') IS NULL
      OR "api_client_id" = NULLIF(current_setting('app.current_api_client_id', true), '')::uuid
    )
  );

-- Direct API-client context (withApiTenant: organization_id + api_client_id without app.current_user_id).
CREATE POLICY storage_objects_api_client_select ON "storage_objects"
  FOR SELECT
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
