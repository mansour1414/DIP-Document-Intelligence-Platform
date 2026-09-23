-- A scheduled retention sweep is intentionally cross-tenant, but must not use
-- the schema owner or the application role. The dedicated role has only the
-- row visibility and column updates required by the retention service.
DO $role$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dip_retention') THEN
    CREATE ROLE dip_retention LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
  END IF;
END
$role$;

DO $role_guard$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = 'dip_retention'
      AND (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolreplication OR rolinherit OR NOT rolcanlogin)
  ) OR EXISTS (
    SELECT 1 FROM pg_auth_members membership
    JOIN pg_roles member_role ON member_role.oid = membership.member
    WHERE member_role.rolname = 'dip_retention'
  ) THEN
    RAISE EXCEPTION 'dip_retention is not a standalone least-privilege role';
  END IF;
END
$role_guard$;
REVOKE ALL PRIVILEGES ON SCHEMA public FROM dip_retention;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM dip_retention;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM dip_retention;
DO $database$
BEGIN
  EXECUTE format('REVOKE ALL PRIVILEGES ON DATABASE %I FROM dip_retention', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO dip_retention', current_database());
END
$database$;
GRANT USAGE ON SCHEMA public TO dip_retention;
GRANT SELECT ON users, plans, subscriptions, documents, files, jobs, storage_objects TO dip_retention;
GRANT UPDATE (status, error_code, completed_at, updated_at) ON jobs TO dip_retention;
GRANT UPDATE (status, updated_at) ON documents TO dip_retention;
GRANT UPDATE (deleted_at) ON storage_objects TO dip_retention;

CREATE POLICY users_retention_select ON "users"
  FOR SELECT TO dip_retention USING (true);
CREATE POLICY subscriptions_retention_select ON "subscriptions"
  FOR SELECT TO dip_retention USING (true);
CREATE POLICY documents_retention_select ON "documents"
  FOR SELECT TO dip_retention USING (true);
CREATE POLICY documents_retention_update ON "documents"
  FOR UPDATE TO dip_retention USING (true) WITH CHECK (true);
CREATE POLICY files_retention_select ON "files"
  FOR SELECT TO dip_retention USING (true);
CREATE POLICY jobs_retention_select ON "jobs"
  FOR SELECT TO dip_retention USING (true);
CREATE POLICY jobs_retention_update ON "jobs"
  FOR UPDATE TO dip_retention USING (true) WITH CHECK (true);
