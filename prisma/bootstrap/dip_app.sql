-- Run as neondb_owner on the target branch after Neon creates the login role.
-- Password creation/rotation remains in Neon and never appears in source control.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dip_app') THEN
    RAISE EXCEPTION 'dip_app must be created by the Neon infrastructure bootstrap first';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_auth_members membership
    JOIN pg_roles member_role ON member_role.oid = membership.member
    JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
    WHERE member_role.rolname = 'dip_app'
      AND granted_role.rolname = 'neon_superuser'
  ) THEN
    RAISE EXCEPTION 'dip_app must not inherit neon_superuser; recreate it as a plain PostgreSQL role';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_roles
    WHERE rolname = 'dip_app'
      AND (
        rolsuper
        OR rolbypassrls
        OR rolcreatedb
        OR rolcreaterole
        OR rolreplication
        OR rolinherit
        OR NOT rolcanlogin
      )
  ) THEN
    RAISE EXCEPTION 'dip_app attributes are not least-privilege; reprovision the role before grants';
  END IF;
END
$$;

REVOKE ALL PRIVILEGES ON DATABASE neondb FROM dip_app;
REVOKE ALL PRIVILEGES ON SCHEMA public FROM dip_app;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM dip_app;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM dip_app;

GRANT CONNECT ON DATABASE neondb TO dip_app;
GRANT USAGE ON SCHEMA public TO dip_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON
  documents,
  files,
  file_versions,
  jobs,
  job_steps,
  tool_executions,
  job_events,
  ai_usage
TO dip_app;
