-- Run after migrations as the database owner to reconcile runtime grants.
-- `roles.sql` deterministically creates/hardens the role before migrations.
-- Password creation/rotation remains environment-owned and never appears here.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dip_app') THEN
    RAISE EXCEPTION 'run prisma/bootstrap/roles.sql before migrations';
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

DO $revoke_database$
BEGIN
  EXECUTE format('REVOKE ALL PRIVILEGES ON DATABASE %I FROM dip_app', current_database());
END
$revoke_database$;
REVOKE ALL PRIVILEGES ON SCHEMA public FROM dip_app;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM dip_app;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM dip_app;

DO $grant_database$
BEGIN
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO dip_app', current_database());
END
$grant_database$;
GRANT USAGE ON SCHEMA public TO dip_app;
GRANT SELECT, INSERT ON users TO dip_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON
  documents,
  files,
  file_versions,
  jobs,
  job_steps,
  tool_executions,
  job_events,
  ai_usage
  ,workflows
  ,workflow_versions
  ,workflow_runs
  ,agent_runs
  ,agent_plan_versions
  ,organizations
  ,memberships
  ,teams
  ,api_clients
  ,api_keys
  ,api_idempotency_records
TO dip_app;

GRANT SELECT, INSERT, UPDATE ON storage_objects TO dip_app;
GRANT INSERT ON audit_logs TO dip_app;

GRANT SELECT ON plans, plan_entitlements, ai_provider_prices TO dip_app;
GRANT SELECT, INSERT ON credit_ledger TO dip_app;
GRANT SELECT, INSERT, UPDATE ON
  subscriptions,
  invoices,
  payments,
  credit_purchases,
  usage_events,
  billing_events
TO dip_app;
