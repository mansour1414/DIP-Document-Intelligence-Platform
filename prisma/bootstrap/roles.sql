-- Pre-migration role bootstrap & read-only role posture verification for DIP.
--
-- Operational separation of duties (PostgreSQL 18 / Neon compatible):
-- 1. Independent first-time role-provisioning gate (privileged cluster admin):
--    - Self-hosted / disposable PostgreSQL 18: execute this file as a PostgreSQL superuser
--      (rolsuper = true, e.g. postgres) to create or remediate least-privilege dip_app and
--      dip_retention roles without embedding credentials in source control.
--    - Managed PostgreSQL 18 (e.g. Neon, where neondb_owner has rolsuper = false): provision
--      dip_app and dip_retention once through the independent privileged SQL role-bootstrap gate
--      with exact attributes (LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
--      NOREPLICATION) and zero role memberships (never via UI flows that auto-grant neon_superuser).
--    - Provision credentials externally via secret management (e.g. ALTER ROLE dip_app WITH PASSWORD ...).
-- 2. Routine pre-migration verification gate (non-superuser schema owner, e.g. neondb_owner):
--    - When invoked by a non-superuser (rolsuper = false), this script NEVER executes CREATE ROLE
--      or ALTER ROLE (which PostgreSQL 18 forbids for NOSUPERUSER / NOBYPASSRLS attributes).
--    - Instead, it performs a read-only, fail-closed catalog verification on pg_catalog.pg_roles
--      and pg_catalog.pg_auth_members for both dip_app and dip_retention, failing closed with an
--      explicit diagnostic if either role is missing, elevated, or holds unsafe memberships.

DO $$
DECLARE
  v_caller_is_super boolean;
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
    RAISE EXCEPTION 'ROLE_BOOTSTRAP_CALLER_INVALID: prisma/bootstrap/roles.sql must not execute as runtime or retention role (%).', current_user
      USING ERRCODE = '42501';
  END IF;

  SELECT r.rolsuper
    INTO v_caller_is_super
    FROM pg_catalog.pg_roles r
   WHERE r.rolname = current_user;

  v_caller_is_super := coalesce(v_caller_is_super, false);

  FOREACH v_target_role IN ARRAY ARRAY['dip_app', 'dip_retention'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_target_role) THEN
      IF NOT v_caller_is_super THEN
        RAISE EXCEPTION 'ROLE_BOOTSTRAP_PRIVILEGE_REQUIRED: required role "%" does not exist and caller "%" is not a PostgreSQL superuser; provision least-privilege roles via the independent privileged role-bootstrap gate before running migrations',
          v_target_role,
          current_user
          USING ERRCODE = '42501';
      END IF;

      EXECUTE format(
        'CREATE ROLE %I LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION',
        v_target_role
      );
    END IF;

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

    IF v_caller_is_super AND (
      NOT v_rolcanlogin
      OR v_rolsuper
      OR v_rolbypassrls
      OR v_rolinherit
      OR v_rolcreatedb
      OR v_rolcreaterole
      OR v_rolreplication
    ) THEN
      EXECUTE format(
        'ALTER ROLE %I LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION',
        v_target_role
      );

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
      RAISE EXCEPTION 'ROLE_PREFLIGHT_INVALID: role "%" violates least-privilege attributes [%]; remediate via the independent privileged role-bootstrap gate before running migrations',
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
