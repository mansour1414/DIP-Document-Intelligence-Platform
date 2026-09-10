-- Run with a provisioning/migration role before `prisma migrate deploy`.
-- Deliberately contains no password: credentials are environment-specific and
-- must be set by the platform or secret manager after role creation.
DO $bootstrap$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dip_app') THEN
    CREATE ROLE dip_app
      LOGIN
      NOINHERIT
      NOSUPERUSER
      NOBYPASSRLS
      NOCREATEDB
      NOCREATEROLE
      NOREPLICATION;
  END IF;
END
$bootstrap$;

-- Reassert least-privilege attributes on every provisioning run without
-- changing any environment-managed password.
ALTER ROLE dip_app
  LOGIN
  NOINHERIT
  NOSUPERUSER
  NOBYPASSRLS
  NOCREATEDB
  NOCREATEROLE
  NOREPLICATION;
