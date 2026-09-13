-- CR-003: narrowly scoped pre-authentication and authenticated identity access.
BEGIN;

ALTER TABLE "users" ENABLE ROW LEVEL SECURITY;

CREATE POLICY users_authenticated_select ON "users"
  FOR SELECT
  USING ("id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid);

CREATE POLICY users_auth_email_select ON "users"
  FOR SELECT
  USING (lower("email") = NULLIF(current_setting('app.auth_email', true), ''));

CREATE POLICY users_auth_email_insert ON "users"
  FOR INSERT
  WITH CHECK (
    "email" = lower(btrim("email"))
    AND "email" = NULLIF(current_setting('app.auth_email', true), '')
  );

COMMIT;
