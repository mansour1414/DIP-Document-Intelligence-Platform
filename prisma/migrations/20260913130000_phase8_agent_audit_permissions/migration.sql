-- Agent audit persistence runs as dip_app. Keep audit access append-only and
-- bind every runtime insert to the transaction-local authenticated tenant.
BEGIN;

ALTER TABLE "audit_logs" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "audit_logs" FORCE ROW LEVEL SECURITY;

CREATE POLICY audit_logs_tenant_insert_policy ON "audit_logs"
  FOR INSERT
  WITH CHECK (
    "user_id" = NULLIF(current_setting('app.current_user_id', true), '')::uuid
  );

GRANT INSERT ON "audit_logs" TO dip_app;

COMMIT;
