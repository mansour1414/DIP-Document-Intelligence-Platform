-- Phase 4 monetization core. Existing economic values are preserved as provisional configuration.
CREATE TYPE "PlanStatus" AS ENUM ('ACTIVE','INACTIVE');
CREATE TYPE "CreditReason" AS ENUM ('TOOL_EXECUTION','AI_USAGE','SUBSCRIPTION_GRANT','PROMOTIONAL_GRANT','PURCHASE','REFUND_REVERSAL','ADMIN_ADJUSTMENT');
CREATE TYPE "InvoiceStatus" AS ENUM ('DRAFT','OPEN','PAID','VOID','UNCOLLECTIBLE');
CREATE TYPE "PaymentStatus" AS ENUM ('PENDING','SUCCEEDED','FAILED','CANCELLED','REFUNDED');
CREATE TYPE "CreditPurchaseStatus" AS ENUM ('PENDING','PAID','GRANTED','FAILED','CANCELLED');
CREATE TYPE "BillingEventStatus" AS ENUM ('RECEIVED','PROCESSED','IGNORED','FAILED');
ALTER TYPE "SubscriptionStatus" RENAME TO "SubscriptionStatusLegacy";
CREATE TYPE "SubscriptionStatus" AS ENUM ('TRIALING','ACTIVE','PAST_DUE','CANCELLED','EXPIRED');

CREATE TABLE "plans"("id" UUID PRIMARY KEY,"code" VARCHAR(32) NOT NULL,"name" VARCHAR(100) NOT NULL,"status" "PlanStatus" NOT NULL DEFAULT 'ACTIVE',"billing_intervals" JSONB NOT NULL DEFAULT '[]',"currencies" JSONB NOT NULL DEFAULT '[]',"version" INTEGER NOT NULL DEFAULT 1,"effective_from" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,"effective_to" TIMESTAMP(3),"created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,"updated_at" TIMESTAMP(3) NOT NULL);
CREATE UNIQUE INDEX "plans_code_key" ON "plans"("code"); CREATE UNIQUE INDEX "plans_code_version_key" ON "plans"("code","version");
INSERT INTO "plans"("id","code","name","billing_intervals","currencies","updated_at") VALUES ('00000000-0000-4000-8000-000000000001','FREE','Free','[]','[]',CURRENT_TIMESTAMP),('00000000-0000-4000-8000-000000000002','PRO','Pro','["monthly","annual"]','[]',CURRENT_TIMESTAMP) ON CONFLICT ("code") DO NOTHING;
CREATE TABLE "plan_entitlements"("id" UUID PRIMARY KEY,"plan_id" UUID NOT NULL REFERENCES "plans"("id") ON DELETE CASCADE,"key" VARCHAR(100) NOT NULL,"value" JSONB NOT NULL,"created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,"updated_at" TIMESTAMP(3) NOT NULL);
CREATE UNIQUE INDEX "plan_entitlements_plan_id_key_key" ON "plan_entitlements"("plan_id","key"); CREATE INDEX "plan_entitlements_plan_id_idx" ON "plan_entitlements"("plan_id");
INSERT INTO "plan_entitlements"("id","plan_id","key","value","updated_at") SELECT gen_random_uuid(),p.id,x.key,x.value,CURRENT_TIMESTAMP FROM "plans" p CROSS JOIN LATERAL jsonb_each(CASE p.code WHEN 'FREE' THEN '{"max_file_size_bytes":26214400,"max_pages_per_file":100,"max_jobs_per_day":20,"max_jobs_per_month":300,"max_concurrent_jobs":2,"credit_allowance":20,"max_ai_credits_per_request":5,"max_ocr_pages_per_month":100,"ai_access":true,"processing_priority":"standard","retention_days":7}'::jsonb ELSE '{"max_file_size_bytes":104857600,"max_pages_per_file":500,"max_jobs_per_day":200,"max_jobs_per_month":3000,"max_concurrent_jobs":8,"credit_allowance":500,"max_ai_credits_per_request":25,"max_ocr_pages_per_month":2000,"ai_access":true,"processing_priority":"high","retention_days":30}'::jsonb END) x ON CONFLICT DO NOTHING;

ALTER TABLE "subscriptions" RENAME COLUMN "plan" TO "legacy_plan";
ALTER TABLE "subscriptions" RENAME COLUMN "status" TO "legacy_status";
ALTER TABLE "subscriptions" ADD COLUMN "plan_id" UUID, ADD COLUMN "status" "SubscriptionStatus" NOT NULL DEFAULT 'ACTIVE', ADD COLUMN "external_reference" VARCHAR(255), ADD COLUMN "starts_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP, ADD COLUMN "cancel_at_period_end" BOOLEAN NOT NULL DEFAULT false, ADD COLUMN "cancelled_at" TIMESTAMP(3);
UPDATE "subscriptions" s SET "plan_id"=p.id,"status"=(CASE s.legacy_status::text WHEN 'INACTIVE' THEN 'EXPIRED' ELSE s.legacy_status::text END)::"SubscriptionStatus" FROM "plans" p WHERE p.code=CASE WHEN s.legacy_plan::text='PRO' THEN 'PRO' ELSE 'FREE' END;
ALTER TABLE "subscriptions" ALTER COLUMN "plan_id" SET NOT NULL;
ALTER TABLE "subscriptions" ADD CONSTRAINT "subscriptions_plan_id_fkey" FOREIGN KEY("plan_id") REFERENCES "plans"("id");
CREATE UNIQUE INDEX "subscriptions_external_reference_key" ON "subscriptions"("external_reference"); CREATE INDEX "subscriptions_user_id_status_current_period_end_idx" ON "subscriptions"("user_id","status","current_period_end");

ALTER TABLE "credit_ledger" ADD COLUMN "idempotency_key" VARCHAR(255), ADD COLUMN "reason" "CreditReason", ADD COLUMN "metadata" JSONB NOT NULL DEFAULT '{}';
UPDATE "credit_ledger" SET "idempotency_key"='legacy:'||id::text,"reason"=CASE WHEN type='USAGE' THEN 'TOOL_EXECUTION'::"CreditReason" WHEN type='PURCHASE' THEN 'PURCHASE'::"CreditReason" WHEN type='REFUND' THEN 'REFUND_REVERSAL'::"CreditReason" ELSE 'PROMOTIONAL_GRANT'::"CreditReason" END;
ALTER TABLE "credit_ledger" ALTER COLUMN "idempotency_key" SET NOT NULL, ALTER COLUMN "reason" SET NOT NULL;
CREATE UNIQUE INDEX "credit_ledger_user_id_idempotency_key_key" ON "credit_ledger"("user_id","idempotency_key");
ALTER TABLE "credit_ledger" ADD CONSTRAINT "credit_amount_nonzero" CHECK(amount<>0), ADD CONSTRAINT "credit_balance_nonnegative" CHECK(balance>=0);
CREATE FUNCTION prevent_credit_ledger_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'credit ledger is append-only'; END $$;
CREATE TRIGGER credit_ledger_append_only BEFORE UPDATE OR DELETE ON "credit_ledger" FOR EACH ROW EXECUTE FUNCTION prevent_credit_ledger_mutation();

CREATE TABLE "invoices"("id" UUID PRIMARY KEY,"user_id" UUID NOT NULL REFERENCES "users"("id"),"subscription_id" UUID REFERENCES "subscriptions"("id"),"number" VARCHAR(100) NOT NULL UNIQUE,"status" "InvoiceStatus" NOT NULL DEFAULT 'DRAFT',"subtotal_minor" BIGINT NOT NULL,"tax_minor" BIGINT,"total_minor" BIGINT NOT NULL,"currency" CHAR(3) NOT NULL,"issued_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,"due_at" TIMESTAMP(3),"paid_at" TIMESTAMP(3),"external_reference" VARCHAR(255) UNIQUE,"created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,CONSTRAINT invoice_amounts_valid CHECK(subtotal_minor>=0 AND (tax_minor IS NULL OR tax_minor>=0) AND total_minor=subtotal_minor+COALESCE(tax_minor,0)),CONSTRAINT invoice_currency_valid CHECK(currency ~ '^[A-Z]{3}$'));
CREATE INDEX "invoices_user_id_issued_at_idx" ON "invoices"("user_id","issued_at");
CREATE TABLE "payments"("id" UUID PRIMARY KEY,"user_id" UUID NOT NULL REFERENCES "users"("id"),"invoice_id" UUID REFERENCES "invoices"("id"),"amount_minor" BIGINT NOT NULL,"currency" CHAR(3) NOT NULL,"status" "PaymentStatus" NOT NULL DEFAULT 'PENDING',"external_reference" VARCHAR(255) UNIQUE,"failure_code" VARCHAR(100),"failure_reason" VARCHAR(500),"paid_at" TIMESTAMP(3),"created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,CONSTRAINT payment_amount_valid CHECK(amount_minor>=0),CONSTRAINT payment_currency_valid CHECK(currency ~ '^[A-Z]{3}$'));
CREATE INDEX "payments_user_id_created_at_idx" ON "payments"("user_id","created_at");
CREATE TABLE "credit_purchases"("id" UUID PRIMARY KEY,"user_id" UUID NOT NULL REFERENCES "users"("id"),"invoice_id" UUID REFERENCES "invoices"("id"),"payment_id" UUID REFERENCES "payments"("id"),"credits" DECIMAL(12,2) NOT NULL,"amount_minor" BIGINT NOT NULL,"currency" CHAR(3) NOT NULL,"status" "CreditPurchaseStatus" NOT NULL DEFAULT 'PENDING',"idempotency_key" VARCHAR(255) NOT NULL UNIQUE,"granted_at" TIMESTAMP(3),"created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,CONSTRAINT purchase_values_valid CHECK(credits>0 AND amount_minor>=0),CONSTRAINT purchase_currency_valid CHECK(currency ~ '^[A-Z]{3}$'));
CREATE INDEX "credit_purchases_user_id_created_at_idx" ON "credit_purchases"("user_id","created_at");
CREATE TABLE "usage_events"("id" UUID PRIMARY KEY,"user_id" UUID NOT NULL REFERENCES "users"("id"),"kind" VARCHAR(50) NOT NULL,"quantity" INTEGER NOT NULL DEFAULT 1,"reference" VARCHAR(255) NOT NULL,"occurred_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,"metadata" JSONB NOT NULL DEFAULT '{}',CONSTRAINT usage_quantity_positive CHECK(quantity>0),UNIQUE("user_id","kind","reference"));
CREATE INDEX "usage_events_user_id_kind_occurred_at_idx" ON "usage_events"("user_id","kind","occurred_at");
CREATE TABLE "ai_provider_prices"("id" UUID PRIMARY KEY,"provider" VARCHAR(50) NOT NULL,"model" VARCHAR(100) NOT NULL,"input_price_per_million" DECIMAL(18,6) NOT NULL,"output_price_per_million" DECIMAL(18,6) NOT NULL,"currency" CHAR(3) NOT NULL,"effective_from" TIMESTAMP(3) NOT NULL,"effective_to" TIMESTAMP(3),"source" VARCHAR(255),"notes" TEXT,"created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,CONSTRAINT ai_prices_nonnegative CHECK(input_price_per_million>=0 AND output_price_per_million>=0),CONSTRAINT ai_price_currency_valid CHECK(currency ~ '^[A-Z]{3}$'),UNIQUE("provider","model","effective_from"));
CREATE INDEX "ai_provider_prices_provider_model_effective_from_effective_to_idx" ON "ai_provider_prices"("provider","model","effective_from","effective_to");
CREATE TABLE "billing_events"("id" UUID PRIMARY KEY,"user_id" UUID REFERENCES "users"("id"),"provider" VARCHAR(50) NOT NULL,"external_event_id" VARCHAR(255) NOT NULL,"type" VARCHAR(100) NOT NULL,"status" "BillingEventStatus" NOT NULL DEFAULT 'RECEIVED',"payload" JSONB NOT NULL DEFAULT '{}',"processed_at" TIMESTAMP(3),"created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,UNIQUE("provider","external_event_id"));
CREATE INDEX "billing_events_user_id_created_at_idx" ON "billing_events"("user_id","created_at");

-- User billing data is fail-closed without app.current_user_id.
DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['subscriptions','invoices','payments','credit_purchases','usage_events','billing_events'] LOOP EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t); EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t); EXECUTE format('CREATE POLICY %I ON %I USING (user_id = NULLIF(current_setting(''app.current_user_id'',true),'''')::uuid) WITH CHECK (user_id = NULLIF(current_setting(''app.current_user_id'',true),'''')::uuid)',t||'_tenant',t); END LOOP; END $$;
ALTER TABLE "credit_ledger" ENABLE ROW LEVEL SECURITY; ALTER TABLE "credit_ledger" FORCE ROW LEVEL SECURITY;
CREATE POLICY "credit_ledger_tenant" ON "credit_ledger" USING(user_id=NULLIF(current_setting('app.current_user_id',true),'')::uuid) WITH CHECK(user_id=NULLIF(current_setting('app.current_user_id',true),'')::uuid);
GRANT SELECT ON "plans","plan_entitlements" TO dip_app;
GRANT SELECT,INSERT,UPDATE ON "subscriptions","invoices","payments","credit_purchases","usage_events","billing_events" TO dip_app;
GRANT SELECT,INSERT ON "credit_ledger" TO dip_app;
GRANT SELECT ON "ai_provider_prices" TO dip_app;
