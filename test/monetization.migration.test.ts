import assert from "node:assert/strict";import test from "node:test";import { readFileSync } from "node:fs";
const sql=readFileSync(new URL("../prisma/migrations/20260910120000_phase4_monetization_core/migration.sql",import.meta.url),"utf8");
test("billing user tables have forced RLS",()=>{for(const table of ["subscriptions","invoices","payments","credit_purchases","usage_events","billing_events"])assert.match(sql,new RegExp(`FORCE ROW LEVEL SECURITY[^]*${table}|${table}[^]*FORCE ROW LEVEL SECURITY`))});
test("billing tenant policy uses transaction context",()=>assert.match(sql,/app\.current_user_id/));
test("ledger has an idempotency uniqueness constraint",()=>assert.match(sql,/credit_ledger_user_id_idempotency_key_key/));
test("ledger is append-only",()=>assert.match(sql,/prevent_credit_ledger_mutation/));
test("invoice totals are database checked",()=>assert.match(sql,/total_minor=subtotal_minor\+COALESCE\(tax_minor,0\)/));
test("duplicate provider events are constrained",()=>assert.match(sql,/UNIQUE\("provider","external_event_id"\)/));
test("migration preserves legacy subscription data",()=>{assert.match(sql,/legacy_plan/);assert.match(sql,/legacy_status/);assert.doesNotMatch(sql,/DROP COLUMN/)});
