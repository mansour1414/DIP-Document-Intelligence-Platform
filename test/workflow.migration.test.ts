import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
const sql = readFileSync(new URL("../prisma/migrations/20260910180000_phase7_workflows/migration.sql", import.meta.url), "utf8");
test("workflow migration versions definitions and binds runs immutably", () => { assert.match(sql, /workflow_versions_workflow_id_version_key/); assert.match(sql, /workflow_run_id_workflow_node_id_key/); assert.match(sql, /workflow_version_id_fkey[^]*ON DELETE RESTRICT/); });
test("all workflow tenant tables enable RLS and fail closed through current tenant context", () => { for (const table of ["workflows", "workflow_versions", "workflow_runs"]) { assert.match(sql, new RegExp(`ALTER TABLE "${table}" ENABLE ROW LEVEL SECURITY`)); assert.match(sql, new RegExp(`CREATE POLICY ${table.replace(/s$/, "")}`)); } assert.match(sql, /current_setting\('app\.current_user_id', true\)/); });
test("runtime grants include workflow tables without elevated role changes", () => { const grants = readFileSync(new URL("../prisma/bootstrap/dip_app.sql", import.meta.url), "utf8"); for (const table of ["workflows", "workflow_versions", "workflow_runs"]) assert.match(grants, new RegExp(table)); assert.doesNotMatch(grants, /BYPASSRLS|SUPERUSER/); });
