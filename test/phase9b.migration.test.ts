import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
const sql = readFileSync(new URL("../prisma/migrations/20260914160000_phase9b_public_api/migration.sql", import.meta.url), "utf8");
test("public jobs carry composite organization/client ownership", () => { assert.match(sql, /jobs_api_client_organization_fkey/); assert.match(sql, /jobs_public_scope_check/); assert.match(sql, /jobs_api_client_policy/); });
test("API usage is content-free, nonnegative, append-only, and RLS protected", () => { assert.match(sql, /CREATE TABLE "api_usage"/); assert.match(sql, /bytes_in/); assert.match(sql, /credits_used/); assert.match(sql, /FORCE ROW LEVEL SECURITY/); assert.match(sql, /GRANT SELECT, INSERT ON "api_usage"/); assert.doesNotMatch(sql, /document_content|request_body|authorization/i); });
test("API clients bind to an organization execution identity without resets", () => { assert.match(sql, /created_by_user_id/); assert.match(sql, /API client has no organization member execution identity/); assert.doesNotMatch(sql, /DROP TABLE|TRUNCATE/i); });
