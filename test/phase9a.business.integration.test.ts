import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import pg from "pg";
const integration = process.env.DIP_RLS_TEST_DATABASE_URL && process.env.DIP_RLS_TEST_OWNER_URL ? test : test.skip;

integration("Phase 9A API client/key lifecycle authenticates, rotates, revokes, and audits without secrets", async () => {
  const owner = new pg.Client({ connectionString: process.env.DIP_RLS_TEST_OWNER_URL }); await owner.connect();
  const user = randomUUID(), attacker = randomUUID(), organization = randomUUID(), attackerOrganization = randomUUID();
  const cleanup = async () => { await owner.query("DELETE FROM audit_logs WHERE organization_id=ANY($1::uuid[])", [[organization, attackerOrganization]]); await owner.query("DELETE FROM api_keys WHERE organization_id=ANY($1::uuid[])", [[organization, attackerOrganization]]); await owner.query("DELETE FROM api_idempotency_records WHERE organization_id=ANY($1::uuid[])", [[organization, attackerOrganization]]); await owner.query("DELETE FROM api_clients WHERE organization_id=ANY($1::uuid[])", [[organization, attackerOrganization]]); await owner.query("DELETE FROM memberships WHERE organization_id=ANY($1::uuid[])", [[organization, attackerOrganization]]); await owner.query("DELETE FROM organizations WHERE id=ANY($1::uuid[])", [[organization, attackerOrganization]]); await owner.query("DELETE FROM users WHERE id=ANY($1::uuid[])", [[user, attacker]]); };
  try {
    await cleanup(); await owner.query("INSERT INTO users(id,email,status,created_at,updated_at) VALUES($1,$2,'ACTIVE',now(),now()),($3,$4,'ACTIVE',now(),now())", [user, `lifecycle-${user}@example.invalid`, attacker, `attacker-${attacker}@example.invalid`]);
    await owner.query("INSERT INTO organizations(id,name,slug,plan,status,created_at,updated_at) VALUES($1,'Lifecycle',$2,'FREE','ACTIVE',now(),now()),($3,'Attacker',$4,'FREE','ACTIVE',now(),now())", [organization, `lifecycle-${organization}`, attackerOrganization, `attacker-${attackerOrganization}`]);
    await owner.query("INSERT INTO memberships(id,user_id,organization_id,role,created_at,updated_at) VALUES(gen_random_uuid(),$1,$2,'OWNER',now(),now()),(gen_random_uuid(),$3,$4,'OWNER',now(),now())", [user, organization, attacker, attackerOrganization]);
    const { createApiClient, createApiKey, rotateApiKey, revokeApiKey } = await import("../src/lib/api-platform/clients"); const { authenticateApiRequest, ApiAuthenticationError } = await import("../src/lib/api-platform/auth");
    const client = await createApiClient(user, organization, "CI client"); const created = await createApiKey(user, organization, client.id, "CI key", ["jobs:create"]);
    assert.match(created.key, /^dip_v1_/); const principal = await authenticateApiRequest(new Request("https://example.invalid", { headers: { authorization: `Bearer ${created.key}` } })); assert.equal(principal.organizationId, organization); assert.deepEqual(principal.scopes, ["jobs:create"]);
    await assert.rejects(() => revokeApiKey(attacker, attackerOrganization, created.id), /NOT_FOUND/);
    const rotated = await rotateApiKey(user, organization, created.id); await assert.rejects(() => authenticateApiRequest(new Request("https://example.invalid", { headers: { authorization: `Bearer ${created.key}` } })), ApiAuthenticationError); assert.equal((await authenticateApiRequest(new Request("https://example.invalid", { headers: { authorization: `Bearer ${rotated.key}` } }))).apiClientId, client.id);
    await revokeApiKey(user, organization, rotated.id); await assert.rejects(() => authenticateApiRequest(new Request("https://example.invalid", { headers: { authorization: `Bearer ${rotated.key}` } })), ApiAuthenticationError);
    const audit = await owner.query("SELECT action,details::text FROM audit_logs WHERE organization_id=$1 ORDER BY created_at", [organization]); assert.deepEqual(audit.rows.map(row => row.action), ["api_client.created", "api_key.created", "api_key.rotated", "api_key.revoked"]); assert.ok(audit.rows.every(row => !row.details.includes(created.key) && !row.details.includes(rotated.key)));
  } finally { try { await cleanup(); } finally { const { db } = await import("../src/lib/db"); await db.$disconnect(); await owner.end(); } }
});
