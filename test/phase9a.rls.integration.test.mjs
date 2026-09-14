import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import pg from "pg";
const { Client } = pg;
const integration = process.env.DIP_RLS_TEST_DATABASE_URL && process.env.DIP_RLS_TEST_OWNER_URL ? test : test.skip;

integration("Phase 9A RLS blocks cross-organization reads and mutations with NOBYPASSRLS role", async () => {
  const owner = new Client({ connectionString: process.env.DIP_RLS_TEST_OWNER_URL }); const runtime = new Client({ connectionString: process.env.DIP_RLS_TEST_DATABASE_URL }); await owner.connect(); await runtime.connect();
  const userA = randomUUID(), userB = randomUUID(), orgA = randomUUID(), orgB = randomUUID(), memberA = randomUUID(), memberB = randomUUID(), clientA = randomUUID(), clientB = randomUUID(), keyA = randomUUID(), keyB = randomUUID();
  const tenant = async (user, organization, work) => { await runtime.query("BEGIN"); try { await runtime.query("SELECT set_config('app.current_user_id',$1,true),set_config('app.current_organization_id',$2,true)", [user, organization]); const result = await work(); await runtime.query("COMMIT"); return result; } catch (error) { await runtime.query("ROLLBACK"); throw error; } };
  const cleanup = async () => { await owner.query("DELETE FROM api_keys WHERE organization_id=ANY($1::uuid[])", [[orgA, orgB]]); await owner.query("DELETE FROM api_idempotency_records WHERE organization_id=ANY($1::uuid[])", [[orgA, orgB]]); await owner.query("DELETE FROM api_clients WHERE organization_id=ANY($1::uuid[])", [[orgA, orgB]]); await owner.query("DELETE FROM memberships WHERE organization_id=ANY($1::uuid[])", [[orgA, orgB]]); await owner.query("DELETE FROM organizations WHERE id=ANY($1::uuid[])", [[orgA, orgB]]); await owner.query("DELETE FROM users WHERE id=ANY($1::uuid[])", [[userA, userB]]); };
  try {
    await cleanup(); await owner.query("INSERT INTO users(id,email,status,created_at,updated_at) VALUES($1,$2,'ACTIVE',now(),now()),($3,$4,'ACTIVE',now(),now())", [userA, `p9a-${userA}@example.invalid`, userB, `p9b-${userB}@example.invalid`]);
    await owner.query("INSERT INTO organizations(id,name,slug,plan,status,created_at,updated_at) VALUES($1,'A',$2,'FREE','ACTIVE',now(),now()),($3,'B',$4,'FREE','ACTIVE',now(),now())", [orgA, `a-${orgA}`, orgB, `b-${orgB}`]);
    await owner.query("INSERT INTO memberships(id,user_id,organization_id,role,created_at,updated_at) VALUES($1,$2,$3,'MEMBER',now(),now()),($4,$5,$6,'OWNER',now(),now())", [memberA, userA, orgA, memberB, userB, orgB]);
    await owner.query("INSERT INTO api_clients(id,organization_id,name,status,created_at,updated_at) VALUES($1,$2,'A','ACTIVE',now(),now()),($3,$4,'B','ACTIVE',now(),now())", [clientA, orgA, clientB, orgB]);
    await owner.query("INSERT INTO api_keys(id,organization_id,api_client_id,name,key_hash,key_prefix,status,scopes,created_at,updated_at) VALUES($1,$2,$3,'A',$4,$5,'ACTIVE','[]',now(),now()),($6,$7,$8,'B',$9,$10,'ACTIVE','[]',now(),now())", [keyA, orgA, clientA, "0".repeat(64), keyA.replaceAll("-", "").slice(0, 16), keyB, orgB, clientB, "1".repeat(64), keyB.replaceAll("-", "").slice(0, 16)]);
    await tenant(userA, orgA, async () => { assert.deepEqual((await runtime.query("SELECT id FROM organizations")).rows.map(r => r.id), [orgA]); assert.deepEqual((await runtime.query("SELECT id FROM api_clients")).rows.map(r => r.id), [clientA]); assert.deepEqual((await runtime.query("SELECT id FROM api_keys")).rows.map(r => r.id), [keyA]); assert.equal((await runtime.query("UPDATE api_keys SET status='REVOKED' WHERE id=$1", [keyB])).rowCount, 0); assert.equal((await runtime.query("UPDATE memberships SET role='OWNER' WHERE id=$1", [memberA])).rowCount, 0, "member cannot self-escalate"); assert.equal((await runtime.query("UPDATE memberships SET role='MEMBER' WHERE id=$1", [memberB])).rowCount, 0); });
    assert.equal((await runtime.query("SELECT id FROM organizations")).rowCount, 0); assert.equal((await runtime.query("SELECT id FROM api_keys")).rowCount, 0);
    const role = (await owner.query("SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname='dip_app'")).rows[0]; assert.deepEqual(role, { rolsuper: false, rolbypassrls: false });
  } finally { try { await cleanup(); } finally { await runtime.end(); await owner.end(); } }
});
