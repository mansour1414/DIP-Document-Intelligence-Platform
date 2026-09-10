import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import pg from "pg";
const { Client } = pg;
const integration = process.env.DIP_RLS_TEST_DATABASE_URL && process.env.DIP_RLS_TEST_OWNER_URL ? test : test.skip;

integration("workflow RLS prevents cross-tenant read, update, delete, run access and fails closed", async () => {
  const owner = new Client({ connectionString: process.env.DIP_RLS_TEST_OWNER_URL }); const runtime = new Client({ connectionString: process.env.DIP_RLS_TEST_DATABASE_URL }); await owner.connect(); await runtime.connect();
  const a = randomUUID(), b = randomUUID(), workflowA = randomUUID(), workflowB = randomUUID(), versionA = randomUUID(), versionB = randomUUID(), runA = randomUUID(), runB = randomUUID();
  const users = [a, b]; const definition = JSON.stringify({ schemaVersion: 1, nodes: [{ id: "compress", toolId: "compress-pdf", toolVersion: "1", dependsOn: [], inputs: [{ source: "workflow", input: "documents" }] }] });
  const cleanup = async () => { await owner.query(`UPDATE workflows SET current_version_id=NULL WHERE owner_id=ANY($1::uuid[])`, [users]); await owner.query(`DELETE FROM workflow_runs WHERE owner_id=ANY($1::uuid[])`, [users]); await owner.query(`DELETE FROM workflow_versions WHERE workflow_id IN (SELECT id FROM workflows WHERE owner_id=ANY($1::uuid[]))`, [users]); await owner.query(`DELETE FROM workflows WHERE owner_id=ANY($1::uuid[])`, [users]); await owner.query(`DELETE FROM users WHERE id=ANY($1::uuid[])`, [users]); };
  const tenant = async (id, work) => { await runtime.query("BEGIN"); try { await runtime.query(`SELECT set_config('app.current_user_id',$1,true)`, [id]); const result = await work(); await runtime.query("COMMIT"); return result; } catch (error) { await runtime.query("ROLLBACK"); throw error; } };
  try { await cleanup(); for (const [id, suffix] of [[a, "a"], [b, "b"]]) await owner.query(`INSERT INTO users(id,email,status,created_at,updated_at) VALUES($1,$2,'ACTIVE',now(),now())`, [id, `workflow-rls-${suffix}-${id}@example.invalid`]); for (const [user, workflow, version, run] of [[a, workflowA, versionA, runA], [b, workflowB, versionB, runB]]) { await owner.query(`INSERT INTO workflows(id,owner_id,name,status,created_at,updated_at) VALUES($1,$2,'test','ACTIVE',now(),now())`, [workflow, user]); await owner.query(`INSERT INTO workflow_versions(id,workflow_id,version,definition,created_at) VALUES($1,$2,1,$3::jsonb,now())`, [version, workflow, definition]); await owner.query(`UPDATE workflows SET current_version_id=$1 WHERE id=$2`, [version, workflow]); await owner.query(`INSERT INTO workflow_runs(id,owner_id,workflow_version_id,status,inputs,correlation_id,created_at,updated_at) VALUES($1,$2,$3,'QUEUED','{}',$4,now(),now())`, [run, user, version, randomUUID()]); }
    await tenant(a, async () => { for (const table of ["workflows", "workflow_versions", "workflow_runs"]) assert.equal((await runtime.query(`SELECT id FROM ${table}`)).rowCount, 1); assert.equal((await runtime.query(`UPDATE workflows SET name='blocked' WHERE id=$1`, [workflowB])).rowCount, 0); assert.equal((await runtime.query(`DELETE FROM workflow_runs WHERE id=$1`, [runB])).rowCount, 0); assert.equal((await runtime.query(`SELECT id FROM workflow_runs WHERE id=$1`, [runB])).rowCount, 0); });
    for (const table of ["workflows", "workflow_versions", "workflow_runs"]) assert.equal((await runtime.query(`SELECT id FROM ${table}`)).rowCount, 0);
  } finally { await cleanup(); await runtime.end(); await owner.end(); }
});
