import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "@prisma/client";
import pg from "pg";

const { Client } = pg;
const appUrl = process.env.DIP_RLS_TEST_DATABASE_URL;
const ownerUrl = process.env.DIP_RLS_TEST_OWNER_URL;
const integrationTest = appUrl && ownerUrl ? test : test.skip;

integrationTest("dip_app pooled RLS isolates tenants and fails closed", async () => {
  const ids = {
    userA: randomUUID(), userB: randomUUID(),
    documentA: randomUUID(), documentB: randomUUID(),
    fileA: randomUUID(), fileB: randomUUID(),
    versionA: randomUUID(), versionB: randomUUID(),
    jobA: randomUUID(), jobB: randomUUID(),
    stepA: randomUUID(), stepB: randomUUID(),
    executionA: randomUUID(), executionB: randomUUID(),
    eventA: randomUUID(), eventB: randomUUID(),
    usageA: randomUUID(), usageB: randomUUID(),
  };
  const owner = new Client({ connectionString: ownerUrl });
  const runtime = new PrismaClient({
    adapter: new PrismaPg({ connectionString: appUrl }),
    log: ["error"],
  });
  await owner.connect();

  const cleanup = async () => {
    const users = [ids.userA, ids.userB];
    await owner.query(`DELETE FROM ai_usage WHERE user_id = ANY($1::uuid[])`, [users]);
    await owner.query(`DELETE FROM jobs WHERE requester_id = ANY($1::uuid[])`, [users]);
    await owner.query(`DELETE FROM file_versions WHERE owner_id = ANY($1::uuid[])`, [users]);
    await owner.query(`DELETE FROM files WHERE document_id IN (SELECT id FROM documents WHERE user_id = ANY($1::uuid[]))`, [users]);
    await owner.query(`DELETE FROM documents WHERE user_id = ANY($1::uuid[])`, [users]);
    await owner.query(`DELETE FROM users WHERE id = ANY($1::uuid[])`, [users]);
  };

  const cleanupStaleFixtures = async () => {
    const taggedUsers = `SELECT id FROM users WHERE email LIKE 'rls-%@example.invalid'`;
    await owner.query(`DELETE FROM ai_usage WHERE user_id IN (${taggedUsers})`);
    await owner.query(`DELETE FROM jobs WHERE requester_id IN (${taggedUsers})`);
    await owner.query(`DELETE FROM file_versions WHERE owner_id IN (${taggedUsers})`);
    await owner.query(`DELETE FROM files WHERE document_id IN (SELECT id FROM documents WHERE user_id IN (${taggedUsers}))`);
    await owner.query(`DELETE FROM documents WHERE user_id IN (${taggedUsers})`);
    await owner.query(`DELETE FROM users WHERE email LIKE 'rls-%@example.invalid'`);
  };

  const insertTenant = async (suffix) => {
    const user = ids[`user${suffix}`];
    const document = ids[`document${suffix}`];
    const file = ids[`file${suffix}`];
    const job = ids[`job${suffix}`];
    await owner.query(`INSERT INTO users (id,email,status,created_at,updated_at) VALUES ($1,$2,'ACTIVE',now(),now())`, [user, `rls-${user}@example.invalid`]);
    await owner.query(`INSERT INTO documents (id,user_id,title,status,created_at,updated_at) VALUES ($1,$2,$3,'ACTIVE',now(),now())`, [document, user, `Tenant ${suffix}`]);
    await owner.query(`INSERT INTO files (id,document_id,original_name,mime_type,size,storage_key,version,created_at) VALUES ($1,$2,$3,'application/pdf',1,$4,1,now())`, [file, document, `${suffix}.pdf`, `rls/${file}`]);
    await owner.query(`INSERT INTO file_versions (id,file_id,owner_id,version,storage_key,created_at) VALUES ($1,$2,$3,1,$4,now())`, [ids[`version${suffix}`], file, user, `rls/version/${file}`]);
    await owner.query(`INSERT INTO jobs (id,tool_id,idempotency_key,requester_id,status,params,created_at,updated_at) VALUES ($1,'rls-test',$2,$3,'QUEUED','{}',now(),now())`, [job, `rls-${job}`, user]);
    await owner.query(`INSERT INTO job_steps (id,job_id,name,status,created_at,updated_at) VALUES ($1,$2,'run','QUEUED',now(),now())`, [ids[`step${suffix}`], job]);
    await owner.query(`INSERT INTO tool_executions (id,job_id,tool_id,mode,created_at,updated_at) VALUES ($1,$2,'rls-test','SERVER',now(),now())`, [ids[`execution${suffix}`], job]);
    await owner.query(`INSERT INTO job_events (id,job_id,type,data,created_at,updated_at) VALUES ($1,$2,'created','{}',now(),now())`, [ids[`event${suffix}`], job]);
    await owner.query(`INSERT INTO ai_usage (id,user_id,job_id,provider,model,task_type,tokens_input,tokens_output,cost,created_at) VALUES ($1,$2,$3,'test','test','test',1,1,0,now())`, [ids[`usage${suffix}`], user, job]);
  };

  const withTenant = (userId, operation) => runtime.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT set_config('app.current_user_id', ${userId}, true)`;
    const context = await tx.$queryRaw`SELECT current_setting('app.current_user_id', true) AS user_id, pg_backend_pid() AS pid`;
    assert.equal(context[0].user_id, userId);
    return operation(tx, context[0].pid);
  });

  try {
    await cleanupStaleFixtures();
    await cleanup();
    await insertTenant("A");
    await insertTenant("B");
    const tables = ["documents", "files", "file_versions", "jobs", "job_steps", "tool_executions", "job_events", "ai_usage"];

    await withTenant(ids.userA, async (tx, pid) => {
      for (const table of tables) {
        const rows = await tx.$queryRawUnsafe(`SELECT *, pg_backend_pid() AS _pid FROM ${table}`);
        assert.equal(rows.length, 1, `${table} must expose only User A's row`);
        assert.equal(rows[0]._pid, pid, `${table} query must stay on the SET LOCAL connection`);
      }
      assert.equal(await tx.$executeRaw`UPDATE documents SET title = 'blocked' WHERE id = ${ids.documentB}::uuid`, 0);
      assert.equal(await tx.$executeRaw`DELETE FROM jobs WHERE id = ${ids.jobB}::uuid`, 0);
    });

    const noContext = await runtime.$transaction((tx) => tx.$queryRaw`SELECT id FROM documents`);
    assert.deepEqual(noContext, []);

    const role = (await owner.query(`SELECT rolsuper,rolbypassrls,rolcreaterole,rolcreatedb FROM pg_roles WHERE rolname='dip_app'`)).rows[0];
    assert.deepEqual(role, { rolsuper: false, rolbypassrls: false, rolcreaterole: false, rolcreatedb: false });
  } finally {
    await runtime.$disconnect();
    await cleanup();
    await owner.end();
  }
});
