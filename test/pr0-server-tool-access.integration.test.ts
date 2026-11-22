/**
 * PR-0 database-backed tenant-isolation evidence.
 *
 * This test executes the real `findJobForUser()` / `findOutputFileForUser()`
 * helpers against Postgres using the least-privilege runtime role, so both the
 * explicit owner predicate **and** row level security are exercised.
 *
 * It is skipped unless the RLS fixtures are provisioned:
 *   DIP_RLS_TEST_DATABASE_URL  least-privilege runtime role (dip_app)
 *   DIP_RLS_TEST_OWNER_URL     migration owner role
 * Both are provided by the CI "Test" job; the local sandbox has neither, so this
 * file reports as skipped locally (see the PR description for the limitation).
 *
 * This is database-backed evidence, not a mock: nothing here stubs Prisma, the
 * policies or the connection role.
 */
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";

const runtimeUrl = process.env.DIP_RLS_TEST_DATABASE_URL;
const ownerUrl = process.env.DIP_RLS_TEST_OWNER_URL;
const integrationTest = runtimeUrl && ownerUrl ? test : test.skip;

integrationTest("PR-0 (database): job and output reads are scoped to the owning user under RLS", { timeout: 60_000 }, async () => {
  const { PrismaPg } = await import("@prisma/adapter-pg");
  const { PrismaClient } = await import("@prisma/client");
  const pg = await import("pg");
  const { findJobForUser, findOutputFileForUser } = await import("../src/lib/jobs/access");

  const ids = {
    userA: randomUUID(), userB: randomUUID(),
    documentA: randomUUID(), documentB: randomUUID(),
    fileA: randomUUID(), fileB: randomUUID(),
    jobA: randomUUID(), jobB: randomUUID(),
  };
  const users = [ids.userA, ids.userB];
  const owner = new pg.default.Client({ connectionString: ownerUrl });
  const runtime = new PrismaClient({ adapter: new PrismaPg({ connectionString: runtimeUrl }), log: ["error"] });
  await owner.connect();

  const cleanup = async () => {
    await owner.query(`DELETE FROM job_steps WHERE job_id IN (SELECT id FROM jobs WHERE requester_id = ANY($1::uuid[]))`, [users]);
    await owner.query(`DELETE FROM jobs WHERE requester_id = ANY($1::uuid[])`, [users]);
    await owner.query(`DELETE FROM file_versions WHERE file_id IN (SELECT id FROM files WHERE document_id IN (SELECT id FROM documents WHERE user_id = ANY($1::uuid[])))`, [users]);
    await owner.query(`DELETE FROM files WHERE document_id IN (SELECT id FROM documents WHERE user_id = ANY($1::uuid[]))`, [users]);
    await owner.query(`DELETE FROM documents WHERE user_id = ANY($1::uuid[])`, [users]);
    await owner.query(`DELETE FROM storage_objects WHERE owner_user_id = ANY($1::uuid[])`, [users]);
    await owner.query(`DELETE FROM users WHERE id = ANY($1::uuid[])`, [users]);
  };

  const seed = async (suffix: "A" | "B") => {
    const user = ids[`user${suffix}`];
    const storageObject = randomUUID();
    const storageKey = `pr0/${ids[`file${suffix}`]}`;
    await owner.query(`INSERT INTO users (id,email,status,created_at,updated_at) VALUES ($1,$2,'ACTIVE',now(),now())`, [user, `pr0-access-${user}@example.invalid`]);
    await owner.query(`INSERT INTO documents (id,user_id,title,status,created_at,updated_at) VALUES ($1,$2,$3,'ACTIVE',now(),now())`, [ids[`document${suffix}`], user, `PR-0 ${suffix}`]);
    await owner.query(`INSERT INTO storage_objects (id,owner_user_id,provider,bucket,object_key,size,created_at) VALUES ($1,$2,'s3','dip-rls',$3,1,now())`, [storageObject, user, storageKey]);
    await owner.query(`INSERT INTO files (id,document_id,storage_object_id,original_name,mime_type,size,storage_key,version,created_at) VALUES ($1,$2,$3,$4,'application/pdf',1,$5,1,now())`, [ids[`file${suffix}`], ids[`document${suffix}`], storageObject, `pr0-${suffix}.pdf`, storageKey]);
    await owner.query(`INSERT INTO jobs (id,tool_id,idempotency_key,requester_id,status,params,result,created_at,updated_at) VALUES ($1,'ocr-pdf',$2,$3,'SUCCEEDED','{}',$4::jsonb,now(),now())`, [ids[`job${suffix}`], `pr0-${ids[`job${suffix}`]}`, user, JSON.stringify({ outputFileIds: [ids[`file${suffix}`]] })]);
    await owner.query(`INSERT INTO job_steps (id,job_id,name,status,created_at,updated_at) VALUES ($1,$2,'run','SUCCEEDED',now(),now())`, [randomUUID(), ids[`job${suffix}`]]);
  };

  try {
    await cleanup();
    await seed("A");
    await seed("B");

    // Each user can read their own job and output.
    const ownJobA = await findJobForUser(ids.userA, ids.jobA, runtime);
    assert.equal(ownJobA?.id, ids.jobA);
    assert.equal(ownJobA?.toolId, "ocr-pdf");
    assert.equal(ownJobA?.status, "SUCCEEDED");
    assert.deepEqual((ownJobA?.result as { outputFileIds?: string[] } | null)?.outputFileIds, [ids.fileA]);

    const ownJobB = await findJobForUser(ids.userB, ids.jobB, runtime);
    assert.equal(ownJobB?.id, ids.jobB);

    const ownFileA = await findOutputFileForUser(ids.userA, ids.fileA, runtime);
    assert.equal(ownFileA?.originalName, "pr0-A.pdf");
    assert.equal(ownFileA?.storageKey, `pr0/${ids.fileA}`);

    const ownFileB = await findOutputFileForUser(ids.userB, ids.fileB, runtime);
    assert.equal(ownFileB?.originalName, "pr0-B.pdf");

    // Neither user can read the other tenant's job or output.
    assert.equal(await findJobForUser(ids.userB, ids.jobA, runtime), null, "user B must not read user A's job");
    assert.equal(await findJobForUser(ids.userA, ids.jobB, runtime), null, "user A must not read user B's job");
    assert.equal(await findOutputFileForUser(ids.userB, ids.fileA, runtime), null, "user B must not read user A's output");
    assert.equal(await findOutputFileForUser(ids.userA, ids.fileB, runtime), null, "user A must not read user B's output");
    // A job id used as a file id (and vice versa) must not resolve either.
    assert.equal(await findJobForUser(ids.userA, ids.fileB, runtime), null);
    assert.equal(await findOutputFileForUser(ids.userA, ids.jobB, runtime), null);

    // RLS evidence: without the tenant context the runtime role sees nothing.
    const unfiltered = await runtime.$transaction((tx) => tx.$queryRaw<Array<{ id: string }>>`SELECT id FROM jobs`);
    assert.deepEqual(unfiltered, [], "jobs must be invisible without app.current_user_id");
    const unfilteredFiles = await runtime.$transaction((tx) => tx.$queryRaw<Array<{ id: string }>>`SELECT id FROM files`);
    assert.deepEqual(unfilteredFiles, [], "files must be invisible without app.current_user_id");

    // RLS evidence: inside tenant A's context only tenant A's rows are visible,
    // even for a query that carries no owner predicate of its own.
    const visibleToA = await runtime.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT set_config('app.current_user_id', ${ids.userA}, true)`;
      return tx.$queryRaw<Array<{ id: string }>>`SELECT id FROM jobs`;
    });
    assert.deepEqual(visibleToA.map((row) => row.id), [ids.jobA], "RLS must expose only tenant A's job");

    // The runtime role used by these helpers must not be able to bypass RLS.
    const [{ current_user: runtimeRole }] = await runtime.$transaction((tx) => tx.$queryRaw<Array<{ current_user: string }>>`SELECT current_user`);
    const role = (await owner.query(`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = $1`, [runtimeRole])).rows[0];
    assert.deepEqual({ rolsuper: role.rolsuper, rolbypassrls: role.rolbypassrls }, { rolsuper: false, rolbypassrls: false }, `runtime role ${runtimeRole} must not bypass RLS`);
  } finally {
    await runtime.$disconnect();
    await cleanup();
    await owner.end();
  }
});
