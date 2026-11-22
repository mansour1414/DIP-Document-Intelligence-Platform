import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { PrismaPg } from "@prisma/adapter-pg";
import { Prisma, PrismaClient } from "@prisma/client";
import pg from "pg";
import { withTenantScope } from "../src/lib/db/tenant.ts";
import { findOutputFileForUser } from "../src/lib/jobs/access.ts";
import { buildStorageObjectConnectOrCreate } from "../src/lib/storage/metadata.ts";

const runtimeUrl = process.env.DIP_RLS_TEST_DATABASE_URL;
const ownerUrl = process.env.DIP_RLS_TEST_OWNER_URL;
const retentionUrl = process.env.DIP_RETENTION_TEST_DATABASE_URL;
const integration = runtimeUrl && ownerUrl && retentionUrl ? test : test.skip;

async function inScope(pool, gucs, fn) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      "SELECT set_config('app.current_user_id', $1, true), set_config('app.current_organization_id', $2, true), set_config('app.current_api_client_id', $3, true)",
      [gucs.userId ?? "", gucs.organizationId ?? "", gucs.apiClientId ?? ""],
    );
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

integration("N1-A storage_objects enforces real PostgreSQL RLS, FORCE RLS, API-client cross-link triggers, Prisma connectOrCreate, SECURITY DEFINER hardening, and retention least privilege", async () => {
  const owner = new pg.Pool({ connectionString: ownerUrl, max: 2 });
  const runtime = new pg.Pool({ connectionString: runtimeUrl, max: 4 });
  const retention = new pg.Pool({ connectionString: retentionUrl, max: 2 });
  const prismaRuntime = new PrismaClient({
    adapter: new PrismaPg({ connectionString: runtimeUrl }),
    log: ["error"],
  });

  const userA = crypto.randomUUID();
  const userA2 = crypto.randomUUID();
  const userB = crypto.randomUUID();
  const orgA = crypto.randomUUID();
  const orgB = crypto.randomUUID();
  const clientA1 = crypto.randomUUID();
  const clientA2 = crypto.randomUUID();
  const clientB1 = crypto.randomUUID();
  const docA = crypto.randomUUID();
  const docB = crypto.randomUUID();
  const docOrgApiA1 = crypto.randomUUID();
  const docOrgApiA2 = crypto.randomUUID();
  const orphanObj = crypto.randomUUID();
  const personalObjA = crypto.randomUUID();
  const personalObjB = crypto.randomUUID();
  const orgObjA = crypto.randomUUID();
  const apiObjA1 = crypto.randomUUID();
  const apiObjA2 = crypto.randomUUID();
  const fileApiA1 = crypto.randomUUID();
  const fileApiA2 = crypto.randomUUID();

  const allDocIds = [docA, docB, docOrgApiA1, docOrgApiA2];

  const cleanup = async () => {
    await owner.query("DELETE FROM files WHERE document_id = ANY($1::uuid[])", [allDocIds]);
    await owner.query("DELETE FROM documents WHERE id = ANY($1::uuid[])", [allDocIds]);
    await owner.query(
      "DELETE FROM storage_objects WHERE id = ANY($1::uuid[]) OR owner_user_id = ANY($2::uuid[])",
      [[orphanObj, personalObjA, personalObjB, orgObjA, apiObjA1, apiObjA2], [userA, userA2, userB]],
    );
    await owner.query("DELETE FROM api_clients WHERE id = ANY($1::uuid[])", [[clientA1, clientA2, clientB1]]);
    await owner.query("DELETE FROM memberships WHERE organization_id = ANY($1::uuid[])", [[orgA, orgB]]);
    await owner.query("DELETE FROM organizations WHERE id = ANY($1::uuid[])", [[orgA, orgB]]);
    await owner.query("DELETE FROM users WHERE id = ANY($1::uuid[])", [[userA, userA2, userB]]);
  };

  try {
    // Catalog audit: pg_class RLS + FORCE RLS, role posture, explicit policy roles, and SECURITY DEFINER privileges.
    const rlsCatalog = await owner.query(
      "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = 'public.storage_objects'::regclass",
    );
    assert.deepEqual(rlsCatalog.rows[0], { relrowsecurity: true, relforcerowsecurity: true });

    const roleCheck = await owner.query(
      "SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname IN ('dip_app', 'dip_retention') ORDER BY rolname",
    );
    assert.deepEqual(roleCheck.rows, [
      { rolname: "dip_app", rolsuper: false, rolbypassrls: false },
      { rolname: "dip_retention", rolsuper: false, rolbypassrls: false },
    ]);

    const policyCatalog = await owner.query(
      `SELECT tablename, policyname, permissive, roles::text[] AS roles
         FROM pg_policies
        WHERE schemaname = 'public'
          AND (tablename = 'storage_objects' OR policyname = 'files_storage_object_rls_guard')
        ORDER BY tablename, policyname`,
    );
    for (const pol of policyCatalog.rows) {
      assert.ok(!pol.roles.includes("public"), `Policy ${pol.policyname} must not target PUBLIC`);
      if (pol.policyname.includes("retention")) {
        assert.deepEqual(pol.roles, ["dip_retention"]);
      } else {
        assert.deepEqual(pol.roles, ["dip_app"]);
      }
    }
    const filesGuardPolicy = policyCatalog.rows.find((p) => p.policyname === "files_storage_object_rls_guard");
    assert.ok(filesGuardPolicy, "files_storage_object_rls_guard policy must exist");
    assert.equal(filesGuardPolicy.permissive, "RESTRICTIVE");

    const fileCheckConstraint = await owner.query(
      `SELECT conname
         FROM pg_constraint
        WHERE conrelid = 'public.files'::regclass
          AND contype = 'c'
          AND conname = 'files_ephemeral_or_storage_object_check'`,
    );
    assert.equal(fileCheckConstraint.rowCount, 1, "files_ephemeral_or_storage_object_check constraint must exist on public.files");

    const fnCatalog = await owner.query(
      `SELECT p.proname,
              pg_get_userbyid(p.proowner) AS owner_role,
              p.prosecdef,
              p.proconfig,
              has_function_privilege('public', p.oid, 'EXECUTE') AS public_exec,
              has_function_privilege('dip_app', p.oid, 'EXECUTE') AS dip_app_exec,
              has_function_privilege('dip_retention', p.oid, 'EXECUTE') AS dip_retention_exec
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
          AND p.proname IN (
            'app_api_client_matches_tenant',
            'enforce_storage_object_immutability',
            'enforce_file_storage_object_tenant_match',
            'enforce_document_storage_object_tenant_match'
          )
        ORDER BY p.proname`,
    );
    assert.equal(fnCatalog.rowCount, 4);
    for (const fn of fnCatalog.rows) {
      assert.equal(fn.prosecdef, true, `${fn.proname} must be SECURITY DEFINER`);
      assert.notEqual(fn.owner_role, "dip_app");
      assert.notEqual(fn.owner_role, "dip_retention");
      assert.ok(
        Array.isArray(fn.proconfig) && fn.proconfig.includes("search_path=pg_catalog, public"),
        `${fn.proname} must pin search_path=pg_catalog, public`,
      );
      assert.equal(fn.public_exec, false, `${fn.proname} must revoke PUBLIC EXECUTE`);
      assert.equal(fn.dip_retention_exec, false, `${fn.proname} must revoke dip_retention EXECUTE`);
      if (fn.proname === "app_api_client_matches_tenant") {
        assert.equal(fn.dip_app_exec, true);
      } else {
        assert.equal(fn.dip_app_exec, false, `${fn.proname} trigger function must revoke dip_app EXECUTE`);
      }
    }

    for (const u of [userA, userA2, userB]) {
      await owner.query("INSERT INTO users(id,email,status,created_at,updated_at) VALUES($1,$2,'ACTIVE',now(),now())", [
        u,
        `n1a-${u}@example.invalid`,
      ]);
    }
    await owner.query("INSERT INTO organizations(id,name,slug,plan,status,created_at,updated_at) VALUES($1,'Org A',$2,'BUSINESS','ACTIVE',now(),now()),($3,'Org B',$4,'BUSINESS','ACTIVE',now(),now())", [
      orgA,
      `n1a-org-a-${orgA.slice(0, 8)}`,
      orgB,
      `n1a-org-b-${orgB.slice(0, 8)}`,
    ]);
    await owner.query(
      "INSERT INTO memberships(id,user_id,organization_id,role,created_at,updated_at) VALUES($1,$2,$3,'OWNER',now(),now()),($4,$5,$3,'MEMBER',now(),now()),($6,$7,$8,'OWNER',now(),now())",
      [crypto.randomUUID(), userA, orgA, crypto.randomUUID(), userA2, crypto.randomUUID(), userB, orgB],
    );
    // Note: clientA1 and clientA2 intentionally share BOTH orgA AND created_by_user_id = userA (Blocker 2 scenario).
    await owner.query(
      "INSERT INTO api_clients(id,organization_id,created_by_user_id,name,status,created_at,updated_at) VALUES($1,$2,$3,'A1','ACTIVE',now(),now()),($4,$2,$3,'A2','ACTIVE',now(),now()),($5,$6,$7,'B1','ACTIVE',now(),now())",
      [clientA1, orgA, userA, clientA2, clientB1, orgB, userB],
    );
    await owner.query(
      "INSERT INTO documents(id,user_id,organization_id,title,status,created_at,updated_at) VALUES($1,$2,NULL,'Doc A','ACTIVE',now(),now()),($3,$4,NULL,'Doc B','ACTIVE',now(),now()),($5,$2,$6,'Doc Org API A1','ACTIVE',now(),now()),($7,$2,$6,'Doc Org API A2','ACTIVE',now(),now())",
      [docA, userA, docB, userB, docOrgApiA1, orgA, docOrgApiA2],
    );

    // Seed an unlinked historical orphan row (NULL ownership).
    await owner.query(
      "INSERT INTO storage_objects(id,owner_user_id,organization_id,api_client_id,provider,bucket,object_key,size,created_at) VALUES($1,NULL,NULL,NULL,'s3','dip-rls',$2,64,now())",
      [orphanObj, `orphan/${orphanObj}.pdf`],
    );

    // Missing/empty tenant context fails closed.
    assert.equal((await runtime.query("SELECT id FROM storage_objects")).rowCount, 0);
    await assert.rejects(
      () =>
        runtime.query(
          "INSERT INTO storage_objects(id,owner_user_id,provider,bucket,object_key,size) VALUES($1,$2,'s3','dip-rls','unscoped.pdf',10)",
          [crypto.randomUUID(), userA],
        ),
      /row-level security/i,
    );

    // Personal user-owned INSERT, SELECT, cross-tenant isolation, and unauthorized INSERT rejection.
    await inScope(runtime, { userId: userA }, (c) =>
      c.query(
        "INSERT INTO storage_objects(id,owner_user_id,provider,bucket,object_key,size,checksum) VALUES($1,$2,'s3','dip-rls',$3,100,'sha-a')",
        [personalObjA, userA, `input/${userA}/a.pdf`],
      ),
    );
    await inScope(runtime, { userId: userB }, (c) =>
      c.query(
        "INSERT INTO storage_objects(id,owner_user_id,provider,bucket,object_key,size,checksum) VALUES($1,$2,'s3','dip-rls',$3,200,'sha-b')",
        [personalObjB, userB, `input/${userB}/b.pdf`],
      ),
    );

    const rowsForA = await inScope(runtime, { userId: userA }, (c) =>
      c.query("SELECT id FROM storage_objects WHERE id = ANY($1::uuid[])", [[personalObjA, personalObjB, orphanObj]]),
    );
    assert.deepEqual(rowsForA.rows.map((r) => r.id), [personalObjA]);

    const crossUpdate = await inScope(runtime, { userId: userA }, (c) =>
      c.query("UPDATE storage_objects SET checksum = 'tamper' WHERE id = $1", [personalObjB]),
    );
    assert.equal(crossUpdate.rowCount, 0);

    await assert.rejects(
      () =>
        inScope(runtime, { userId: userA }, (c) =>
          c.query(
            "INSERT INTO storage_objects(id,owner_user_id,provider,bucket,object_key,size) VALUES($1,$2,'s3','dip-rls','forged.pdf',10)",
            [crypto.randomUUID(), userB],
          ),
        ),
      /row-level security/i,
    );

    // Organization & API-client isolation + composite FK enforcement.
    await inScope(runtime, { userId: userA, organizationId: orgA }, (c) =>
      c.query(
        "INSERT INTO storage_objects(id,owner_user_id,organization_id,provider,bucket,object_key,size) VALUES($1,$2,$3,'s3','dip-rls',$4,300)",
        [orgObjA, userA, orgA, `org/${orgA}/doc.pdf`],
      ),
    );
    assert.equal(
      (await inScope(runtime, { userId: userA2, organizationId: orgA }, (c) => c.query("SELECT id FROM storage_objects WHERE id=$1", [orgObjA]))).rowCount,
      1,
    );
    assert.equal(
      (await inScope(runtime, { userId: userB, organizationId: orgB }, (c) => c.query("SELECT id FROM storage_objects WHERE id=$1", [orgObjA]))).rowCount,
      0,
    );

    await inScope(runtime, { userId: userA, organizationId: orgA, apiClientId: clientA1 }, (c) =>
      c.query(
        "INSERT INTO storage_objects(id,owner_user_id,organization_id,api_client_id,provider,bucket,object_key,size) VALUES($1,$2,$3,$4,'s3','dip-rls',$5,400)",
        [apiObjA1, userA, orgA, clientA1, `api/${orgA}/${clientA1}/doc.pdf`],
      ),
    );
    await inScope(runtime, { userId: userA, organizationId: orgA, apiClientId: clientA2 }, (c) =>
      c.query(
        "INSERT INTO storage_objects(id,owner_user_id,organization_id,api_client_id,provider,bucket,object_key,size) VALUES($1,$2,$3,$4,'s3','dip-rls',$5,410)",
        [apiObjA2, userA, orgA, clientA2, `api/${orgA}/${clientA2}/doc.pdf`],
      ),
    );

    assert.equal(
      (await inScope(runtime, { organizationId: orgA, apiClientId: clientA1 }, (c) => c.query("SELECT id FROM storage_objects WHERE id=$1", [apiObjA1]))).rowCount,
      1,
    );
    assert.equal(
      (await inScope(runtime, { organizationId: orgA, apiClientId: clientA2 }, (c) => c.query("SELECT id FROM storage_objects WHERE id=$1", [apiObjA1]))).rowCount,
      0,
    );
    // Non-API org session for userA cannot see API-client-scoped storage_objects either.
    assert.equal(
      (await inScope(runtime, { userId: userA, organizationId: orgA }, (c) => c.query("SELECT id FROM storage_objects WHERE id=$1", [apiObjA1]))).rowCount,
      0,
    );
    assert.equal(
      (await inScope(runtime, { organizationId: orgB, apiClientId: clientB1 }, (c) => c.query("SELECT id FROM storage_objects WHERE id=$1", [apiObjA1]))).rowCount,
      0,
    );

    // Anti-oracle check: app_api_client_matches_tenant returns false when GUC context does not match probed client/org.
    const oracleProbeWrongClient = await inScope(
      runtime,
      { userId: userA, organizationId: orgA, apiClientId: clientA2 },
      (c) => c.query("SELECT app_api_client_matches_tenant($1, $2, $3, false) AS ok", [orgA, clientA1, userA]),
    );
    assert.equal(oracleProbeWrongClient.rows[0].ok, false);

    // BLOCKER 2 EXPLICIT NEGATIVE SUITE:
    // clientA1 and clientA2 share BOTH orgA and execution user userA.
    // 1. clientA1 creates its legitimate File linked to apiObjA1.
    await inScope(runtime, { userId: userA, organizationId: orgA, apiClientId: clientA1 }, (c) =>
      c.query(
        "INSERT INTO files(id,document_id,storage_object_id,storage_key,mime_type,original_name,size,created_at) VALUES($1,$2,$3,$4,'application/pdf','a1.pdf',400,now())",
        [fileApiA1, docOrgApiA1, apiObjA1, `api/${orgA}/${clientA1}/doc.pdf`],
      ),
    );
    await inScope(runtime, { userId: userA, organizationId: orgA, apiClientId: clientA2 }, (c) =>
      c.query(
        "INSERT INTO files(id,document_id,storage_object_id,storage_key,mime_type,original_name,size,created_at) VALUES($1,$2,$3,$4,'application/pdf','a2.pdf',410,now())",
        [fileApiA2, docOrgApiA2, apiObjA2, `api/${orgA}/${clientA2}/doc.pdf`],
      ),
    );

    // 2. clientA2 CANNOT SELECT clientA1's files row (including storage_key), despite sharing userA and orgA.
    assert.equal(
      (
        await inScope(runtime, { userId: userA, organizationId: orgA, apiClientId: clientA2 }, (c) =>
          c.query("SELECT id, storage_key FROM files WHERE id = $1", [fileApiA1]),
        )
      ).rowCount,
      0,
    );
    // Personal userA session and non-API org session also CANNOT SELECT clientA1's files row.
    assert.equal(
      (await inScope(runtime, { userId: userA }, (c) => c.query("SELECT id, storage_key FROM files WHERE id = $1", [fileApiA1]))).rowCount,
      0,
    );
    assert.equal(
      (
        await inScope(runtime, { userId: userA, organizationId: orgA }, (c) =>
          c.query("SELECT id, storage_key FROM files WHERE id = $1", [fileApiA1]),
        )
      ).rowCount,
      0,
    );

    // 3. clientA2 CANNOT INSERT a File referencing clientA1's StorageObject (apiObjA1), even with same orgA + userA!
    await assert.rejects(
      () =>
        inScope(runtime, { userId: userA, organizationId: orgA, apiClientId: clientA2 }, (c) =>
          c.query(
            "INSERT INTO files(id,document_id,storage_object_id,storage_key,mime_type,original_name,size,created_at) VALUES($1,$2,$3,'cross-api.pdf','application/pdf','x.pdf',400,now())",
            [crypto.randomUUID(), docOrgApiA2, apiObjA1],
          ),
        ),
      /STORAGE_OBJECT_API_CLIENT_MISMATCH|row-level security/i,
    );

    // 4. clientA2 CANNOT UPDATE its own File to reference clientA1's StorageObject (apiObjA1).
    await assert.rejects(
      () =>
        inScope(runtime, { userId: userA, organizationId: orgA, apiClientId: clientA2 }, (c) =>
          c.query("UPDATE files SET storage_object_id = $1 WHERE id = $2", [apiObjA1, fileApiA2]),
        ),
      /STORAGE_OBJECT_API_CLIENT_MISMATCH|row-level security/i,
    );

    // 5. Non-API org session for userA CANNOT INSERT a File referencing clientA1's StorageObject (apiObjA1).
    await assert.rejects(
      () =>
        inScope(runtime, { userId: userA, organizationId: orgA }, (c) =>
          c.query(
            "INSERT INTO files(id,document_id,storage_object_id,storage_key,mime_type,original_name,size,created_at) VALUES($1,$2,$3,'org-to-api.pdf','application/pdf','o2a.pdf',400,now())",
            [crypto.randomUUID(), docOrgApiA2, apiObjA1],
          ),
        ),
      /STORAGE_OBJECT_API_CLIENT_MISMATCH|row-level security/i,
    );

    // Composite FK prevents mismatched (api_client_id, organization_id) even as owner.
    await assert.rejects(
      () =>
        owner.query(
          "INSERT INTO storage_objects(id,owner_user_id,organization_id,api_client_id,provider,bucket,object_key,size) VALUES($1,$2,$3,$4,'s3','dip-rls','bad-fk.pdf',10)",
          [crypto.randomUUID(), userB, orgB, clientA1],
        ),
      /storage_objects_api_client_organization_fkey/,
    );

    // Cross-tenant File -> StorageObject link and orphan link are rejected by trigger; object-key collision fails closed.
    await assert.rejects(
      () =>
        inScope(runtime, { userId: userB }, (c) =>
          c.query(
            "INSERT INTO files(id,document_id,storage_object_id,storage_key,mime_type,original_name,size,created_at) VALUES($1,$2,$3,'hijack.pdf','application/pdf','h.pdf',100,now())",
            [crypto.randomUUID(), docB, personalObjA],
          ),
        ),
      /STORAGE_OBJECT_TENANT_MISMATCH/,
    );
    await assert.rejects(
      () =>
        inScope(runtime, { userId: userA }, (c) =>
          c.query(
            "INSERT INTO files(id,document_id,storage_object_id,storage_key,mime_type,original_name,size,created_at) VALUES($1,$2,$3,'orphan.pdf','application/pdf','o.pdf',64,now())",
            [crypto.randomUUID(), docA, orphanObj],
          ),
        ),
      /STORAGE_OBJECT_TENANT_MISMATCH/,
    );
    await assert.rejects(
      () =>
        inScope(runtime, { userId: userB }, (c) =>
          c.query(
            "INSERT INTO storage_objects(id,owner_user_id,provider,bucket,object_key,size) VALUES($1,$2,'s3','dip-rls',$3,100)",
            [crypto.randomUUID(), userB, `input/${userA}/a.pdf`],
          ),
        ),
      /duplicate key value violates unique constraint/,
    );

    // REAL PRISMA connectOrCreate & connect VERIFICATION AGAINST POSTGRESQL dip_app:
    const assertExpectedPrismaDbRejection = (expectedCodes) => (error) => {
      assert.equal(
        error instanceof Prisma.PrismaClientValidationError || error?.name === "PrismaClientValidationError",
        false,
        `Must not fail due to malformed Prisma input: ${error?.message ?? String(error)}`,
      );
      assert.equal(
        error instanceof Prisma.PrismaClientKnownRequestError,
        true,
        `Expected PrismaClientKnownRequestError, received ${error?.constructor?.name ?? typeof error}: ${error?.message ?? String(error)}`,
      );
      assert.equal(
        expectedCodes.includes(error.code),
        true,
        `Expected Prisma error code in [${expectedCodes.join(", ")}], got ${error.code}: ${error.message}`,
      );
      return true;
    };

    // (a) Same personal tenant connectOrCreate reuses existing StorageObject cleanly.
    const prismaPersonalKey = `prisma-connect/${userA}/${crypto.randomUUID()}.pdf`;
    const createdPersonal1 = await withTenantScope(
      { userId: userA },
      (tx) =>
        tx.file.create({
          data: {
            document: { connect: { id: docA } },
            storageKey: prismaPersonalKey,
            mimeType: "application/pdf",
            originalName: "p1.pdf",
            size: BigInt(512),
            storageObject: buildStorageObjectConnectOrCreate(
              { userId: userA },
              { bucket: "dip-rls", objectKey: prismaPersonalKey, size: 512, checksum: "sha-p1" },
            ),
          },
          select: { id: true, storageObjectId: true },
        }),
      prismaRuntime,
    );
    const createdPersonal2 = await withTenantScope(
      { userId: userA },
      (tx) =>
        tx.file.create({
          data: {
            document: { connect: { id: docA } },
            storageKey: prismaPersonalKey,
            mimeType: "application/pdf",
            originalName: "p1-copy.pdf",
            size: BigInt(512),
            storageObject: buildStorageObjectConnectOrCreate(
              { userId: userA },
              { bucket: "dip-rls", objectKey: prismaPersonalKey, size: 512, checksum: "sha-p1" },
            ),
          },
          select: { id: true, storageObjectId: true },
        }),
      prismaRuntime,
    );
    assert.ok(createdPersonal1.storageObjectId);
    assert.equal(createdPersonal1.storageObjectId, createdPersonal2.storageObjectId);

    // (b) Cross-user Prisma connectOrCreate on colliding (provider, bucket, object_key) fails closed on uniqueness/RLS (P2002),
    // and direct nested connect by StorageObject ID fails closed on RLS non-visibility (P2025)!
    await assert.rejects(
      () =>
        withTenantScope(
          { userId: userB },
          (tx) =>
            tx.file.create({
              data: {
                document: { connect: { id: docB } },
                storageKey: prismaPersonalKey,
                mimeType: "application/pdf",
                originalName: "hijack-prisma.pdf",
                size: BigInt(512),
                storageObject: buildStorageObjectConnectOrCreate(
                  { userId: userB },
                  { bucket: "dip-rls", objectKey: prismaPersonalKey, size: 512 },
                ),
              },
              select: { id: true, storageObjectId: true },
            }),
          prismaRuntime,
        ),
      assertExpectedPrismaDbRejection(["P2002"]),
    );

    await assert.rejects(
      () =>
        withTenantScope(
          { userId: userB },
          (tx) =>
            tx.file.create({
              data: {
                document: { connect: { id: docB } },
                storageKey: `prisma-connect/${userB}/hijack-direct.pdf`,
                mimeType: "application/pdf",
                originalName: "hijack-direct.pdf",
                size: BigInt(512),
                storageObject: { connect: { id: createdPersonal1.storageObjectId } },
              },
              select: { id: true, storageObjectId: true },
            }),
          prismaRuntime,
        ),
      assertExpectedPrismaDbRejection(["P2025"]),
    );

    // Verify no cross-tenant File or StorageObject rows/links were created on docB or prismaPersonalKey.
    const docBFilesAfterCollision = await owner.query(
      "SELECT id, storage_object_id FROM files WHERE document_id = $1",
      [docB],
    );
    assert.equal(docBFilesAfterCollision.rowCount, 0);
    const personalKeyObjects = await owner.query(
      "SELECT id, owner_user_id, organization_id, api_client_id FROM storage_objects WHERE provider = 's3' AND bucket = 'dip-rls' AND object_key = $1",
      [prismaPersonalKey],
    );
    assert.deepEqual(personalKeyObjects.rows, [
      {
        id: createdPersonal1.storageObjectId,
        owner_user_id: userA,
        organization_id: null,
        api_client_id: null,
      },
    ]);

    // (c) Same-org, same-execution-user cross-API-client Prisma connectOrCreate & connect fail closed!
    const prismaApiKey = `prisma-api/${orgA}/${clientA1}/${crypto.randomUUID()}.pdf`;
    const createdApiFile = await withTenantScope(
      { userId: userA, organizationId: orgA, apiClientId: clientA1 },
      (tx) =>
        tx.file.create({
          data: {
            document: { connect: { id: docOrgApiA1 } },
            storageKey: prismaApiKey,
            mimeType: "application/pdf",
            originalName: "api-a1.pdf",
            size: BigInt(768),
            storageObject: buildStorageObjectConnectOrCreate(
              { userId: userA, organizationId: orgA, apiClientId: clientA1 },
              { bucket: "dip-rls", objectKey: prismaApiKey, size: 768 },
            ),
          },
          select: { id: true, storageObjectId: true },
        }),
      prismaRuntime,
    );
    assert.ok(createdApiFile.storageObjectId);

    // Same-API-client repeat connectOrCreate reuses createdApiFile.storageObjectId cleanly.
    const reusedApiFile = await withTenantScope(
      { userId: userA, organizationId: orgA, apiClientId: clientA1 },
      (tx) =>
        tx.file.create({
          data: {
            document: { connect: { id: docOrgApiA1 } },
            storageKey: prismaApiKey,
            mimeType: "application/pdf",
            originalName: "api-a1-copy.pdf",
            size: BigInt(768),
            storageObject: buildStorageObjectConnectOrCreate(
              { userId: userA, organizationId: orgA, apiClientId: clientA1 },
              { bucket: "dip-rls", objectKey: prismaApiKey, size: 768 },
            ),
          },
          select: { id: true, storageObjectId: true },
        }),
      prismaRuntime,
    );
    assert.equal(reusedApiFile.storageObjectId, createdApiFile.storageObjectId);

    await assert.rejects(
      () =>
        withTenantScope(
          { userId: userA, organizationId: orgA, apiClientId: clientA2 },
          (tx) =>
            tx.file.create({
              data: {
                document: { connect: { id: docOrgApiA2 } },
                storageKey: prismaApiKey,
                mimeType: "application/pdf",
                originalName: "api-a2-collide.pdf",
                size: BigInt(768),
                storageObject: buildStorageObjectConnectOrCreate(
                  { userId: userA, organizationId: orgA, apiClientId: clientA2 },
                  { bucket: "dip-rls", objectKey: prismaApiKey, size: 768 },
                ),
              },
              select: { id: true, storageObjectId: true },
            }),
          prismaRuntime,
        ),
      assertExpectedPrismaDbRejection(["P2002"]),
    );

    await assert.rejects(
      () =>
        withTenantScope(
          { userId: userA, organizationId: orgA, apiClientId: clientA2 },
          (tx) =>
            tx.file.create({
              data: {
                document: { connect: { id: docOrgApiA2 } },
                storageKey: `prisma-api/${orgA}/${clientA2}/direct-hijack.pdf`,
                mimeType: "application/pdf",
                originalName: "api-a2-direct.pdf",
                size: BigInt(768),
                storageObject: { connect: { id: createdApiFile.storageObjectId } },
              },
              select: { id: true, storageObjectId: true },
            }),
          prismaRuntime,
        ),
      assertExpectedPrismaDbRejection(["P2025"]),
    );

    // Verify clientA2 created zero cross-client File links on docOrgApiA2 (only its earlier legitimate fileApiA2 exists)
    // and createdApiFile.storageObjectId remains attributed solely to clientA1.
    const docOrgApiA2Files = await owner.query(
      "SELECT id, storage_object_id FROM files WHERE document_id = $1",
      [docOrgApiA2],
    );
    assert.deepEqual(docOrgApiA2Files.rows, [{ id: fileApiA2, storage_object_id: apiObjA2 }]);
    const apiKeyObjects = await owner.query(
      "SELECT id, owner_user_id, organization_id, api_client_id FROM storage_objects WHERE provider = 's3' AND bucket = 'dip-rls' AND object_key = $1",
      [prismaApiKey],
    );
    assert.deepEqual(apiKeyObjects.rows, [
      {
        id: createdApiFile.storageObjectId,
        owner_user_id: userA,
        organization_id: orgA,
        api_client_id: clientA1,
      },
    ]);

    // STORAGE KEY INTEGRITY & EPHEMERAL JOB-HISTORY SUITE (PostgreSQL 18 kernel + real Prisma):
    // 1. Unlinked non-ephemeral File (storage_object_id = NULL, storage_key not ephemeral/*) is rejected
    //    for both dip_app and table owner.
    await assert.rejects(
      () =>
        inScope(runtime, { userId: userA }, (c) =>
          c.query(
            "INSERT INTO files(id,document_id,storage_object_id,storage_key,mime_type,original_name,size,created_at) VALUES($1,$2,NULL,$3,'application/pdf','unlinked.pdf',128,now())",
            [crypto.randomUUID(), docA, `input/${userB}/b.pdf`],
          ),
        ),
      /FILE_STORAGE_OBJECT_REQUIRED|files_ephemeral_or_storage_object_check/i,
    );
    await assert.rejects(
      () =>
        owner.query(
          "INSERT INTO files(id,document_id,storage_object_id,storage_key,mime_type,original_name,size,created_at) VALUES($1,$2,NULL,$3,'application/pdf','owner-unlinked.pdf',128,now())",
          [crypto.randomUUID(), docA, `input/${userB}/b.pdf`],
        ),
      /FILE_STORAGE_OBJECT_REQUIRED|files_ephemeral_or_storage_object_check/i,
    );
    await assert.rejects(
      () =>
        withTenantScope(
          { userId: userA },
          (tx) =>
            tx.file.create({
              data: {
                document: { connect: { id: docA } },
                storageKey: `input/${userB}/b.pdf`,
                mimeType: "application/pdf",
                originalName: "prisma-unlinked.pdf",
                size: BigInt(128),
              },
              select: { id: true },
            }),
          prismaRuntime,
        ),
      (error) => {
        assert.equal(
          error instanceof Prisma.PrismaClientValidationError || error?.name === "PrismaClientValidationError",
          false,
          `Must not fail due to malformed Prisma input: ${error?.message ?? String(error)}`,
        );
        assert.match(String(error?.message ?? error), /FILE_STORAGE_OBJECT_REQUIRED|files_ephemeral_or_storage_object_check/i);
        return true;
      },
    );

    // 2. Forged File.storageKey linked to attacker's own authorized StorageObject is rejected
    //    across personal scope, same-org/same-execution-user API-client scope, and real Prisma.
    await assert.rejects(
      () =>
        inScope(runtime, { userId: userA }, (c) =>
          c.query(
            "INSERT INTO files(id,document_id,storage_object_id,storage_key,mime_type,original_name,size,created_at) VALUES($1,$2,$3,$4,'application/pdf','forged-personal.pdf',100,now())",
            [crypto.randomUUID(), docA, personalObjA, `input/${userB}/b.pdf`],
          ),
        ),
      /FILE_STORAGE_KEY_MISMATCH|row-level security/i,
    );
    await assert.rejects(
      () =>
        inScope(runtime, { userId: userA, organizationId: orgA, apiClientId: clientA2 }, (c) =>
          c.query(
            "INSERT INTO files(id,document_id,storage_object_id,storage_key,mime_type,original_name,size,created_at) VALUES($1,$2,$3,$4,'application/pdf','forged-api.pdf',410,now())",
            [crypto.randomUUID(), docOrgApiA2, apiObjA2, `api/${orgA}/${clientA1}/doc.pdf`],
          ),
        ),
      /FILE_STORAGE_KEY_MISMATCH|row-level security/i,
    );
    await assert.rejects(
      () =>
        withTenantScope(
          { userId: userA },
          (tx) =>
            tx.file.create({
              data: {
                document: { connect: { id: docA } },
                storageKey: `input/${userB}/b.pdf`,
                mimeType: "application/pdf",
                originalName: "prisma-forged.pdf",
                size: BigInt(100),
                storageObject: { connect: { id: personalObjA } },
              },
              select: { id: true },
            }),
          prismaRuntime,
        ),
      (error) => {
        assert.equal(
          error instanceof Prisma.PrismaClientValidationError || error?.name === "PrismaClientValidationError",
          false,
          `Must not fail due to malformed Prisma input: ${error?.message ?? String(error)}`,
        );
        assert.match(String(error?.message ?? error), /FILE_STORAGE_KEY_MISMATCH|row-level security/i);
        return true;
      },
    );

    // 3. Ephemeral storage_key cannot be paired with a non-null storage_object_id, and bare 'ephemeral/' is rejected.
    await assert.rejects(
      () =>
        inScope(runtime, { userId: userA }, (c) =>
          c.query(
            "INSERT INTO files(id,document_id,storage_object_id,storage_key,mime_type,original_name,size,created_at) VALUES($1,$2,$3,'ephemeral/forged-link.pdf','application/pdf','bad-ephemeral.pdf',64,now())",
            [crypto.randomUUID(), docA, personalObjA],
          ),
        ),
      /FILE_STORAGE_KEY_MISMATCH|files_ephemeral_or_storage_object_check/i,
    );
    await assert.rejects(
      () =>
        inScope(runtime, { userId: userA }, (c) =>
          c.query(
            "INSERT INTO files(id,document_id,storage_object_id,storage_key,mime_type,original_name,size,created_at) VALUES($1,$2,NULL,'ephemeral/','application/pdf','empty-ephemeral.pdf',64,now())",
            [crypto.randomUUID(), docA],
          ),
        ),
      /FILE_STORAGE_OBJECT_REQUIRED|files_ephemeral_or_storage_object_check/i,
    );

    // 4. Post-insert mutation of File.storage_key or unlinking storage_object_id on an existing File is rejected,
    //    while legitimate metadata updates (e.g. created_at for retention tests) remain permitted.
    await assert.rejects(
      () =>
        inScope(runtime, { userId: userA }, (c) =>
          c.query("UPDATE files SET storage_key = $1 WHERE id = $2", [`input/${userB}/b.pdf`, createdPersonal1.id]),
        ),
      /FILE_STORAGE_COORDINATES_IMMUTABLE|FILE_STORAGE_KEY_MISMATCH|row-level security/i,
    );
    await assert.rejects(
      () =>
        inScope(runtime, { userId: userA }, (c) =>
          c.query("UPDATE files SET storage_object_id = NULL WHERE id = $1", [createdPersonal1.id]),
        ),
      /FILE_STORAGE_OBJECT_REQUIRED|FILE_STORAGE_COORDINATES_IMMUTABLE|files_ephemeral_or_storage_object_check/i,
    );
    assert.equal(
      (
        await inScope(runtime, { userId: userA }, (c) =>
          c.query("UPDATE files SET created_at = created_at WHERE id = $1", [createdPersonal1.id]),
        )
      ).rowCount,
      1,
    );
    assert.equal(
      (await findOutputFileForUser(userA, createdPersonal1.id, prismaRuntime))?.storageKey,
      prismaPersonalKey,
    );

    // 5. Legitimate browser job-history ephemeral/* File (storage_object_id = NULL) succeeds for its tenant,
    //    stays invisible to other tenants, and is never returned by physical output download helpers.
    const ephemeralHistoryKey = `ephemeral/${crypto.randomUUID()}-browser-history.pdf`;
    const ephemeralFile = await withTenantScope(
      { userId: userA },
      (tx) =>
        tx.file.create({
          data: {
            document: { connect: { id: docA } },
            storageKey: ephemeralHistoryKey,
            mimeType: "application/pdf",
            originalName: "browser-history.pdf",
            size: BigInt(2048),
          },
          select: { id: true, storageKey: true, storageObjectId: true },
        }),
      prismaRuntime,
    );
    assert.equal(ephemeralFile.storageObjectId, null);
    assert.equal(
      (await inScope(runtime, { userId: userA }, (c) => c.query("SELECT id FROM files WHERE id = $1", [ephemeralFile.id]))).rowCount,
      1,
    );
    assert.equal(
      (await inScope(runtime, { userId: userB }, (c) => c.query("SELECT id FROM files WHERE id = $1", [ephemeralFile.id]))).rowCount,
      0,
    );
    assert.equal(
      await findOutputFileForUser(userA, ephemeralFile.id, prismaRuntime),
      null,
      "ephemeral job-history file must never be exposed for physical object download",
    );

    // Immutability & column grants: dip_app cannot DELETE or mutate coordinates/ownership.
    await assert.rejects(() => inScope(runtime, { userId: userA }, (c) => c.query("DELETE FROM storage_objects WHERE id=$1", [personalObjA])), /permission denied/i);
    await assert.rejects(
      () => inScope(runtime, { userId: userA }, (c) => c.query("UPDATE storage_objects SET object_key='moved.pdf' WHERE id=$1", [personalObjA])),
      /permission denied|STORAGE_OBJECT_COORDINATES_IMMUTABLE/i,
    );

    // Retention role can SELECT across tenants/orphans and UPDATE only deleted_at.
    const retentionSeeAll = await retention.query(
      "SELECT id FROM storage_objects WHERE id = ANY($1::uuid[])",
      [
        [
          orphanObj,
          personalObjA,
          personalObjB,
          orgObjA,
          apiObjA1,
          apiObjA2,
          createdPersonal1.storageObjectId,
          createdApiFile.storageObjectId,
        ],
      ],
    );
    assert.equal(retentionSeeAll.rowCount, 8);
    assert.equal(
      (await retention.query("UPDATE storage_objects SET deleted_at = now() WHERE id = $1", [orphanObj])).rowCount,
      1,
    );
    await assert.rejects(() => retention.query("UPDATE storage_objects SET checksum = 'x' WHERE id = $1", [orphanObj]), /permission denied/i);
    await assert.rejects(() => retention.query("DELETE FROM storage_objects WHERE id = $1", [orphanObj]), /permission denied/i);
    await assert.rejects(
      () =>
        retention.query(
          "INSERT INTO storage_objects(id,owner_user_id,provider,bucket,object_key,size) VALUES($1,$2,'s3','dip-rls','ret.pdf',1)",
          [crypto.randomUUID(), userA],
        ),
      /permission denied/i,
    );
  } finally {
    await cleanup().catch(() => undefined);
    await prismaRuntime.$disconnect().catch(() => undefined);
    await retention.end();
    await runtime.end();
    await owner.end();
  }
});
