import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import pg from "pg";

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

integration("N1-A storage_objects enforces real PostgreSQL RLS, FORCE RLS, triggers, composite FK, orphan quarantine, and retention least privilege", async () => {
  const owner = new pg.Pool({ connectionString: ownerUrl, max: 2 });
  const runtime = new pg.Pool({ connectionString: runtimeUrl, max: 4 });
  const retention = new pg.Pool({ connectionString: retentionUrl, max: 2 });

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
  const orphanObj = crypto.randomUUID();
  const personalObjA = crypto.randomUUID();
  const personalObjB = crypto.randomUUID();
  const orgObjA = crypto.randomUUID();
  const apiObjA1 = crypto.randomUUID();

  const cleanup = async () => {
    await owner.query("DELETE FROM files WHERE document_id = ANY($1::uuid[])", [[docA, docB]]);
    await owner.query("DELETE FROM documents WHERE id = ANY($1::uuid[])", [[docA, docB]]);
    await owner.query(
      "DELETE FROM storage_objects WHERE id = ANY($1::uuid[]) OR owner_user_id = ANY($2::uuid[])",
      [[orphanObj, personalObjA, personalObjB, orgObjA, apiObjA1], [userA, userA2, userB]],
    );
    await owner.query("DELETE FROM api_clients WHERE id = ANY($1::uuid[])", [[clientA1, clientA2, clientB1]]);
    await owner.query("DELETE FROM memberships WHERE organization_id = ANY($1::uuid[])", [[orgA, orgB]]);
    await owner.query("DELETE FROM organizations WHERE id = ANY($1::uuid[])", [[orgA, orgB]]);
    await owner.query("DELETE FROM users WHERE id = ANY($1::uuid[])", [[userA, userA2, userB]]);
  };

  try {
    // 16. Verify pg_class RLS + FORCE RLS and non-bypass runtime/retention roles.
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
    await owner.query(
      "INSERT INTO api_clients(id,organization_id,created_by_user_id,name,status,created_at,updated_at) VALUES($1,$2,$3,'A1','ACTIVE',now(),now()),($4,$2,$3,'A2','ACTIVE',now(),now()),($5,$6,$7,'B1','ACTIVE',now(),now())",
      [clientA1, orgA, userA, clientA2, clientB1, orgB, userB],
    );
    await owner.query(
      "INSERT INTO documents(id,user_id,title,status,created_at,updated_at) VALUES($1,$2,'Doc A','ACTIVE',now(),now()),($3,$4,'Doc B','ACTIVE',now(),now())",
      [docA, userA, docB, userB],
    );

    // Seed an unlinked historical orphan row (NULL ownership).
    await owner.query(
      "INSERT INTO storage_objects(id,owner_user_id,organization_id,api_client_id,provider,bucket,object_key,size,created_at) VALUES($1,NULL,NULL,NULL,'s3','dip-rls',$2,64,now())",
      [orphanObj, `orphan/${orphanObj}.pdf`],
    );

    // 5. Missing/empty tenant context fails closed.
    assert.equal((await runtime.query("SELECT id FROM storage_objects")).rowCount, 0);
    await assert.rejects(
      () =>
        runtime.query(
          "INSERT INTO storage_objects(id,owner_user_id,provider,bucket,object_key,size) VALUES($1,$2,'s3','dip-rls','unscoped.pdf',10)",
          [crypto.randomUUID(), userA],
        ),
      /row-level security/i,
    );

    // 1-4 & 6. Personal user-owned INSERT, SELECT, cross-tenant isolation, and unauthorized INSERT rejection.
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

    // 7-8. Organization & API-client isolation + composite FK enforcement.
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
    assert.equal(
      (await inScope(runtime, { organizationId: orgA, apiClientId: clientA1 }, (c) => c.query("SELECT id FROM storage_objects WHERE id=$1", [apiObjA1]))).rowCount,
      1,
    );
    assert.equal(
      (await inScope(runtime, { organizationId: orgA, apiClientId: clientA2 }, (c) => c.query("SELECT id FROM storage_objects WHERE id=$1", [apiObjA1]))).rowCount,
      0,
    );
    assert.equal(
      (await inScope(runtime, { organizationId: orgB, apiClientId: clientB1 }, (c) => c.query("SELECT id FROM storage_objects WHERE id=$1", [apiObjA1]))).rowCount,
      0,
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

    // 12 & 13. Cross-tenant File -> StorageObject link and orphan link are rejected by trigger; object-key collision fails closed.
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

    // Immutability & column grants: dip_app cannot DELETE or mutate coordinates/ownership.
    await assert.rejects(() => inScope(runtime, { userId: userA }, (c) => c.query("DELETE FROM storage_objects WHERE id=$1", [personalObjA])), /permission denied/i);
    await assert.rejects(
      () => inScope(runtime, { userId: userA }, (c) => c.query("UPDATE storage_objects SET object_key='moved.pdf' WHERE id=$1", [personalObjA])),
      /permission denied|STORAGE_OBJECT_COORDINATES_IMMUTABLE/i,
    );

    // 15. Retention role can SELECT across tenants/orphans and UPDATE only deleted_at.
    const retentionSeeAll = await retention.query(
      "SELECT id FROM storage_objects WHERE id = ANY($1::uuid[])",
      [[orphanObj, personalObjA, personalObjB, orgObjA, apiObjA1]],
    );
    assert.equal(retentionSeeAll.rowCount, 5);
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
    await cleanup();
    await Promise.all([runtime.end(), retention.end(), owner.end()]);
  }
});
