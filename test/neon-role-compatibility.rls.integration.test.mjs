import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import pg from "pg";

const execFileAsync = promisify(execFile);

const adminUrl = process.env.DIP_PG18_ADMIN_URL?.trim();
const runtimeBaseUrl = process.env.DIP_RLS_TEST_DATABASE_URL?.trim();
const retentionBaseUrl = process.env.DIP_RETENTION_TEST_DATABASE_URL?.trim();

const ALLOWED_LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]", "postgres"]);

function buildDbUrl(baseUrl, pathname, username, password) {
  const parsed = new URL(baseUrl);
  if (!ALLOWED_LOCAL_HOSTS.has(parsed.hostname.toLowerCase())) {
    throw new Error(`FORBIDDEN_TEST_HOST: refusing non-disposable host ${parsed.hostname}`);
  }
  parsed.pathname = `/${pathname}`;
  if (username !== undefined) {
    parsed.username = username;
  }
  if (password !== undefined) {
    parsed.password = password;
  }
  return parsed.toString();
}

const rolesBootstrapSql = readFileSync(new URL("../prisma/bootstrap/roles.sql", import.meta.url), "utf8");
const runtimeGrantsSql = readFileSync(new URL("../prisma/bootstrap/dip_app.sql", import.meta.url), "utf8");
const n1aMigrationSql = readFileSync(
  new URL("../prisma/migrations/20261121120000_n1a_storage_objects_tenant_isolation/migration.sql", import.meta.url),
  "utf8",
);

const historicalMigrationDirs = readdirSync(new URL("../prisma/migrations", import.meta.url), { withFileTypes: true })
  .filter((entry) => entry.isDirectory() && entry.name < "20261121120000_n1a_storage_objects_tenant_isolation")
  .map((entry) => entry.name)
  .sort();

test(
  "Neon PostgreSQL 18 non-superuser migration owner & fail-closed role preflight compatibility",
  { skip: !adminUrl || !runtimeBaseUrl || !retentionBaseUrl },
  async (t) => {
    const schemaOwnerRole = "dip_schema_owner";
    const schemaOwnerPassword = "dip_pg18_schema_owner_pw";
    const compatDb = "dip_neon_compat_pg18";
    const negDb = "dip_neon_neg_pg18";

    const adminClient = new pg.Client({ connectionString: adminUrl });
    await adminClient.connect();

    async function restoreCanonicalRuntimeRoles() {
      const existing = await adminClient.query(
        `SELECT rolname FROM pg_catalog.pg_roles WHERE rolname IN ('dip_app_absent_tmp', 'dip_retention_absent_tmp')`,
      );
      for (const row of existing.rows) {
        if (row.rolname === "dip_app_absent_tmp") {
          await adminClient.query("ALTER ROLE dip_app_absent_tmp RENAME TO dip_app");
        }
        if (row.rolname === "dip_retention_absent_tmp") {
          await adminClient.query("ALTER ROLE dip_retention_absent_tmp RENAME TO dip_retention");
        }
      }
      await adminClient.query("REVOKE neon_superuser FROM dip_app, dip_retention").catch(() => undefined);
      await adminClient.query("REVOKE pg_read_all_data FROM dip_app, dip_retention").catch(() => undefined);
      await adminClient.query(
        "ALTER ROLE dip_app LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION",
      );
      await adminClient.query(
        "ALTER ROLE dip_retention LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION",
      );
    }

    t.after(async () => {
      try {
        await restoreCanonicalRuntimeRoles();
        await adminClient.query(`DROP DATABASE IF EXISTS ${compatDb} WITH (FORCE)`);
        await adminClient.query(`DROP DATABASE IF EXISTS ${negDb} WITH (FORCE)`);
        await adminClient.query(`DROP ROLE IF EXISTS ${schemaOwnerRole}`);
        await adminClient.query("DROP ROLE IF EXISTS neon_superuser");
      } finally {
        await adminClient.end();
      }
    });

    // Clean any leftover artifacts from an interrupted local run before provisioning.
    await adminClient.query(`DROP DATABASE IF EXISTS ${compatDb} WITH (FORCE)`);
    await adminClient.query(`DROP DATABASE IF EXISTS ${negDb} WITH (FORCE)`);
    await adminClient.query(`DROP ROLE IF EXISTS ${schemaOwnerRole}`);
    await adminClient.query("DROP ROLE IF EXISTS neon_superuser");

    // Separate authorized test administrator provisions least-privilege runtime/retention roles
    // plus a simulated neon_superuser role (for negative membership tests) and a strictly
    // unprivileged non-superuser schema/migration owner.
    await adminClient.query(rolesBootstrapSql);
    await adminClient.query("CREATE ROLE neon_superuser NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION");
    await adminClient.query(
      `CREATE ROLE ${schemaOwnerRole} LOGIN PASSWORD '${schemaOwnerPassword}' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT`,
    );

    await adminClient.query(`CREATE DATABASE ${compatDb} OWNER ${schemaOwnerRole}`);
    await adminClient.query(`CREATE DATABASE ${negDb} OWNER ${schemaOwnerRole}`);
    await adminClient.query(`GRANT CONNECT, TEMP ON DATABASE ${compatDb} TO ${schemaOwnerRole}, dip_app, dip_retention`);
    await adminClient.query(`GRANT CONNECT, TEMP ON DATABASE ${negDb} TO ${schemaOwnerRole}, dip_app, dip_retention`);

    for (const dbName of [compatDb, negDb]) {
      const dbAdmin = new pg.Client({ connectionString: buildDbUrl(adminUrl, dbName) });
      await dbAdmin.connect();
      try {
        await dbAdmin.query(`ALTER SCHEMA public OWNER TO ${schemaOwnerRole}`);
        await dbAdmin.query(`GRANT ALL ON SCHEMA public TO ${schemaOwnerRole}`);
      } finally {
        await dbAdmin.end();
      }
    }

    const compatOwnerUrl = buildDbUrl(adminUrl, compatDb, schemaOwnerRole, schemaOwnerPassword);
    const negOwnerUrl = buildDbUrl(adminUrl, negDb, schemaOwnerRole, schemaOwnerPassword);
    const negAppUrl = buildDbUrl(runtimeBaseUrl, negDb);
    const negRetentionUrl = buildDbUrl(retentionBaseUrl, negDb);

    await t.test("1. PostgreSQL 18 forbids non-superuser ALTER ROLE ... NOSUPERUSER/NOBYPASSRLS (reproducing Neon blocker)", async () => {
      const ownerClient = new pg.Client({ connectionString: compatOwnerUrl });
      await ownerClient.connect();
      try {
        const versionRes = await ownerClient.query(
          "SELECT current_setting('server_version_num')::int AS server_version_num, current_user AS caller",
        );
        assert.ok(
          Number(versionRes.rows[0].server_version_num) >= 180000,
          `Expected PostgreSQL >= 18, got ${versionRes.rows[0].server_version_num}`,
        );
        assert.equal(versionRes.rows[0].caller, schemaOwnerRole);

        const ownerPosture = await ownerClient.query(
          `SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolreplication, rolinherit, rolcanlogin
             FROM pg_catalog.pg_roles
            WHERE rolname = $1`,
          [schemaOwnerRole],
        );
        assert.deepEqual(ownerPosture.rows[0], {
          rolsuper: false,
          rolbypassrls: false,
          rolcreatedb: false,
          rolcreaterole: false,
          rolreplication: false,
          rolinherit: false,
          rolcanlogin: true,
        });

        await assert.rejects(
          () => ownerClient.query("ALTER ROLE dip_app NOSUPERUSER"),
          (err) => err?.code === "42501",
          "PostgreSQL 18 must reject ALTER ROLE ... NOSUPERUSER from a non-superuser",
        );
        await assert.rejects(
          () => ownerClient.query("ALTER ROLE dip_app NOBYPASSRLS"),
          (err) => err?.code === "42501",
          "PostgreSQL 18 must reject ALTER ROLE ... NOBYPASSRLS from a non-superuser",
        );
      } finally {
        await ownerClient.end();
      }
    });

    await t.test("2. Routine prisma/bootstrap/roles.sql passes as non-superuser read-only check without ALTER ROLE", async () => {
      const ownerClient = new pg.Client({ connectionString: compatOwnerUrl });
      await ownerClient.connect();
      try {
        await ownerClient.query(rolesBootstrapSql);
      } finally {
        await ownerClient.end();
      }
    });

    await t.test("3. Full prisma migrate deploy + dip_app.sql succeed under non-superuser schema owner and enforce FORCE RLS", async () => {
      const prismaBin = resolve(process.cwd(), "node_modules/.bin/prisma");
      const { stdout, stderr } = await execFileAsync(prismaBin, ["migrate", "deploy"], {
        cwd: process.cwd(),
        env: {
          ...process.env,
          DATABASE_URL: compatOwnerUrl,
          DATABASE_URL_UNPOOLED: compatOwnerUrl,
        },
      });
      const combinedOutput = `${stdout}\n${stderr}`;
      assert.match(combinedOutput, /20261121120000_n1a_storage_objects_tenant_isolation/);

      const ownerClient = new pg.Client({ connectionString: compatOwnerUrl });
      await ownerClient.connect();
      try {
        await ownerClient.query(runtimeGrantsSql);

        const applied = await ownerClient.query(
          `SELECT migration_name, finished_at, rolled_back_at
             FROM "_prisma_migrations"
            ORDER BY migration_name`,
        );
        assert.equal(applied.rowCount, 13, "All 13 migrations must apply cleanly under non-superuser owner");
        for (const row of applied.rows) {
          assert.notEqual(row.finished_at, null, `${row.migration_name} must have finished_at populated`);
          assert.equal(row.rolled_back_at, null, `${row.migration_name} must not be rolled back`);
        }

        const relRes = await ownerClient.query(
          `SELECT c.relrowsecurity, c.relforcerowsecurity, pg_catalog.pg_get_userbyid(c.relowner) AS owner_name
             FROM pg_catalog.pg_class c
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relname = 'storage_objects'`,
        );
        assert.deepEqual(relRes.rows[0], {
          relrowsecurity: true,
          relforcerowsecurity: true,
          owner_name: schemaOwnerRole,
        });

        const fnRes = await ownerClient.query(
          `SELECT p.proname, p.prosecdef, pg_catalog.pg_get_userbyid(p.proowner) AS owner_name
             FROM pg_catalog.pg_proc p
             JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public'
              AND p.proname IN (
                'app_api_client_matches_tenant',
                'enforce_storage_object_immutability',
                'enforce_file_storage_object_tenant_match',
                'enforce_document_storage_object_tenant_match'
              )
            ORDER BY p.proname`,
        );
        assert.equal(fnRes.rowCount, 4);
        for (const row of fnRes.rows) {
          assert.equal(row.prosecdef, true);
          assert.equal(row.owner_name, schemaOwnerRole);
        }

        // Seed 1 row via superuser and confirm even the NOBYPASSRLS table owner sees 0 rows under FORCE RLS.
        const compatAdmin = new pg.Client({ connectionString: buildDbUrl(adminUrl, compatDb) });
        await compatAdmin.connect();
        try {
          await compatAdmin.query(
            `INSERT INTO "users" ("id", "email", "updated_at")
             VALUES ('11111111-1111-4111-8111-111111111111', 'force-rls-owner-check@dip.local', NOW())`,
          );
          await compatAdmin.query(
            `INSERT INTO "storage_objects" ("id", "provider", "bucket", "object_key", "size", "owner_user_id")
             VALUES ('22222222-2222-4222-8222-222222222222', 's3', 'dip-test', 'input/11111111-1111-4111-8111-111111111111/test.pdf', 128, '11111111-1111-4111-8111-111111111111')`,
          );
        } finally {
          await compatAdmin.end();
        }

        const ownerScan = await ownerClient.query(`SELECT id FROM "storage_objects"`);
        assert.equal(
          ownerScan.rowCount,
          0,
          "FORCE ROW LEVEL SECURITY must block unscoped reads even by the NOBYPASSRLS table owner",
        );
      } finally {
        await ownerClient.end();
      }
    });

    await t.test("4. Missing, elevated, or member-attached runtime/retention roles fail closed BEFORE modifying schema", async () => {
      const negOwner = new pg.Client({ connectionString: negOwnerUrl });
      await negOwner.connect();

      try {
        for (const dir of historicalMigrationDirs) {
          const histSql = readFileSync(new URL(`../prisma/migrations/${dir}/migration.sql`, import.meta.url), "utf8");
          await negOwner.query(histSql);
        }
        await negOwner.query(runtimeGrantsSql);

        async function assertN1aColumnsAbsent() {
          const cols = await negOwner.query(
            `SELECT column_name
               FROM information_schema.columns
              WHERE table_schema = 'public'
                AND table_name = 'storage_objects'
                AND column_name IN ('owner_user_id', 'organization_id', 'api_client_id')`,
          );
          assert.equal(cols.rowCount, 0, "Failed preflight must roll back cleanly before altering storage_objects");
        }

        async function expectOwnerMigrationFailure(pattern) {
          await assert.rejects(
            async () => {
              try {
                await negOwner.query(n1aMigrationSql);
              } catch (err) {
                await negOwner.query("ROLLBACK").catch(() => undefined);
                throw err;
              }
            },
            pattern,
          );
        }

        // 4a. Rejects running N1-A migration or roles.sql directly as dip_app or dip_retention.
        for (const [roleLabel, connStr] of [
          ["dip_app", negAppUrl],
          ["dip_retention", negRetentionUrl],
        ]) {
          const roleClient = new pg.Client({ connectionString: connStr });
          await roleClient.connect();
          try {
            await assert.rejects(
              async () => {
                try {
                  await roleClient.query(n1aMigrationSql);
                } catch (err) {
                  await roleClient.query("ROLLBACK").catch(() => undefined);
                  throw err;
                }
              },
              new RegExp(`MIGRATION_ROLE_INVALID.*${roleLabel}`),
            );
            await assert.rejects(
              () => roleClient.query(rolesBootstrapSql),
              new RegExp(`ROLE_BOOTSTRAP_CALLER_INVALID.*${roleLabel}`),
            );
          } finally {
            await roleClient.end();
          }
        }

        // 4b. Missing dip_app and missing dip_retention fail closed in both migration.sql and non-superuser roles.sql.
        for (const [targetRole, tempName] of [
          ["dip_app", "dip_app_absent_tmp"],
          ["dip_retention", "dip_retention_absent_tmp"],
        ]) {
          await adminClient.query(`ALTER ROLE ${targetRole} RENAME TO ${tempName}`);
          try {
            await expectOwnerMigrationFailure(new RegExp(`ROLE_PREFLIGHT_MISSING: required database role "${targetRole}"`));
            await assert.rejects(
              () => negOwner.query(rolesBootstrapSql),
              new RegExp(`ROLE_BOOTSTRAP_PRIVILEGE_REQUIRED: required role "${targetRole}"`),
            );
          } finally {
            await adminClient.query(`ALTER ROLE ${tempName} RENAME TO ${targetRole}`);
          }
        }

        // 4c. Every elevated or malformed attribute on dip_app / dip_retention fails closed.
        const malformedCases = [
          ["dip_app", "SUPERUSER", /ROLE_PREFLIGHT_INVALID: role "dip_app".*rolsuper=true \(expected NOSUPERUSER\)/],
          ["dip_app", "BYPASSRLS", /ROLE_PREFLIGHT_INVALID: role "dip_app".*rolbypassrls=true \(expected NOBYPASSRLS\)/],
          ["dip_app", "INHERIT", /ROLE_PREFLIGHT_INVALID: role "dip_app".*rolinherit=true \(expected NOINHERIT\)/],
          ["dip_app", "CREATEDB", /ROLE_PREFLIGHT_INVALID: role "dip_app".*rolcreatedb=true \(expected NOCREATEDB\)/],
          ["dip_app", "CREATEROLE", /ROLE_PREFLIGHT_INVALID: role "dip_app".*rolcreaterole=true \(expected NOCREATEROLE\)/],
          ["dip_app", "REPLICATION", /ROLE_PREFLIGHT_INVALID: role "dip_app".*rolreplication=true \(expected NOREPLICATION\)/],
          ["dip_app", "NOLOGIN", /ROLE_PREFLIGHT_INVALID: role "dip_app".*rolcanlogin=false \(expected LOGIN\)/],
          ["dip_retention", "BYPASSRLS", /ROLE_PREFLIGHT_INVALID: role "dip_retention".*rolbypassrls=true \(expected NOBYPASSRLS\)/],
          ["dip_retention", "INHERIT", /ROLE_PREFLIGHT_INVALID: role "dip_retention".*rolinherit=true \(expected NOINHERIT\)/],
        ];

        for (const [roleName, badFlag, expectedError] of malformedCases) {
          await adminClient.query(`ALTER ROLE ${roleName} ${badFlag}`);
          try {
            await expectOwnerMigrationFailure(expectedError);
            await assert.rejects(() => negOwner.query(rolesBootstrapSql), expectedError);
          } finally {
            await restoreCanonicalRuntimeRoles();
          }
        }

        // 4d. Unsafe role memberships (e.g. Neon's neon_superuser or pg_read_all_data) fail closed.
        await adminClient.query("GRANT neon_superuser TO dip_app");
        try {
          await expectOwnerMigrationFailure(/ROLE_PREFLIGHT_MEMBERSHIP_INVALID: role "dip_app".*\[neon_superuser\]/);
          await assert.rejects(
            () => negOwner.query(rolesBootstrapSql),
            /ROLE_PREFLIGHT_MEMBERSHIP_INVALID: role "dip_app".*\[neon_superuser\]/,
          );
          await assert.rejects(
            () => adminClient.query(rolesBootstrapSql),
            /ROLE_PREFLIGHT_MEMBERSHIP_INVALID: role "dip_app".*\[neon_superuser\]/,
          );
        } finally {
          await restoreCanonicalRuntimeRoles();
        }

        await adminClient.query("GRANT pg_read_all_data TO dip_retention");
        try {
          await expectOwnerMigrationFailure(/ROLE_PREFLIGHT_MEMBERSHIP_INVALID: role "dip_retention".*\[pg_read_all_data\]/);
          await assert.rejects(
            () => negOwner.query(rolesBootstrapSql),
            /ROLE_PREFLIGHT_MEMBERSHIP_INVALID: role "dip_retention".*\[pg_read_all_data\]/,
          );
        } finally {
          await restoreCanonicalRuntimeRoles();
        }

        // Confirm zero schema mutation leaked across any negative preflight failure.
        await assertN1aColumnsAbsent();

        // Once clean least-privilege roles are restored, N1-A migration succeeds under non-superuser owner.
        await negOwner.query(n1aMigrationSql);

        const colsAfter = await negOwner.query(
          `SELECT column_name
             FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'storage_objects'
              AND column_name IN ('owner_user_id', 'organization_id', 'api_client_id')
            ORDER BY column_name`,
        );
        assert.deepEqual(
          colsAfter.rows.map((r) => r.column_name),
          ["api_client_id", "organization_id", "owner_user_id"],
        );
      } finally {
        await negOwner.end();
      }
    });
  },
);
