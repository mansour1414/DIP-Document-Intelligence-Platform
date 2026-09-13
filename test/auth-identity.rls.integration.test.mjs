import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import pg from "pg";

const { Client } = pg;
const integration = process.env.DIP_RLS_TEST_DATABASE_URL && process.env.DIP_RLS_TEST_OWNER_URL ? test : test.skip;

integration("CR-003 users RLS scopes pre-auth and authenticated identity access", async () => {
  const owner = new Client({ connectionString: process.env.DIP_RLS_TEST_OWNER_URL });
  const runtime = new Client({ connectionString: process.env.DIP_RLS_TEST_DATABASE_URL });
  const a = randomUUID();
  const b = randomUUID();
  const inserted = randomUUID();
  const emailA = `auth-rls-a-${a}@example.invalid`;
  const emailB = `auth-rls-b-${b}@example.invalid`;
  const insertedEmail = `auth-rls-insert-${inserted}@example.invalid`;
  await owner.connect();
  await runtime.connect();

  const cleanup = () => owner.query(`DELETE FROM users WHERE id = ANY($1::uuid[])`, [[a, b, inserted]]);
  const scoped = async (setting, value, operation) => {
    await runtime.query("BEGIN");
    try {
      await runtime.query(`SELECT set_config($1, $2, true)`, [setting, value]);
      const result = await operation();
      await runtime.query("COMMIT");
      return result;
    } catch (error) {
      await runtime.query("ROLLBACK");
      throw error;
    }
  };

  try {
    await cleanup();
    await owner.query(`INSERT INTO users(id,email,status,created_at,updated_at) VALUES($1,$2,'ACTIVE',now(),now()),($3,$4,'ACTIVE',now(),now())`, [a, emailA, b, emailB]);

    assert.equal((await runtime.query(`SELECT id FROM users`)).rowCount, 0);
    await assert.rejects(() => runtime.query(`UPDATE users SET display_name='blocked' WHERE id=$1`, [a]), /permission denied/i);
    await assert.rejects(() => runtime.query(`DELETE FROM users WHERE id=$1`, [a]), /permission denied/i);

    await scoped("app.auth_email", emailA, async () => {
      const rows = await runtime.query(`SELECT id FROM users`);
      assert.deepEqual(rows.rows.map((row) => row.id), [a]);
    });
    await assert.rejects(() => scoped("app.auth_email", emailA, () => runtime.query(`UPDATE users SET display_name='blocked' WHERE id=$1`, [a])), /permission denied/i);
    await assert.rejects(() => scoped("app.auth_email", emailA, () => runtime.query(`DELETE FROM users WHERE id=$1`, [a])), /permission denied/i);
    await assert.rejects(() => scoped("app.auth_email", emailA, () => runtime.query(`INSERT INTO users(id,email,status,created_at,updated_at) VALUES($1,$2,'ACTIVE',now(),now())`, [inserted, emailB])), /row-level security/i);

    await scoped("app.auth_email", insertedEmail, async () => {
      const result = await runtime.query(`INSERT INTO users(id,email,status,created_at,updated_at) VALUES($1,$2,'ACTIVE',now(),now()) RETURNING id`, [inserted, insertedEmail]);
      assert.equal(result.rows[0].id, inserted);
    });

    await scoped("app.current_user_id", a, async () => {
      const rows = await runtime.query(`SELECT id FROM users`);
      assert.deepEqual(rows.rows.map((row) => row.id), [a]);
    });
    await scoped("app.current_user_id", b, async () => {
      assert.equal((await runtime.query(`SELECT id FROM users WHERE id=$1`, [a])).rowCount, 0);
    });
    await scoped("app.auth_email", "malformed", async () => {
      assert.equal((await runtime.query(`SELECT id FROM users`)).rowCount, 0);
    });

    assert.equal((await runtime.query(`SELECT id FROM users`)).rowCount, 0, "transaction-local auth scope must not leak");
    const role = (await owner.query(`SELECT rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,rolinherit FROM pg_roles WHERE rolname='dip_app'`)).rows[0];
    assert.deepEqual(role, { rolsuper: false, rolbypassrls: false, rolcreatedb: false, rolcreaterole: false, rolinherit: false });
  } finally {
    await cleanup();
    await runtime.end();
    await owner.end();
  }
});
