import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";

const integration = process.env.DIP_RLS_TEST_OWNER_URL && process.env.DIP_RETENTION_TEST_DATABASE_URL ? test : test.skip;

integration("retention role crosses tenant RLS only through narrow cleanup privileges", async () => {
  const owner = new pg.Client({ connectionString: process.env.DIP_RLS_TEST_OWNER_URL });
  const retention = new pg.Client({ connectionString: process.env.DIP_RETENTION_TEST_DATABASE_URL });
  await owner.connect(); await retention.connect();
  const users = [crypto.randomUUID(), crypto.randomUUID()];
  const jobs = [crypto.randomUUID(), crypto.randomUUID()];
  try {
    for (let index = 0; index < users.length; index += 1) {
      await owner.query("INSERT INTO users(id,email,status,created_at,updated_at) VALUES($1,$2,'ACTIVE',now(),now())", [users[index], `retention-${users[index]}@example.invalid`]);
      await owner.query("INSERT INTO jobs(id,tool_id,idempotency_key,requester_id,status,params,created_at,updated_at) VALUES($1,'compress-pdf',$2,$3,'QUEUED','{}',now()-interval '2 days',now())", [jobs[index], `retention-${jobs[index]}`, users[index]]);
    }
    assert.equal(Number((await retention.query("SELECT count(*) FROM jobs WHERE id=ANY($1::uuid[])", [jobs])).rows[0].count), 2);
    assert.equal((await retention.query("UPDATE jobs SET status='EXPIRED',error_code='JOB_EXPIRED',completed_at=now(),updated_at=now() WHERE id=ANY($1::uuid[])", [jobs])).rowCount, 2);
    await assert.rejects(() => retention.query("DELETE FROM jobs WHERE id=$1", [jobs[0]]), /permission denied/);
    await assert.rejects(() => retention.query("SELECT * FROM api_keys"), /permission denied/);
  } finally {
    await owner.query("DELETE FROM jobs WHERE id=ANY($1::uuid[])", [jobs]);
    await owner.query("DELETE FROM users WHERE id=ANY($1::uuid[])", [users]);
    await retention.end(); await owner.end();
  }
});
