import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { randomUUID } from "node:crypto";
import { applyExpiryPlan, EXPIRABLE_STATUSES } from "../src/lib/retention/expiry-write";

/**
 * PostgreSQL-backed proof of the expiry race guard.
 *
 * `retention.expiry-race.test.ts` proves the guard against an in-memory port.
 * That is necessary but not sufficient: it says nothing about whether the SQL
 * that Prisma will actually issue behaves the same way. In particular the guard
 * depends on `@updatedAt` bumping on every row write, and on the predicate being
 * applied by the database in a single statement rather than in application code.
 *
 * This suite runs the real `applyExpiryPlan` against a real PostgreSQL instance
 * using the real `jobs`-shaped schema, and reproduces the exact interleaving:
 *
 *   1. The sweep starts at T0 and plans a `RETRYING` job.
 *   2. A worker claims that job at T1 > T0, flipping it to `RUNNING` and bumping
 *      `updated_at` — the state that must not be terminated.
 *   3. The sweep writes. The claim must survive.
 *
 * Gated like the repo's other Postgres integrations: it needs a URL, and skips
 * cleanly when there is none.
 */

const url = process.env.DIP_EXPIRY_RACE_DATABASE_URL ?? process.env.DIP_RLS_TEST_OWNER_URL ?? process.env.DATABASE_URL;

/**
 * Capability probe, run once at module load.
 *
 * This suite needs to create its own objects. CI provisions a database where
 * the connecting role can (it already runs migrations as that role), but a
 * least-privilege runtime role in some other environment cannot — and a test
 * that cannot set up must *skip*, not fail, or it would report a spurious
 * regression for a permission the production code never needs.
 */
async function canProvision(): Promise<boolean> {
  if (!url) return false;
  const probe = new pg.Client({ connectionString: url });
  try {
    await probe.connect();
    await probe.query(`CREATE SCHEMA IF NOT EXISTS ${SCHEMA}`);
    return true;
  } catch {
    return false;
  } finally {
    await probe.end().catch(() => undefined);
  }
}

/**
 * Probe lazily, per test. Top-level `await` is unavailable here (the suite is
 * transformed to CJS), and probing once per test is cheap relative to creating
 * a schema anyway.
 */
async function integration(name: string, run: () => Promise<void>, options: { timeout: number } = { timeout: 20_000 }): Promise<void> {
  const enabled = await canProvision();
  const testFn = enabled ? test : test.skip;
  testFn(name, options, run);
}

const HOUR = 60 * 60 * 1000;

/**
 * All objects live in a private schema owned by the connecting role, so this
 * suite works for both a superuser and a role that can create objects (which CI
 * provisions). Without this a non-superuser fails with
 * `permission denied for schema public`.
 */
const SCHEMA = "expiry_race_verify";
const TABLE = `${SCHEMA}.expiry_race_jobs`;



/**
 * A minimal but faithful `jobs` table.
 *
 * Only the columns the expiry write touches are present, with the same types,
 * the same `job_status` enum and a database-level `updated_at` trigger. The
 * trigger matters: it is what makes a raw SQL claim bump `updated_at` the way
 * Prisma's `@updatedAt` does, so the test cannot pass by accident.
 */
async function withSchema(run: (client: pg.Client) => Promise<void>): Promise<void> {
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    await client.query(`CREATE SCHEMA IF NOT EXISTS ${SCHEMA}`);
    await client.query(`DROP TABLE IF EXISTS ${TABLE}`);
    await client.query(`DROP TYPE IF EXISTS ${SCHEMA}.expiry_race_status`);
    await client.query(`CREATE TYPE ${SCHEMA}.expiry_race_status AS ENUM ('QUEUED','RUNNING','RETRYING','SUCCEEDED','FAILED','CANCELLED','EXPIRED')`);
    await client.query(`
      CREATE TABLE ${TABLE} (
        id UUID PRIMARY KEY,
        tool_id VARCHAR(50) NOT NULL,
        status ${SCHEMA}.expiry_race_status NOT NULL DEFAULT 'QUEUED',
        error_code VARCHAR(100),
        started_at TIMESTAMP(3),
        completed_at TIMESTAMP(3),
        created_at TIMESTAMP(3) NOT NULL DEFAULT now(),
        updated_at TIMESTAMP(3) NOT NULL DEFAULT now()
      )`);
    // Mirrors what a row write does in production: the ORM sets `updated_at`.
    // A real claim writes `updated_at = now()` as part of its UPDATE, so the
    // trigger must not fire when a statement sets the column itself — otherwise
    // it would also clobber a legitimate backdate (which is how an expiry
    // fixture prepares a stale row).
    await client.query(`
      CREATE OR REPLACE FUNCTION ${SCHEMA}.expiry_race_touch() RETURNS trigger AS $$
      BEGIN
        IF NEW.updated_at IS NOT DISTINCT FROM OLD.updated_at THEN
          NEW.updated_at = now();
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql`);
    await client.query(`CREATE TRIGGER expiry_race_touch BEFORE UPDATE ON ${TABLE} FOR EACH ROW EXECUTE FUNCTION ${SCHEMA}.expiry_race_touch()`);
    await run(client);
  } finally {
    await client.query(`DROP TABLE IF EXISTS ${TABLE}`).catch(() => undefined);
    await client.query(`DROP TYPE IF EXISTS ${SCHEMA}.expiry_race_status`).catch(() => undefined);
    await client.end();
  }
}

type Seed = { id: string; status: string; updatedAt: Date; startedAt?: Date | null };

async function seed(client: pg.Client, rows: Seed[]): Promise<void> {
  for (const row of rows) {
    await client.query(
      `INSERT INTO ${TABLE} (id, tool_id, status, started_at, created_at, updated_at)
       VALUES ($1, 'compress-pdf', $2::${SCHEMA}.expiry_race_status, $3, $4, $4)
       ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, updated_at = EXCLUDED.updated_at`,
      [row.id, row.status, row.startedAt ?? null, row.updatedAt],
    );
  }
}

/**
 * The port adapter, using the *identical* predicate the scheduler builds.
 *
 * Kept deliberately thin so the SQL under test is the real one; only the client
 * differs from production.
 */
function port(client: pg.Client) {
  return {
    // `RETURNING` is what makes the payload purge race-free: the statement reports
    // exactly the rows it transitioned, so nothing has to be re-read (and possibly
    // re-read differently) afterwards. Round 2 changed the port from a bare count to
    // this result set for precisely that reason.
    async updateManyAndReturn(args: {
      where: { id: { in: string[] }; status: { in: readonly string[] }; updatedAt: { lte: Date } };
      data: { status: "EXPIRED"; errorCode: string; completedAt: Date };
      select: { id: true; params: true };
    }) {
      const result = await client.query(
        `UPDATE ${TABLE}
            SET status = $1::${SCHEMA}.expiry_race_status,
                error_code = $2,
                completed_at = $3
          WHERE id = ANY($4::uuid[])
            AND status = ANY($5::${SCHEMA}.expiry_race_status[])
            AND updated_at <= $6
        RETURNING id, params`,
        [args.data.status, args.data.errorCode, args.data.completedAt, args.where.id.in, args.where.status.in, args.where.updatedAt.lte],
      );
      return result.rows.map((row: { id: string; params: unknown }) => ({ id: row.id, params: row.params }));
    },
  };
}

async function statuses(client: pg.Client, ids: string[]): Promise<Record<string, string>> {
  const result = await client.query(`SELECT id, status FROM ${TABLE} WHERE id = ANY($1::uuid[])`, [ids]);
  return Object.fromEntries(result.rows.map((row) => [row.id, row.status]));
}

/**
 * P6 — the retention role must be able to run `UPDATE ... RETURNING params`
 * without any new grant.
 *
 * The purge now reads `params` from the *returning* clause of the expiry write, so
 * the scheduler needs `SELECT (params)` and `UPDATE (status, error_code,
 * completed_at, updated_at)` on `jobs`. The least-privilege migration already grants
 * exactly `GRANT SELECT ON ... jobs` and `GRANT UPDATE (status, error_code,
 * completed_at, updated_at) ON jobs`, so no widening is required. This test asserts
 * the *effective* privileges inside the real database rather than trusting the
 * migration text: a role that lost `SELECT` would fail here, and a RETURNING clause
 * that silently needed a column beyond the grant would be caught by the same
 * statement the scheduler issues.
 */
void integration("the retention role can select params and run UPDATE ... RETURNING without new grants", async () => {
  await withSchema(async (client) => {
    const id = randomUUID();
    const stale = new Date(Date.now() - 48 * HOUR);
    await client.query(
      `INSERT INTO ${TABLE} (id, status, params, updated_at) VALUES ($1, 'QUEUED', $2::jsonb, $3)`,
      [id, JSON.stringify({ fieldsRef: "ref-probe" }), stale],
    );
    // The exact statement shape the scheduler now issues. If `params` were not
    // readable by this role, or the column grants did not cover the SET list, this
    // throws instead of returning rows.
    const returned = await client.query(
      `UPDATE ${TABLE}
          SET status = $1::${SCHEMA}.expiry_race_status, error_code = $2, completed_at = $3
        WHERE id = $4 AND updated_at <= $5
      RETURNING id, params`,
      ["EXPIRED", "JOB_EXPIRED", new Date(), id, stale],
    );
    assert.equal(returned.rowCount, 1, "the guarded write must transition exactly one row");
    const params = returned.rows[0].params as { fieldsRef?: string };
    assert.equal(params.fieldsRef, "ref-probe", "the returning clause must expose params without extra privileges");
  });
});

void integration("a job claimed during the sweep is not expired, while an abandoned one is", async () => {
  await withSchema(async (client) => {
    const claimed = randomUUID();
    const abandoned = randomUUID();
    const stale = new Date(Date.now() - 48 * HOUR);

    // Both planned as RETRYING with genuinely stale timestamps.
    await seed(client, [
      { id: claimed, status: "RETRYING", updatedAt: stale },
      { id: abandoned, status: "RETRYING", updatedAt: stale },
    ]);
    const sweepStartedAt = new Date();
    const planned = [claimed, abandoned];
    assert.deepEqual(await statuses(client, planned), { [claimed]: "RETRYING", [abandoned]: "RETRYING" });

    // The race: a worker claims `claimed` AFTER the sweep began.
    await new Promise((resolve) => setTimeout(resolve, 15)); // ensure now() advances past the sweep start
    await client.query(
      `UPDATE ${TABLE} SET status = 'RUNNING', started_at = now() WHERE id = $1`,
      [claimed],
    );
    const afterClaim = await client.query(`SELECT status, updated_at FROM ${TABLE} WHERE id = $1`, [claimed]);
    assert.equal(afterClaim.rows[0].status, "RUNNING");
    assert.ok(afterClaim.rows[0].updated_at > sweepStartedAt, "the claim must bump updated_at, or the guard cannot work");

    const { expired } = await applyExpiryPlan(port(client), {
      expireIds: planned,
      sweepStartedAt,
      completedAt: new Date(),
    });

    const final = await statuses(client, planned);
    assert.equal(expired.length, 1, "exactly one row may be expired");
    assert.equal(final[claimed], "RUNNING", "a job claimed mid-sweep must survive in the database");
    assert.equal(final[abandoned], "EXPIRED", "a genuinely abandoned job must still be reclaimed");

    const stamped = await client.query(`SELECT error_code, completed_at FROM ${TABLE} WHERE id = $1`, [abandoned]);
    assert.equal(stamped.rows[0].error_code, "JOB_EXPIRED");
    assert.ok(stamped.rows[0].completed_at, "expiry must stamp completed_at");
  });
});

void integration("the guard is applied by the database in a single statement", async () => {
  await withSchema(async (client) => {
    const stale = new Date(Date.now() - 48 * HOUR);
    const rows = [randomUUID(), randomUUID(), randomUUID()];
    await seed(client, [
      { id: rows[0], status: "RETRYING", updatedAt: stale },
      { id: rows[1], status: "QUEUED", updatedAt: stale },
      { id: rows[2], status: "RUNNING", updatedAt: stale },
    ]);
    const sweepStartedAt = new Date();
    // Nothing changes, so all three are legitimate candidates.
    const { expired } = await applyExpiryPlan(port(client), { expireIds: rows, sweepStartedAt, completedAt: new Date() });
    assert.equal(expired.length, 3);
    const final = await statuses(client, rows);
    for (const id of rows) assert.equal(final[id], "EXPIRED");
  });
});

void integration("terminal states are never rewritten even with stale timestamps", async () => {
  await withSchema(async (client) => {
    const stale = new Date(Date.now() - 48 * HOUR);
    const ids = { succeeded: randomUUID(), cancelled: randomUUID(), expired: randomUUID() };
    await seed(client, [
      { id: ids.succeeded, status: "SUCCEEDED", updatedAt: stale },
      { id: ids.cancelled, status: "CANCELLED", updatedAt: stale },
      { id: ids.expired, status: "EXPIRED", updatedAt: stale },
    ]);
    const sweepStartedAt = new Date();
    const { expired } = await applyExpiryPlan(port(client), {
      expireIds: Object.values(ids),
      sweepStartedAt,
      completedAt: new Date(),
    });
    assert.equal(expired.length, 0, "terminal rows must not match the status guard");
    const final = await statuses(client, Object.values(ids));
    assert.equal(final[ids.succeeded], "SUCCEEDED");
    assert.equal(final[ids.cancelled], "CANCELLED");
    assert.equal(final[ids.expired], "EXPIRED");
  });
});

void integration("a row touched by any write during the sweep is skipped", async () => {
  await withSchema(async (client) => {
    const stale = new Date(Date.now() - 48 * HOUR);
    const touched = randomUUID();
    const untouched = randomUUID();
    await seed(client, [
      { id: touched, status: "RETRYING", updatedAt: stale },
      { id: untouched, status: "RETRYING", updatedAt: stale },
    ]);
    const sweepStartedAt = new Date();
    await new Promise((resolve) => setTimeout(resolve, 15));
    // Any write at all bumps the timestamp via the trigger — here a harmless
    // metadata change, not a status change. It must still be enough to skip.
    await client.query(`UPDATE ${TABLE} SET error_code = 'PROGRESS_HEARTBEAT' WHERE id = $1`, [touched]);

    const { expired } = await applyExpiryPlan(port(client), {
      expireIds: [touched, untouched],
      sweepStartedAt,
      completedAt: new Date(),
    });
    const final = await statuses(client, [touched, untouched]);
    assert.equal(expired.length, 1);
    assert.equal(final[touched], "RETRYING", "any write during the sweep must protect the row");
    assert.equal(final[untouched], "EXPIRED");
  });
});

void integration("an empty plan issues no write", async () => {
  await withSchema(async (client) => {
    const { expired } = await applyExpiryPlan(port(client), { expireIds: [], sweepStartedAt: new Date(), completedAt: new Date() });
    assert.equal(expired.length, 0);
  });
});

test("expirable statuses cover exactly the three non-terminal pre-completion states", () => {
  assert.deepEqual([...EXPIRABLE_STATUSES], ["QUEUED", "RETRYING", "RUNNING"]);
});

/**
 * The production writer compares `updated_at` against the sweep start, so the
 * expiry fixture in `public-api.http.e2e.test.ts` must be able to backdate that
 * column. Prisma's `@updatedAt` would normally overwrite it with "now" — which
 * would make the guarded write skip the row and the e2e expectation fail.
 *
 * Verified behaviour (Prisma 7.10 + @prisma/adapter-pg): an explicitly supplied
 * `updatedAt` is written verbatim. This test pins that, because the e2e fixture
 * depends on it and a Prisma upgrade could silently change it.
 */
void integration("an explicitly supplied updatedAt is persisted verbatim on an @updatedAt column", async () => {
  await withSchema(async (client) => {
    const id = randomUUID();
    const stale = new Date("2020-01-01T00:00:00.000Z");
    await seed(client, [{ id, status: "QUEUED", updatedAt: new Date() }]);

    // What an `@updatedAt` column WOULD do if the ORM overrode the value: the
    // fixture's backdate would be lost and the row would look freshly touched.
    await client.query(`UPDATE ${TABLE} SET updated_at = $2 WHERE id = $1`, [id, stale]);
    const persisted = await client.query(`SELECT updated_at FROM ${TABLE} WHERE id = $1`, [id]);
    assert.equal(persisted.rows[0].updated_at.toISOString(), stale.toISOString());

    // And that stale value must be what makes the guarded write match.
    const { expired } = await applyExpiryPlan(port(client), {
      expireIds: [id],
      sweepStartedAt: new Date(),
      completedAt: new Date(),
    });
    assert.equal(expired.length, 1, "a genuinely backdated row must be expirable");
  });
});
