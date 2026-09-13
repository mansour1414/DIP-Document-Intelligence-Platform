import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "@prisma/client";
import pg from "pg";
import { withAuthIdentity } from "../src/lib/db/auth-identity";
import { grantSignupCreditsInTransaction } from "../src/lib/billing/credits";

const { Client } = pg;
const integration = process.env.DIP_RLS_TEST_DATABASE_URL && process.env.DIP_RLS_TEST_OWNER_URL ? test : test.skip;

integration("signup user and credit grant roll back atomically", async () => {
  const runtime = new PrismaClient({ adapter: new PrismaPg({ connectionString: process.env.DIP_RLS_TEST_DATABASE_URL! }) });
  const owner = new Client({ connectionString: process.env.DIP_RLS_TEST_OWNER_URL });
  const email = `auth-rollback-${randomUUID()}@example.invalid`;
  await owner.connect();
  try {
    await assert.rejects(
      () => withAuthIdentity(email, async (tx, normalizedEmail) => {
        const user = await tx.user.create({ data: { email: normalizedEmail, passwordHash: "test-only" }, select: { id: true } });
        await tx.$queryRaw`SELECT set_config('app.current_user_id', ${user.id}, true)`;
        await grantSignupCreditsInTransaction(tx, user.id);
        throw new Error("forced rollback after credit grant");
      }, runtime),
      /forced rollback/,
    );
    assert.equal(Number((await owner.query(`SELECT count(*) FROM users WHERE email=$1`, [email])).rows[0].count), 0);
    assert.equal(Number((await owner.query(`SELECT count(*) FROM credit_ledger WHERE user_id IN (SELECT id FROM users WHERE email=$1)`, [email])).rows[0].count), 0);
  } finally {
    await runtime.$disconnect();
    await owner.end();
  }
});
