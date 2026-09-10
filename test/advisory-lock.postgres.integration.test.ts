import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

const integration = process.env.CI && process.env.DATABASE_URL ? test : test.skip;

integration("real PostgreSQL advisory locks serialize usage, credit and AI idempotency", { timeout: 30_000 }, async () => {
  const { db } = await import("../src/lib/db/index");
  const { enforceJobCreation } = await import("../src/lib/usage/enforcement");
  const { recordAiUsageOnce } = await import("../src/lib/ai/gateway/usage");
  const userId = randomUUID(); const jobId = randomUUID(); const idempotencyKey = `advisory-${randomUUID()}`;
  await db.user.create({ data: { id: userId, email: `advisory-${userId}@example.invalid`, creditLedger: { create: { type: "BONUS", amount: 100, balance: 100, idempotencyKey: "seed", reason: "PROMOTIONAL_GRANT" } } } });

  const attempts = await Promise.all(Array.from({ length: 4 }, () => enforceJobCreation({ userId, toolId: "merge-pdf", idempotencyKey, files: [{ size: 1 }, { size: 1 }] })));
  assert.equal(attempts.length, 4);
  assert.equal(await db.usageEvent.count({ where: { userId, kind: "job.created", reference: idempotencyKey } }), 1);
  assert.equal(await db.creditLedger.count({ where: { userId, idempotencyKey: `job:merge-pdf:${idempotencyKey}` } }), 1);

  const context = { userId, jobId, toolId: "summarize-pdf" as const, correlationId: randomUUID() };
  const response = { provider: "integration", model: "fixture", text: "ok", inputTokens: 10, outputTokens: 5, latencyMs: 1 };
  const accounting = await Promise.all(Array.from({ length: 4 }, () => recordAiUsageOnce(context, response)));
  assert.equal(accounting.filter((entry) => !entry.reused).length, 1);
  assert.equal(await db.aiUsage.count({ where: { userId, jobId } }), 1);
  await db.$disconnect();
});
