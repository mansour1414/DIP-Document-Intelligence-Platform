import type { Prisma } from "@prisma/client";

/** Acquire a transaction-scoped PostgreSQL lock without exposing its void result to Prisma. */
export async function acquireTransactionAdvisoryLock(transaction: Prisma.TransactionClient, key: string) {
  const rows = await transaction.$queryRaw<Array<{ acquired: number }>>`
    SELECT 1::integer AS acquired
    FROM pg_advisory_xact_lock(hashtextextended(${key}, 0))
  `;
  if (rows[0]?.acquired !== 1) throw new Error("ADVISORY_LOCK_NOT_ACQUIRED");
}
