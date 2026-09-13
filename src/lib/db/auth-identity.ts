import type { Prisma, PrismaClient } from "@prisma/client";
import { normalizeAuthEmail } from "@/lib/auth/identity";
import { db } from "./index";

export async function withAuthIdentity<T>(
  email: string,
  operation: (transaction: Prisma.TransactionClient, normalizedEmail: string) => Promise<T>,
  client: PrismaClient = db,
): Promise<T> {
  const normalizedEmail = normalizeAuthEmail(email);
  return client.$transaction(async (transaction) => {
    await transaction.$queryRaw`SELECT set_config('app.auth_email', ${normalizedEmail}, true)`;
    return operation(transaction, normalizedEmail);
  });
}
