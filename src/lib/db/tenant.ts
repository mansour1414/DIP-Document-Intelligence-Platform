import type { Prisma, PrismaClient } from "@prisma/client";
import { db } from "./index";

export type AuthenticatedPrincipal = Readonly<{ userId: string }>;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export async function withTenant<T>(
  principal: AuthenticatedPrincipal,
  operation: (transaction: Prisma.TransactionClient) => Promise<T>,
  client: PrismaClient = db,
): Promise<T> {
  if (!UUID_PATTERN.test(principal.userId)) {
    throw new Error("Authenticated principal has an invalid user id");
  }

  return client.$transaction(async (transaction) => {
    // The third argument makes set_config transaction-local, equivalent to SET LOCAL.
    await transaction.$queryRaw`
      SELECT set_config('app.current_user_id', ${principal.userId}, true)
    `;
    return operation(transaction);
  });
}
