import type { Prisma, PrismaClient } from "@prisma/client";
import { db } from "./index";

export type AuthenticatedPrincipal = Readonly<{ userId: string }>;
export type OrganizationPrincipal = Readonly<{ userId: string; organizationId: string }>;
export type ApiTenantPrincipal = Readonly<{ organizationId: string; apiClientId: string }>;

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

export async function withOrganization<T>(
  principal: OrganizationPrincipal,
  operation: (transaction: Prisma.TransactionClient) => Promise<T>,
  client: PrismaClient = db,
): Promise<T> {
  if (!UUID_PATTERN.test(principal.userId) || !UUID_PATTERN.test(principal.organizationId)) throw new Error("Invalid organization principal");
  return client.$transaction(async (transaction) => {
    await transaction.$queryRaw`SELECT set_config('app.current_user_id', ${principal.userId}, true), set_config('app.current_organization_id', ${principal.organizationId}, true)`;
    return operation(transaction);
  });
}

export async function withApiTenant<T>(
  principal: ApiTenantPrincipal,
  operation: (transaction: Prisma.TransactionClient) => Promise<T>,
  client: PrismaClient = db,
): Promise<T> {
  if (!UUID_PATTERN.test(principal.organizationId) || !UUID_PATTERN.test(principal.apiClientId)) throw new Error("Invalid API principal");
  return client.$transaction(async (transaction) => {
    await transaction.$queryRaw`SELECT set_config('app.current_organization_id', ${principal.organizationId}, true), set_config('app.current_api_client_id', ${principal.apiClientId}, true)`;
    return operation(transaction);
  });
}
