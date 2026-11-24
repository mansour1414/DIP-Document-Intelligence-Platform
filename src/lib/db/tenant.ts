import type { Prisma, PrismaClient } from "@prisma/client";
import { db } from "./index";

/**
 * The default Prisma client used by the tenant-scoped helpers.
 *
 * Every production call site relies on the default, so the *ordering* of database
 * effects relative to screening was previously untestable in-process — which is why
 * the earlier orchestration evidence could only read source text. `withTenantScope`
 * already accepted a `client` argument; making the default substitutable lets a test
 * observe real calls without changing a single call site.
 *
 * Application code never writes this. The only writer is
 * `setTenantClientForTests`, and passing `undefined` restores the real client.
 */
let defaultTenantClient: PrismaClient = db;

/** Replace the default tenant client for a test. `undefined` restores the real one. */
export function setTenantClientForTests(client?: PrismaClient) { defaultTenantClient = client ?? db; }

export type AuthenticatedPrincipal = Readonly<{ userId: string }>;
export type OrganizationPrincipal = Readonly<{ userId: string; organizationId: string }>;
export type ApiTenantPrincipal = Readonly<{ organizationId: string; apiClientId: string }>;
export type TenantExecutionScope = Readonly<{
  userId: string;
  organizationId?: string | null;
  apiClientId?: string | null;
}>;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function assertValidTenantExecutionScope(principal: TenantExecutionScope): {
  userId: string;
  organizationId: string | null;
  apiClientId: string | null;
} {
  if (!UUID_PATTERN.test(principal.userId)) {
    throw new Error("Authenticated principal has an invalid user id");
  }

  const organizationId = principal.organizationId ?? null;
  const apiClientId = principal.apiClientId ?? null;

  if (organizationId !== null && !UUID_PATTERN.test(organizationId)) {
    throw new Error("Invalid organization principal");
  }
  if (apiClientId !== null && !UUID_PATTERN.test(apiClientId)) {
    throw new Error("Invalid API principal");
  }
  if (apiClientId !== null && organizationId === null) {
    throw new Error("API client principal requires an organization id");
  }

  return { userId: principal.userId, organizationId, apiClientId };
}

export async function withTenant<T>(
  principal: AuthenticatedPrincipal,
  operation: (transaction: Prisma.TransactionClient) => Promise<T>,
  client: PrismaClient = defaultTenantClient,
): Promise<T> {
  if (!UUID_PATTERN.test(principal.userId)) {
    throw new Error("Authenticated principal has an invalid user id");
  }

  return client.$transaction(async (transaction) => {
    // The third argument makes set_config transaction-local, equivalent to SET LOCAL.
    await transaction.$queryRaw`
      SELECT set_config('app.current_user_id', ${principal.userId}, true),
             set_config('app.current_organization_id', '', true),
             set_config('app.current_api_client_id', '', true)
    `;
    return operation(transaction);
  });
}

export async function withOrganization<T>(
  principal: OrganizationPrincipal,
  operation: (transaction: Prisma.TransactionClient) => Promise<T>,
  client: PrismaClient = defaultTenantClient,
): Promise<T> {
  if (!UUID_PATTERN.test(principal.userId) || !UUID_PATTERN.test(principal.organizationId)) throw new Error("Invalid organization principal");
  return client.$transaction(async (transaction) => {
    await transaction.$queryRaw`
      SELECT set_config('app.current_user_id', ${principal.userId}, true),
             set_config('app.current_organization_id', ${principal.organizationId}, true),
             set_config('app.current_api_client_id', '', true)
    `;
    return operation(transaction);
  });
}

export async function withApiTenant<T>(
  principal: ApiTenantPrincipal,
  operation: (transaction: Prisma.TransactionClient) => Promise<T>,
  client: PrismaClient = defaultTenantClient,
): Promise<T> {
  if (!UUID_PATTERN.test(principal.organizationId) || !UUID_PATTERN.test(principal.apiClientId)) throw new Error("Invalid API principal");
  return client.$transaction(async (transaction) => {
    await transaction.$queryRaw`
      SELECT set_config('app.current_user_id', '', true),
             set_config('app.current_organization_id', ${principal.organizationId}, true),
             set_config('app.current_api_client_id', ${principal.apiClientId}, true)
    `;
    return operation(transaction);
  });
}

export async function withTenantScope<T>(
  principal: TenantExecutionScope,
  operation: (transaction: Prisma.TransactionClient) => Promise<T>,
  client: PrismaClient = defaultTenantClient,
): Promise<T> {
  const scope = assertValidTenantExecutionScope(principal);
  return client.$transaction(async (transaction) => {
    await transaction.$queryRaw`
      SELECT set_config('app.current_user_id', ${scope.userId}, true),
             set_config('app.current_organization_id', ${scope.organizationId ?? ""}, true),
             set_config('app.current_api_client_id', ${scope.apiClientId ?? ""}, true)
    `;
    return operation(transaction);
  });
}
