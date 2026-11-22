import type { Prisma, PrismaClient } from "@prisma/client";
import { db } from "@/lib/db";
import {
  assertValidTenantExecutionScope,
  type ApiTenantPrincipal,
  type AuthenticatedPrincipal,
  type OrganizationPrincipal,
  type TenantExecutionScope,
  withApiTenant,
  withOrganization,
  withTenant,
} from "@/lib/db/tenant";

export type StorageObjectCoordinatesInput = Readonly<{
  provider?: string;
  bucket: string;
  objectKey: string;
  region?: string | null;
  size: bigint | number;
  checksum?: string | null;
}>;

export type MutableStorageObjectMetadata = Readonly<{
  region?: string | null;
  checksum?: string | null;
  deletedAt?: Date | null;
}>;

export const storageObjectMetadataSelect = {
  id: true,
  ownerUserId: true,
  organizationId: true,
  apiClientId: true,
  provider: true,
  bucket: true,
  objectKey: true,
  region: true,
  size: true,
  checksum: true,
  createdAt: true,
  deletedAt: true,
} as const;

export type FileStorageAccessCandidate = Readonly<{
  storageKey: string;
  storageObjectId?: string | null;
  document: Readonly<{
    userId: string;
    organizationId?: string | null;
    status?: string | null;
  }> | null;
  storageObject?: Readonly<{
    ownerUserId?: string | null;
    organizationId?: string | null;
    apiClientId?: string | null;
    deletedAt?: Date | null;
  }> | null;
}>;

export function isAuthorizedFileStorageAccess(
  file: FileStorageAccessCandidate | null | undefined,
  principal: TenantExecutionScope,
): boolean {
  if (!file || !file.storageKey || file.storageKey.startsWith("ephemeral/")) {
    return false;
  }

  const scope = assertValidTenantExecutionScope(principal);
  if ("document" in file) {
    const doc = file.document;
    if (!doc) {
      return false;
    }
    if (doc.userId !== scope.userId) {
      return false;
    }
    if ((doc.organizationId ?? null) !== scope.organizationId) {
      return false;
    }
    if ((doc.status ?? "ACTIVE") !== "ACTIVE") {
      return false;
    }
  }

  if ((file.storageObjectId ?? null) !== null) {
    const so = file.storageObject;
    if (!so) {
      return false;
    }
    if (so.deletedAt !== null && so.deletedAt !== undefined) {
      return false;
    }
    if (so.ownerUserId !== scope.userId) {
      return false;
    }
    if ((so.organizationId ?? null) !== scope.organizationId) {
      return false;
    }
    if ((so.apiClientId ?? null) !== scope.apiClientId) {
      return false;
    }
  }

  return true;
}

export function buildStorageObjectConnectOrCreate(
  principal: TenantExecutionScope,
  object: StorageObjectCoordinatesInput,
): Prisma.StorageObjectCreateNestedOneWithoutFilesInput {
  const scope = assertValidTenantExecutionScope(principal);
  const provider = (object.provider ?? "s3").trim();
  const bucket = object.bucket.trim();
  const objectKey = object.objectKey.trim();

  if (!provider || !bucket || !objectKey) {
    throw new Error("StorageObject requires non-empty provider, bucket, and objectKey");
  }

  return {
    connectOrCreate: {
      where: {
        provider_bucket_objectKey: {
          provider,
          bucket,
          objectKey,
        },
      },
      create: {
        ownerUserId: scope.userId,
        organizationId: scope.organizationId,
        apiClientId: scope.apiClientId,
        provider,
        bucket,
        objectKey,
        region: object.region ?? undefined,
        size: typeof object.size === "bigint" ? object.size : BigInt(object.size),
        checksum: object.checksum ?? undefined,
      },
    },
  };
}

function sanitizeMutableMetadata(patch: MutableStorageObjectMetadata): Prisma.StorageObjectUpdateManyMutationInput {
  const data: Prisma.StorageObjectUpdateManyMutationInput = {};
  if ("region" in patch) data.region = patch.region;
  if ("checksum" in patch) data.checksum = patch.checksum;
  if ("deletedAt" in patch) data.deletedAt = patch.deletedAt;
  return data;
}

export function findStorageObjectForUser(
  principal: AuthenticatedPrincipal,
  storageObjectId: string,
  client: PrismaClient = db,
) {
  return withTenant(
    principal,
    (tx) =>
      tx.storageObject.findFirst({
        where: {
          id: storageObjectId,
          ownerUserId: principal.userId,
          organizationId: null,
          apiClientId: null,
          deletedAt: null,
        },
        select: storageObjectMetadataSelect,
      }),
    client,
  );
}

export function findStorageObjectForOrganization(
  principal: OrganizationPrincipal,
  storageObjectId: string,
  client: PrismaClient = db,
) {
  return withOrganization(
    principal,
    (tx) =>
      tx.storageObject.findFirst({
        where: {
          id: storageObjectId,
          organizationId: principal.organizationId,
          apiClientId: null,
          deletedAt: null,
        },
        select: storageObjectMetadataSelect,
      }),
    client,
  );
}

export function findStorageObjectForApiClient(
  principal: ApiTenantPrincipal,
  storageObjectId: string,
  client: PrismaClient = db,
) {
  return withApiTenant(
    principal,
    (tx) =>
      tx.storageObject.findFirst({
        where: {
          id: storageObjectId,
          organizationId: principal.organizationId,
          apiClientId: principal.apiClientId,
          deletedAt: null,
        },
        select: storageObjectMetadataSelect,
      }),
    client,
  );
}

export function updateStorageObjectMetadataForUser(
  principal: AuthenticatedPrincipal,
  storageObjectId: string,
  patch: MutableStorageObjectMetadata,
  client: PrismaClient = db,
) {
  const data = sanitizeMutableMetadata(patch);
  return withTenant(
    principal,
    async (tx) => {
      const updated = await tx.storageObject.updateMany({
        where: {
          id: storageObjectId,
          ownerUserId: principal.userId,
          organizationId: null,
          apiClientId: null,
        },
        data,
      });
      return updated.count;
    },
    client,
  );
}

export function updateStorageObjectMetadataForOrganization(
  principal: OrganizationPrincipal,
  storageObjectId: string,
  patch: MutableStorageObjectMetadata,
  client: PrismaClient = db,
) {
  const data = sanitizeMutableMetadata(patch);
  return withOrganization(
    principal,
    async (tx) => {
      const updated = await tx.storageObject.updateMany({
        where: {
          id: storageObjectId,
          organizationId: principal.organizationId,
          apiClientId: null,
        },
        data,
      });
      return updated.count;
    },
    client,
  );
}

export function updateStorageObjectMetadataForApiClient(
  principal: ApiTenantPrincipal,
  storageObjectId: string,
  patch: MutableStorageObjectMetadata,
  client: PrismaClient = db,
) {
  const data = sanitizeMutableMetadata(patch);
  return withApiTenant(
    principal,
    async (tx) => {
      const updated = await tx.storageObject.updateMany({
        where: {
          id: storageObjectId,
          organizationId: principal.organizationId,
          apiClientId: principal.apiClientId,
        },
        data,
      });
      return updated.count;
    },
    client,
  );
}
