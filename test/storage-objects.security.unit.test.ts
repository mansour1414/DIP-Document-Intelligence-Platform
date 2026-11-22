import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { PrismaPg } from "@prisma/adapter-pg";
import { Prisma, PrismaClient as RuntimePrismaClient, type PrismaClient } from "@prisma/client";
import { PDFDocument } from "pdf-lib";
import pg from "pg";
import type { ApiPrincipal } from "@/lib/api-platform/auth";
import {
  assertValidTenantExecutionScope,
  withApiTenant,
  withOrganization,
  withTenant,
  withTenantScope,
} from "@/lib/db/tenant";
import { findOutputFileForUser } from "@/lib/jobs/access";
import { processDocumentJob } from "@/lib/jobs/document-pipeline";
import type { MalwareScanner } from "@/lib/malware";
import { downloadPublicJobResult, getPublicJobResult } from "@/lib/public-api/jobs";
import { runRetentionCleanup } from "@/lib/retention/service";
import type { ObjectStorage, StoredObject } from "@/lib/storage";
import {
  buildStorageObjectConnectOrCreate,
  findStorageObjectForApiClient,
  findStorageObjectForOrganization,
  findStorageObjectForUser,
  isAuthorizedFileStorageAccess,
  updateStorageObjectMetadataForApiClient,
  updateStorageObjectMetadataForOrganization,
  updateStorageObjectMetadataForUser,
} from "@/lib/storage/metadata";
import {
  evaluateRlsTestCounts,
  REQUIRED_RLS_TEST_FILES,
  validateIsolatedRlsGateEnv,
} from "../scripts/run-rls-security-gate.mjs";

/**
 * NOTE ON EVIDENCE BOUNDARIES (Phase 4):
 * This suite exercises real application helpers, orchestrator/worker pipelines,
 * download/result paths, and a deterministic in-memory model of the N1-A SQL
 * constraints, triggers, grants, and RLS/FORCE RLS predicates.
 * It does NOT claim real PostgreSQL 18 kernel RLS execution; real PostgreSQL
 * verification lives in `test/storage-objects.rls.integration.test.mjs`.
 */

type Role = "dip_app" | "dip_retention" | "table_owner";

type GucState = {
  userId: string;
  organizationId: string;
  apiClientId: string;
};

type SimStorageObject = {
  id: string;
  ownerUserId: string | null;
  organizationId: string | null;
  apiClientId: string | null;
  provider: string;
  bucket: string;
  objectKey: string;
  region: string | null;
  size: bigint;
  checksum: string | null;
  createdAt: Date;
  deletedAt: Date | null;
};

type SimDocument = {
  id: string;
  userId: string;
  organizationId: string | null;
  title: string;
  status: "ACTIVE" | "ARCHIVED" | "DELETED";
};

type SimFile = {
  id: string;
  documentId: string;
  storageObjectId: string | null;
  storageKey: string;
  originalName: string;
  mimeType: string;
  size: bigint;
  checksum: string | null;
  pageCount: number | null;
  createdAt: Date;
};

type SimJob = {
  id: string;
  toolId: string;
  requesterId: string | null;
  organizationId: string | null;
  apiClientId: string | null;
  status: string;
  params: unknown;
  result: unknown;
  outputFileId: string | null;
  correlationId: string | null;
  startedAt: Date | null;
  completedAt: Date | null;
  errorCode: string | null;
};

class SimulatedTenantDatabase {
  readonly users = new Set<string>();
  readonly organizations = new Map<string, { status: "ACTIVE" | "SUSPENDED" }>();
  readonly memberships = new Set<string>(); // `${orgId}:${userId}`
  readonly apiClients = new Map<string, { organizationId: string; createdByUserId: string; status: "ACTIVE" | "DISABLED" }>();
  storageObjects = new Map<string, SimStorageObject>();
  documents = new Map<string, SimDocument>();
  files = new Map<string, SimFile>();
  fileVersions: Array<{ id: string; fileId: string; ownerId: string; version: number; storageKey: string }> = [];
  jobs = new Map<string, SimJob>();
  jobSteps = new Map<string, { id: string; jobId: string; name: string; status: string }>();
  toolExecutions: Array<{ id: string; jobId: string; toolId: string }> = [];

  forceRls = true;
  private txQueue: Promise<void> = Promise.resolve();

  isOrgMember(organizationId: string | null, userId: string | null): boolean {
    if (!organizationId || !userId) return false;
    const org = this.organizations.get(organizationId);
    return Boolean(org && org.status === "ACTIVE" && this.memberships.has(`${organizationId}:${userId}`));
  }

  apiClientMatchesTenant(
    organizationId: string | null,
    apiClientId: string | null,
    userId: string | null,
    requireActive: boolean,
  ): boolean {
    if (!organizationId || !apiClientId || !userId) return false;
    const client = this.apiClients.get(apiClientId);
    const org = this.organizations.get(organizationId);
    if (!client || !org) return false;
    if (client.organizationId !== organizationId || client.createdByUserId !== userId) return false;
    if (requireActive && (client.status !== "ACTIVE" || org.status !== "ACTIVE")) return false;
    return true;
  }

  canSelectStorageObject(role: Role, guc: GucState, row: SimStorageObject): boolean {
    if (!this.forceRls && role === "table_owner") return true;
    if (role === "dip_retention") return true;
    const u = guc.userId || null;
    const o = guc.organizationId || null;
    const c = guc.apiClientId || null;

    const userPolicy =
      row.ownerUserId !== null &&
      row.organizationId === null &&
      row.apiClientId === null &&
      u !== null &&
      row.ownerUserId === u &&
      o === null &&
      c === null;

    const orgMemberPolicy =
      row.ownerUserId !== null &&
      row.organizationId !== null &&
      o !== null &&
      row.organizationId === o &&
      this.isOrgMember(row.organizationId, u) &&
      row.apiClientId === c;

    const apiClientPolicy =
      row.ownerUserId !== null &&
      row.organizationId !== null &&
      row.apiClientId !== null &&
      u === null &&
      o !== null &&
      c !== null &&
      row.organizationId === o &&
      row.apiClientId === c;

    return userPolicy || orgMemberPolicy || apiClientPolicy;
  }

  canInsertStorageObject(role: Role, guc: GucState, row: SimStorageObject): boolean {
    if (role === "dip_retention") throw Object.assign(new Error("permission denied for table storage_objects"), { code: "42501" });
    if (!this.forceRls && role === "table_owner") return true;

    const u = guc.userId || null;
    const o = guc.organizationId || null;
    const c = guc.apiClientId || null;

    const userPolicy =
      row.ownerUserId !== null &&
      row.organizationId === null &&
      row.apiClientId === null &&
      u !== null &&
      row.ownerUserId === u &&
      o === null &&
      c === null;

    const orgMemberPolicy =
      row.ownerUserId !== null &&
      row.organizationId !== null &&
      u !== null &&
      o !== null &&
      row.ownerUserId === u &&
      row.organizationId === o &&
      this.isOrgMember(row.organizationId, u) &&
      row.apiClientId === c &&
      (row.apiClientId === null || this.apiClientMatchesTenant(row.organizationId, row.apiClientId, row.ownerUserId, false));

    const apiClientPolicy =
      row.ownerUserId !== null &&
      row.organizationId !== null &&
      row.apiClientId !== null &&
      u === null &&
      o !== null &&
      c !== null &&
      row.organizationId === o &&
      row.apiClientId === c &&
      this.apiClientMatchesTenant(row.organizationId, row.apiClientId, row.ownerUserId, true);

    return userPolicy || orgMemberPolicy || apiClientPolicy;
  }

  canUpdateStorageObject(role: Role, guc: GucState, row: SimStorageObject): boolean {
    if (!this.forceRls && role === "table_owner") return true;
    if (role === "dip_retention") return true;
    return this.canSelectStorageObject(role, guc, row);
  }

  private assertStorageObjectConstraints(row: SimStorageObject) {
    const validNullOrphan = row.ownerUserId === null && row.organizationId === null && row.apiClientId === null;
    const validAttributed = row.ownerUserId !== null && (row.apiClientId === null || row.organizationId !== null);
    if (!validNullOrphan && !validAttributed) {
      throw Object.assign(new Error("STORAGE_OBJECT_SCOPE_CHECK_FAILED"), { code: "23514" });
    }
    if (row.ownerUserId !== null && !this.users.has(row.ownerUserId)) {
      throw Object.assign(new Error("storage_objects_owner_user_id_fkey"), { code: "23503" });
    }
    if (row.organizationId !== null && !this.organizations.has(row.organizationId)) {
      throw Object.assign(new Error("storage_objects_organization_id_fkey"), { code: "23503" });
    }
    if (row.apiClientId !== null) {
      const apiClient = this.apiClients.get(row.apiClientId);
      if (!apiClient || apiClient.organizationId !== row.organizationId) {
        throw Object.assign(new Error("storage_objects_api_client_organization_fkey"), { code: "23503" });
      }
    }
  }

  insertRawStorageObjectAsOwner(row: Partial<SimStorageObject> & Pick<SimStorageObject, "provider" | "bucket" | "objectKey" | "size">) {
    const full: SimStorageObject = {
      id: row.id ?? randomUUID(),
      ownerUserId: row.ownerUserId ?? null,
      organizationId: row.organizationId ?? null,
      apiClientId: row.apiClientId ?? null,
      provider: row.provider,
      bucket: row.bucket,
      objectKey: row.objectKey,
      region: row.region ?? null,
      size: row.size,
      checksum: row.checksum ?? null,
      createdAt: row.createdAt ?? new Date(),
      deletedAt: row.deletedAt ?? null,
    };
    this.assertStorageObjectConstraints(full);
    for (const existing of this.storageObjects.values()) {
      if (existing.provider === full.provider && existing.bucket === full.bucket && existing.objectKey === full.objectKey) {
        throw Object.assign(new Error("duplicate key value violates unique constraint storage_objects_provider_bucket_object_key_key"), { code: "23505" });
      }
    }
    this.storageObjects.set(full.id, full);
    return full;
  }

  clientForRole(role: Role = "dip_app"): PrismaClient {
    return {
      $transaction: async <T>(operation: (tx: unknown) => Promise<T>): Promise<T> => {
        const run = this.txQueue.then(async () => {
          const snapshot = {
            storageObjects: new Map([...this.storageObjects.entries()].map(([k, v]) => [k, { ...v }])),
            documents: new Map([...this.documents.entries()].map(([k, v]) => [k, { ...v }])),
            files: new Map([...this.files.entries()].map(([k, v]) => [k, { ...v }])),
            fileVersions: this.fileVersions.map((v) => ({ ...v })),
            jobs: new Map([...this.jobs.entries()].map(([k, v]) => [k, structuredClone(v)])),
            jobSteps: new Map([...this.jobSteps.entries()].map(([k, v]) => [k, { ...v }])),
            toolExecutions: this.toolExecutions.map((v) => ({ ...v })),
          };
          const guc: GucState = { userId: "", organizationId: "", apiClientId: "" };

          const insertStorageObject = (createData: Record<string, unknown>): SimStorageObject => {
            const candidate: SimStorageObject = {
              id: (createData.id as string | undefined) ?? randomUUID(),
              ownerUserId: (createData.ownerUserId as string | null | undefined) ?? null,
              organizationId: (createData.organizationId as string | null | undefined) ?? null,
              apiClientId: (createData.apiClientId as string | null | undefined) ?? null,
              provider: String(createData.provider),
              bucket: String(createData.bucket),
              objectKey: String(createData.objectKey),
              region: (createData.region as string | null | undefined) ?? null,
              size: BigInt(createData.size as bigint | number),
              checksum: (createData.checksum as string | null | undefined) ?? null,
              createdAt: (createData.createdAt as Date | undefined) ?? new Date(),
              deletedAt: (createData.deletedAt as Date | null | undefined) ?? null,
            };
            this.assertStorageObjectConstraints(candidate);
            if (!this.canInsertStorageObject(role, guc, candidate)) {
              throw Object.assign(new Error("new row violates row-level security policy for table \"storage_objects\""), { code: "42501" });
            }
            for (const existing of this.storageObjects.values()) {
              if (existing.provider === candidate.provider && existing.bucket === candidate.bucket && existing.objectKey === candidate.objectKey) {
                throw Object.assign(new Error("duplicate key value violates unique constraint \"storage_objects_provider_bucket_object_key_key\""), { code: "23505" });
              }
            }
            this.storageObjects.set(candidate.id, candidate);
            return candidate;
          };

          const tx = {
            $queryRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
              const rendered = strings.reduce(
                (acc, part, idx) => acc + part + (idx < values.length ? `'${String(values[idx] ?? "")}'` : ""),
                "",
              );
              for (const match of rendered.matchAll(/set_config\('([^']+)',\s*'([^']*)',\s*true\)/g)) {
                const [, name, val] = match;
                if (name === "app.current_user_id") guc.userId = val;
                if (name === "app.current_organization_id") guc.organizationId = val;
                if (name === "app.current_api_client_id") guc.apiClientId = val;
              }
              return [];
            },
            storageObject: {
              create: async ({ data }: { data: Record<string, unknown> }) => ({ ...insertStorageObject(data) }),
              findMany: async ({ where = {} }: { where?: Record<string, unknown> } = {}) => {
                return [...this.storageObjects.values()].filter((row) => {
                  if (!this.canSelectStorageObject(role, guc, row)) return false;
                  if ("id" in where && row.id !== where.id) return false;
                  if ("ownerUserId" in where && row.ownerUserId !== where.ownerUserId) return false;
                  if ("organizationId" in where && row.organizationId !== where.organizationId) return false;
                  if ("apiClientId" in where && row.apiClientId !== where.apiClientId) return false;
                  if ("deletedAt" in where && row.deletedAt !== where.deletedAt) return false;
                  return true;
                });
              },
              findFirst: async ({ where = {} }: { where?: Record<string, unknown> } = {}) => {
                const rows = await tx.storageObject.findMany({ where });
                return rows[0] ?? null;
              },
              updateMany: async ({ where = {}, data }: { where?: Record<string, unknown>; data: Record<string, unknown> }) => {
                for (const key of Object.keys(data)) {
                  if (role === "dip_retention" && key !== "deletedAt") {
                    throw Object.assign(new Error("permission denied for table storage_objects"), { code: "42501" });
                  }
                  if (role === "dip_app" && !["region", "checksum", "deletedAt"].includes(key)) {
                    throw Object.assign(new Error("permission denied for table storage_objects"), { code: "42501" });
                  }
                }
                let count = 0;
                for (const row of this.storageObjects.values()) {
                  if (!this.canUpdateStorageObject(role, guc, row)) continue;
                  if ("id" in where && row.id !== where.id) continue;
                  if ("ownerUserId" in where && row.ownerUserId !== where.ownerUserId) continue;
                  if ("organizationId" in where && row.organizationId !== where.organizationId) continue;
                  if ("apiClientId" in where && row.apiClientId !== where.apiClientId) continue;

                  const updated: SimStorageObject = { ...row, ...data } as SimStorageObject;
                  if (
                    updated.provider !== row.provider ||
                    updated.bucket !== row.bucket ||
                    updated.objectKey !== row.objectKey
                  ) {
                    throw Object.assign(new Error("STORAGE_OBJECT_COORDINATES_IMMUTABLE"), { code: "23514" });
                  }
                  if (
                    row.ownerUserId !== null &&
                    (updated.ownerUserId !== row.ownerUserId ||
                      updated.organizationId !== row.organizationId ||
                      updated.apiClientId !== row.apiClientId)
                  ) {
                    throw Object.assign(new Error("STORAGE_OBJECT_OWNERSHIP_IMMUTABLE"), { code: "23514" });
                  }
                  this.assertStorageObjectConstraints(updated);
                  if (!this.canUpdateStorageObject(role, guc, updated)) {
                    throw Object.assign(new Error("new row violates row-level security policy"), { code: "42501" });
                  }
                  this.storageObjects.set(row.id, updated);
                  count += 1;
                }
                return { count };
              },
              deleteMany: async () => {
                throw Object.assign(new Error("permission denied for table storage_objects"), { code: "42501" });
              },
            },
            document: {
              create: async ({ data }: { data: { id?: string; userId: string; organizationId?: string | null; title: string; status?: "ACTIVE" | "DELETED" } }) => {
                const u = guc.userId || null;
                const o = guc.organizationId || null;
                const allowed =
                  role === "table_owner" ||
                  (data.organizationId == null && u === data.userId) ||
                  (data.organizationId != null && o === data.organizationId && this.isOrgMember(data.organizationId, u));
                if (!allowed) throw Object.assign(new Error("documents RLS violation"), { code: "42501" });
                const doc: SimDocument = {
                  id: data.id ?? randomUUID(),
                  userId: data.userId,
                  organizationId: data.organizationId ?? null,
                  title: data.title,
                  status: data.status ?? "ACTIVE",
                };
                this.documents.set(doc.id, doc);
                return doc;
              },
            },
            file: {
              create: async ({ data }: { data: Record<string, unknown> }) => {
                const docConnect = data.document as { connect?: { id: string } } | undefined;
                const documentId = (data.documentId as string | undefined) ?? docConnect?.connect?.id;
                if (!documentId) throw new Error("Missing documentId");
                const parentDoc = this.documents.get(documentId);
                if (!parentDoc) throw Object.assign(new Error("FILE_DOCUMENT_NOT_FOUND"), { code: "23503" });

                let storageObjectId = (data.storageObjectId as string | null | undefined) ?? null;
                const nested = data.storageObject as
                  | {
                      connect?: { id: string };
                      connectOrCreate?: {
                        where: { provider_bucket_objectKey: { provider: string; bucket: string; objectKey: string } };
                        create: Record<string, unknown>;
                      };
                    }
                  | undefined;

                if (nested?.connect?.id) {
                  storageObjectId = nested.connect.id;
                } else if (nested?.connectOrCreate) {
                  const coords = nested.connectOrCreate.where.provider_bucket_objectKey;
                  const visibleExisting = [...this.storageObjects.values()].find(
                    (row) =>
                      this.canSelectStorageObject(role, guc, row) &&
                      row.provider === coords.provider &&
                      row.bucket === coords.bucket &&
                      row.objectKey === coords.objectKey,
                  );
                  if (visibleExisting) {
                    storageObjectId = visibleExisting.id;
                  } else {
                    const created = insertStorageObject(nested.connectOrCreate.create);
                    storageObjectId = created.id;
                  }
                }

                const rawStorageKey = String(data.storageKey);

                // Trigger: enforce_file_storage_object_tenant_match
                if (storageObjectId === null) {
                  if (!rawStorageKey.startsWith("ephemeral/") || rawStorageKey.length <= "ephemeral/".length) {
                    throw Object.assign(new Error("FILE_STORAGE_OBJECT_REQUIRED"), { code: "23514" });
                  }
                } else {
                  const obj = this.storageObjects.get(storageObjectId);
                  if (!obj) throw Object.assign(new Error("FILE_STORAGE_OBJECT_NOT_FOUND"), { code: "23503" });
                  if (
                    obj.ownerUserId === null ||
                    obj.ownerUserId !== parentDoc.userId ||
                    obj.organizationId !== parentDoc.organizationId
                  ) {
                    throw Object.assign(new Error("STORAGE_OBJECT_TENANT_MISMATCH"), { code: "42501" });
                  }
                  const ctxApiClientId = guc.apiClientId || null;
                  if (obj.apiClientId !== ctxApiClientId) {
                    throw Object.assign(new Error("STORAGE_OBJECT_API_CLIENT_MISMATCH"), { code: "42501" });
                  }
                  if (obj.deletedAt !== null) {
                    throw Object.assign(new Error("FILE_STORAGE_OBJECT_DELETED"), { code: "23514" });
                  }
                  if (!rawStorageKey.trim() || rawStorageKey.startsWith("ephemeral/") || rawStorageKey !== obj.objectKey) {
                    throw Object.assign(new Error("FILE_STORAGE_KEY_MISMATCH"), { code: "23514" });
                  }
                }

                const file: SimFile = {
                  id: (data.id as string | undefined) ?? randomUUID(),
                  documentId,
                  storageObjectId,
                  storageKey: rawStorageKey,
                  originalName: String(data.originalName),
                  mimeType: String(data.mimeType),
                  size: BigInt(data.size as bigint | number),
                  checksum: (data.checksum as string | null | undefined) ?? null,
                  pageCount: (data.pageCount as number | null | undefined) ?? null,
                  createdAt: data.createdAt instanceof Date ? data.createdAt : new Date(),
                };
                this.files.set(file.id, file);
                return file;
              },
              update: async ({
                where,
                data,
              }: {
                where: { id: string };
                data: Record<string, unknown>;
              }) => {
                if (role === "dip_retention") {
                  throw Object.assign(new Error("permission denied for table files"), { code: "42501" });
                }
                const oldRow = this.files.get(where.id);
                if (!oldRow) {
                  throw new Prisma.PrismaClientKnownRequestError("Record to update not found.", {
                    code: "P2025",
                    clientVersion: "7.0.0",
                  });
                }
                if (role === "dip_app") {
                  const doc = this.documents.get(oldRow.documentId);
                  const u = guc.userId || null;
                  const o = guc.organizationId || null;
                  const docVisible =
                    Boolean(doc) &&
                    ((doc!.organizationId === null && u === doc!.userId) ||
                      (doc!.organizationId !== null && o === doc!.organizationId && this.isOrgMember(doc!.organizationId, u)));
                  if (!docVisible) {
                    throw new Prisma.PrismaClientKnownRequestError("Record to update not found.", {
                      code: "P2025",
                      clientVersion: "7.0.0",
                    });
                  }
                  if (oldRow.storageObjectId === null) {
                    if (!oldRow.storageKey.startsWith("ephemeral/") || oldRow.storageKey.length <= "ephemeral/".length) {
                      throw new Prisma.PrismaClientKnownRequestError("Record to update not found.", {
                        code: "P2025",
                        clientVersion: "7.0.0",
                      });
                    }
                  } else {
                    const so = this.storageObjects.get(oldRow.storageObjectId);
                    if (!so || so.objectKey !== oldRow.storageKey || !this.canSelectStorageObject(role, guc, so)) {
                      throw new Prisma.PrismaClientKnownRequestError("Record to update not found.", {
                        code: "P2025",
                        clientVersion: "7.0.0",
                      });
                    }
                  }
                }

                const nextDocumentId = "documentId" in data ? String(data.documentId) : oldRow.documentId;
                const nextStorageObjectId =
                  "storageObjectId" in data ? ((data.storageObjectId as string | null) ?? null) : oldRow.storageObjectId;
                const nextStorageKey = "storageKey" in data ? String(data.storageKey) : oldRow.storageKey;

                // Trigger: enforce_file_storage_object_tenant_match (BEFORE UPDATE ON "files")
                if (nextStorageObjectId === null) {
                  if (!nextStorageKey.startsWith("ephemeral/") || nextStorageKey.length <= "ephemeral/".length) {
                    throw Object.assign(new Error("FILE_STORAGE_OBJECT_REQUIRED"), { code: "23514" });
                  }
                  if (
                    nextStorageKey !== oldRow.storageKey ||
                    nextDocumentId !== oldRow.documentId ||
                    nextStorageObjectId !== oldRow.storageObjectId
                  ) {
                    throw Object.assign(new Error("FILE_STORAGE_COORDINATES_IMMUTABLE"), { code: "23514" });
                  }
                } else {
                  const parentDoc = this.documents.get(nextDocumentId);
                  if (!parentDoc) throw Object.assign(new Error("FILE_DOCUMENT_NOT_FOUND"), { code: "23503" });
                  const obj = this.storageObjects.get(nextStorageObjectId);
                  if (!obj) throw Object.assign(new Error("FILE_STORAGE_OBJECT_NOT_FOUND"), { code: "23503" });
                  if (
                    obj.ownerUserId === null ||
                    obj.ownerUserId !== parentDoc.userId ||
                    obj.organizationId !== parentDoc.organizationId
                  ) {
                    throw Object.assign(new Error("STORAGE_OBJECT_TENANT_MISMATCH"), { code: "42501" });
                  }
                  if (nextStorageObjectId !== oldRow.storageObjectId) {
                    const ctxApiClientId = guc.apiClientId || null;
                    if (obj.apiClientId !== ctxApiClientId) {
                      throw Object.assign(new Error("STORAGE_OBJECT_API_CLIENT_MISMATCH"), { code: "42501" });
                    }
                  }
                  if (
                    nextStorageKey !== oldRow.storageKey ||
                    nextDocumentId !== oldRow.documentId ||
                    nextStorageObjectId !== oldRow.storageObjectId
                  ) {
                    throw Object.assign(new Error("FILE_STORAGE_COORDINATES_IMMUTABLE"), { code: "23514" });
                  }
                  if (!nextStorageKey.trim() || nextStorageKey.startsWith("ephemeral/") || nextStorageKey !== obj.objectKey) {
                    throw Object.assign(new Error("FILE_STORAGE_KEY_MISMATCH"), { code: "23514" });
                  }
                }

                const updated: SimFile = {
                  ...oldRow,
                  documentId: nextDocumentId,
                  storageObjectId: nextStorageObjectId,
                  storageKey: nextStorageKey,
                  originalName: "originalName" in data ? String(data.originalName) : oldRow.originalName,
                  checksum: "checksum" in data ? ((data.checksum as string | null) ?? null) : oldRow.checksum,
                  pageCount: "pageCount" in data ? ((data.pageCount as number | null) ?? null) : oldRow.pageCount,
                  createdAt: data.createdAt instanceof Date ? data.createdAt : oldRow.createdAt,
                };
                this.files.set(updated.id, updated);
                return updated;
              },
              findMany: async ({
                where = {},
                include,
                select,
              }: {
                where?: Record<string, unknown>;
                include?: { document?: boolean; storageObject?: boolean };
                select?: { document?: unknown; storageObject?: unknown };
              }) => {
                const matchClause = (file: SimFile, doc: SimDocument, clause: Record<string, unknown>): boolean => {
                  if (clause.id && typeof clause.id === "object" && "in" in (clause.id as object)) {
                    if (!((clause.id as { in: string[] }).in).includes(file.id)) return false;
                  } else if (typeof clause.id === "string" && file.id !== clause.id) {
                    return false;
                  }

                  if (clause.storageKey && typeof clause.storageKey === "object") {
                    const sk = clause.storageKey as Record<string, unknown>;
                    if ("in" in sk && !((sk.in as string[]) ?? []).includes(file.storageKey)) return false;
                    if (typeof sk.startsWith === "string" && !file.storageKey.startsWith(sk.startsWith)) return false;
                  }

                  if ("storageObjectId" in clause) {
                    const soFilter = clause.storageObjectId;
                    if (soFilter && typeof soFilter === "object" && "not" in (soFilter as object)) {
                      if (file.storageObjectId === (soFilter as { not: string | null }).not) return false;
                    } else if (file.storageObjectId !== soFilter) {
                      return false;
                    }
                  }

                  if (clause.document && typeof clause.document === "object") {
                    const docFilter = clause.document as Record<string, unknown>;
                    if ("userId" in docFilter && doc.userId !== docFilter.userId) return false;
                    if ("organizationId" in docFilter && doc.organizationId !== docFilter.organizationId) return false;
                    if ("status" in docFilter && doc.status !== docFilter.status) return false;
                  }

                  if (clause.storageObject && typeof clause.storageObject === "object") {
                    if (!file.storageObjectId) return false;
                    const so = this.storageObjects.get(file.storageObjectId);
                    if (!so || !this.canSelectStorageObject(role, guc, so)) return false;
                    const f = clause.storageObject as Record<string, unknown>;
                    if ("ownerUserId" in f && so.ownerUserId !== f.ownerUserId) return false;
                    if ("organizationId" in f && so.organizationId !== f.organizationId) return false;
                    if ("apiClientId" in f && so.apiClientId !== f.apiClientId) return false;
                    if ("deletedAt" in f && so.deletedAt !== f.deletedAt) return false;
                  }

                  if (clause.NOT && typeof clause.NOT === "object") {
                    if (matchClause(file, doc, clause.NOT as Record<string, unknown>)) return false;
                  }

                  if (Array.isArray(clause.AND)) {
                    if (!(clause.AND as Array<Record<string, unknown>>).every((sub) => matchClause(file, doc, sub))) {
                      return false;
                    }
                  }

                  if (Array.isArray(clause.OR)) {
                    if (!(clause.OR as Array<Record<string, unknown>>).some((sub) => matchClause(file, doc, sub))) {
                      return false;
                    }
                  }

                  return true;
                };

                const matches = [...this.files.values()].filter((file) => {
                  const doc = this.documents.get(file.documentId);
                  if (!doc) return false;
                  const u = guc.userId || null;
                  const o = guc.organizationId || null;
                  const docVisible =
                    (doc.organizationId === null && u === doc.userId) ||
                    (doc.organizationId !== null && o === doc.organizationId && this.isOrgMember(doc.organizationId, u));
                  if (!docVisible) return false;
                  // Restrictive files_storage_object_rls_guard TO dip_app
                  if (role === "dip_app") {
                    if (file.storageObjectId === null) {
                      if (!file.storageKey.startsWith("ephemeral/") || file.storageKey.length <= "ephemeral/".length) {
                        return false;
                      }
                    } else {
                      if (file.storageKey.startsWith("ephemeral/")) return false;
                      const so = this.storageObjects.get(file.storageObjectId);
                      if (!so || so.objectKey !== file.storageKey || !this.canSelectStorageObject(role, guc, so)) {
                        return false;
                      }
                    }
                  }
                  return matchClause(file, doc, where);
                });

                return matches.map((file) => ({
                  ...file,
                  ...(include?.document || select?.document ? { document: this.documents.get(file.documentId)! } : {}),
                  ...(include?.storageObject || select?.storageObject
                    ? { storageObject: file.storageObjectId ? this.storageObjects.get(file.storageObjectId) ?? null : null }
                    : {}),
                }));
              },
              findFirst: async (args: {
                where?: Record<string, unknown>;
                include?: { document?: boolean; storageObject?: boolean };
                select?: { document?: unknown; storageObject?: unknown };
              }) => {
                const rows = await tx.file.findMany(args);
                return rows[0] ?? null;
              },
            },
            fileVersion: {
              create: async ({ data }: { data: { fileId: string; ownerId: string; version: number; storageKey: string } }) => {
                const entry = { id: randomUUID(), ...data };
                this.fileVersions.push(entry);
                return entry;
              },
            },
            job: {
              findUnique: async ({ where }: { where: { id: string } }) => {
                const job = this.jobs.get(where.id);
                if (!job) return null;
                const u = guc.userId || null;
                const o = guc.organizationId || null;
                const c = guc.apiClientId || null;
                const visible =
                  (job.organizationId === null && u === job.requesterId) ||
                  (job.organizationId !== null && u === job.requesterId) ||
                  (job.organizationId !== null && o === job.organizationId && this.isOrgMember(job.organizationId, u)) ||
                  (job.organizationId !== null && o === job.organizationId && job.apiClientId !== null && job.apiClientId === c);
                if (!visible) return null;
                const steps = [...this.jobSteps.values()].filter((s) => s.jobId === job.id);
                return { ...structuredClone(job), steps };
              },
              findUniqueOrThrow: async ({ where }: { where: { id: string } }) => {
                const found = await tx.job.findUnique({ where });
                if (!found) throw new Error("JOB_NOT_FOUND");
                return found;
              },
              findFirst: async ({ where }: { where: Record<string, unknown> }) => {
                const job = this.jobs.get(String(where.id));
                if (!job) return null;
                const o = guc.organizationId || null;
                const c = guc.apiClientId || null;
                if ("organizationId" in where && job.organizationId !== where.organizationId) return null;
                if ("apiClientId" in where && job.apiClientId !== where.apiClientId) return null;
                if ("status" in where && job.status !== where.status) return null;
                if (job.organizationId !== o || job.apiClientId !== c) return null;
                return structuredClone(job);
              },
              updateMany: async ({ where, data }: { where: Record<string, unknown>; data: Record<string, unknown> }) => {
                const job = this.jobs.get(String(where.id));
                if (!job) return { count: 0 };
                if ("outputFileId" in where && job.outputFileId !== where.outputFileId) return { count: 0 };
                const notIn = (where.status as { notIn?: string[] } | undefined)?.notIn;
                if (notIn && notIn.includes(job.status)) return { count: 0 };
                Object.assign(job, data);
                return { count: 1 };
              },
            },
            jobStep: {
              updateMany: async ({ where, data }: { where: { id: string; status?: { notIn?: string[] } }; data: Record<string, unknown> }) => {
                const step = this.jobSteps.get(where.id);
                if (!step) return { count: 0 };
                if (where.status?.notIn?.includes(step.status)) return { count: 0 };
                Object.assign(step, data);
                return { count: 1 };
              },
            },
            toolExecution: {
              create: async ({ data }: { data: { jobId: string; toolId: string } }) => {
                const exec = { id: randomUUID(), jobId: data.jobId, toolId: data.toolId };
                this.toolExecutions.push(exec);
                return exec;
              },
            },
          };

          try {
            return await operation(tx);
          } catch (error) {
            this.storageObjects = snapshot.storageObjects;
            this.documents = snapshot.documents;
            this.files = snapshot.files;
            this.fileVersions = snapshot.fileVersions;
            this.jobs = snapshot.jobs;
            this.jobSteps = snapshot.jobSteps;
            this.toolExecutions = snapshot.toolExecutions;
            throw error;
          }
        });
        this.txQueue = run.then(() => undefined, () => undefined);
        return run;
      },
    } as unknown as PrismaClient;
  }
}

function seedMultiTenantWorld() {
  const sim = new SimulatedTenantDatabase();
  const userA = randomUUID();
  const userA2 = randomUUID();
  const userB = randomUUID();
  const orgA = randomUUID();
  const orgB = randomUUID();
  const clientA1 = randomUUID();
  const clientA2 = randomUUID();
  const clientB1 = randomUUID();

  for (const u of [userA, userA2, userB]) sim.users.add(u);
  sim.organizations.set(orgA, { status: "ACTIVE" });
  sim.organizations.set(orgB, { status: "ACTIVE" });
  sim.memberships.add(`${orgA}:${userA}`);
  sim.memberships.add(`${orgA}:${userA2}`);
  sim.memberships.add(`${orgB}:${userB}`);
  sim.apiClients.set(clientA1, { organizationId: orgA, createdByUserId: userA, status: "ACTIVE" });
  sim.apiClients.set(clientA2, { organizationId: orgA, createdByUserId: userA, status: "ACTIVE" });
  sim.apiClients.set(clientB1, { organizationId: orgB, createdByUserId: userB, status: "ACTIVE" });

  return { sim, userA, userA2, userB, orgA, orgB, clientA1, clientA2, clientB1 };
}

test("1-6. Personal user-owned metadata isolation, unauthorized INSERT rejection, and fail-closed tenant context", async () => {
  const { sim, userA, userB } = seedMultiTenantWorld();
  const appClient = sim.clientForRole("dip_app");

  // Missing or malformed tenant contexts fail closed before touching the database.
  await assert.rejects(() => withTenant({ userId: "" }, async () => "unreachable", appClient), /invalid user id/);
  await assert.rejects(() => withTenant({ userId: "not-a-uuid" }, async () => "unreachable", appClient), /invalid user id/);
  await assert.rejects(() => withOrganization({ userId: userA, organizationId: "bad" }, async () => "unreachable", appClient), /Invalid organization principal/);
  await assert.rejects(() => withApiTenant({ organizationId: "bad", apiClientId: randomUUID() }, async () => "unreachable", appClient), /Invalid API principal/);
  assert.throws(
    () => assertValidTenantExecutionScope({ userId: userA, organizationId: null, apiClientId: randomUUID() }),
    /API client principal requires an organization id/,
  );

  // Unscoped DB transaction without GUC sees nothing and cannot insert.
  const objA = sim.insertRawStorageObjectAsOwner({
    ownerUserId: userA,
    provider: "s3",
    bucket: "dip-test",
    objectKey: `input/${userA}/a.pdf`,
    size: BigInt(128),
    checksum: "sha-a",
  });
  const objB = sim.insertRawStorageObjectAsOwner({
    ownerUserId: userB,
    provider: "s3",
    bucket: "dip-test",
    objectKey: `input/${userB}/b.pdf`,
    size: BigInt(256),
    checksum: "sha-b",
  });

  const unscopedRows = await appClient.$transaction((tx) => tx.storageObject.findMany());
  assert.equal(unscopedRows.length, 0, "missing tenant GUC must return zero rows");

  await assert.rejects(
    () =>
      appClient.$transaction((tx) =>
        tx.storageObject.create({
          data: { ownerUserId: userA, provider: "s3", bucket: "dip-test", objectKey: "unscoped.pdf", size: BigInt(10) },
        }),
      ),
    /row-level security/,
  );

  // Tenant A reads its own metadata and cannot read or update Tenant B metadata.
  const readOwn = await findStorageObjectForUser({ userId: userA }, objA.id, appClient);
  assert.equal(readOwn?.id, objA.id);
  assert.equal(readOwn?.ownerUserId, userA);

  const crossRead = await findStorageObjectForUser({ userId: userA }, objB.id, appClient);
  assert.equal(crossRead, null);

  const crossUpdateCount = await updateStorageObjectMetadataForUser(
    { userId: userA },
    objB.id,
    { checksum: "tampered" },
    appClient,
  );
  assert.equal(crossUpdateCount, 0);
  assert.equal(sim.storageObjects.get(objB.id)?.checksum, "sha-b");

  const ownUpdateCount = await updateStorageObjectMetadataForUser(
    { userId: userA },
    objA.id,
    { region: "me-central-1" },
    appClient,
  );
  assert.equal(ownUpdateCount, 1);
  assert.equal(sim.storageObjects.get(objA.id)?.region, "me-central-1");

  // Tenant A cannot INSERT claiming Tenant B as ownerUserId.
  await assert.rejects(
    () =>
      withTenant(
        { userId: userA },
        (tx) =>
          tx.storageObject.create({
            data: {
              ownerUserId: userB,
              provider: "s3",
              bucket: "dip-test",
              objectKey: `forged/${userB}/doc.pdf`,
              size: BigInt(64),
            },
          }),
        appClient,
      ),
    /row-level security/,
  );
});

test("7-8. Organization-owned access, membership revocation enforcement, and API-client boundary isolation", async () => {
  const { sim, userA, userA2, userB, orgA, orgB, clientA1, clientA2, clientB1 } = seedMultiTenantWorld();
  const appClient = sim.clientForRole("dip_app");

  const orgObj = await withOrganization(
    { userId: userA, organizationId: orgA },
    (tx) =>
      tx.storageObject.create({
        data: {
          ownerUserId: userA,
          organizationId: orgA,
          provider: "s3",
          bucket: "dip-test",
          objectKey: `org/${orgA}/shared.pdf`,
          size: BigInt(512),
        },
      }),
    appClient,
  );

  // Fellow active member of Org A can read & update mutable metadata; Org B member cannot.
  assert.equal((await findStorageObjectForOrganization({ userId: userA2, organizationId: orgA }, orgObj.id, appClient))?.id, orgObj.id);
  assert.equal(await findStorageObjectForOrganization({ userId: userB, organizationId: orgB }, orgObj.id, appClient), null);
  assert.equal(await findStorageObjectForOrganization({ userId: userB, organizationId: orgA }, orgObj.id, appClient), null);

  // Personal scope (without org context) cannot read organization-owned StorageObject even for creator userA.
  assert.equal(await findStorageObjectForUser({ userId: userA }, orgObj.id, appClient), null);

  // Revoking userA's membership immediately revokes userA's access even though ownerUserId === userA.
  sim.memberships.delete(`${orgA}:${userA}`);
  assert.equal(await findStorageObjectForOrganization({ userId: userA, organizationId: orgA }, orgObj.id, appClient), null);
  assert.equal(
    await updateStorageObjectMetadataForOrganization({ userId: userA, organizationId: orgA }, orgObj.id, { region: "eu-west-1" }, appClient),
    0,
  );
  sim.memberships.add(`${orgA}:${userA}`);

  // API-client scoped object cannot escape its organization or be read by another API client.
  const apiObjA1 = await withTenantScope(
    { userId: userA, organizationId: orgA, apiClientId: clientA1 },
    (tx) =>
      tx.storageObject.create({
        data: {
          ownerUserId: userA,
          organizationId: orgA,
          apiClientId: clientA1,
          provider: "s3",
          bucket: "dip-test",
          objectKey: `api/${orgA}/${clientA1}/in.pdf`,
          size: BigInt(300),
        },
      }),
    appClient,
  );

  assert.equal((await findStorageObjectForApiClient({ organizationId: orgA, apiClientId: clientA1 }, apiObjA1.id, appClient))?.id, apiObjA1.id);
  assert.equal(await findStorageObjectForApiClient({ organizationId: orgA, apiClientId: clientA2 }, apiObjA1.id, appClient), null);
  assert.equal(await findStorageObjectForApiClient({ organizationId: orgB, apiClientId: clientB1 }, apiObjA1.id, appClient), null);
  assert.equal(
    await updateStorageObjectMetadataForApiClient({ organizationId: orgA, apiClientId: clientA2 }, apiObjA1.id, { checksum: "bad" }, appClient),
    0,
  );

  // Composite FK & RLS prevent binding clientA1 to orgB.
  await assert.rejects(
    () =>
      withApiTenant(
        { organizationId: orgB, apiClientId: clientA1 },
        (tx) =>
          tx.storageObject.create({
            data: {
              ownerUserId: userB,
              organizationId: orgB,
              apiClientId: clientA1,
              provider: "s3",
              bucket: "dip-test",
              objectKey: "escape.pdf",
              size: BigInt(10),
            },
          }),
        appClient,
      ),
    /storage_objects_api_client_organization_fkey|row-level security/,
  );
});

test("9-12. Worker output creation, connectOrCreate isolation, concurrent retries, and object-key collision defense", async () => {
  const { sim, userA, userB, orgA, clientA1 } = seedMultiTenantWorld();
  const appClient = sim.clientForRole("dip_app");

  // 10 & 12: Same-tenant connectOrCreate reuses existing row; cross-tenant object-key collision fails closed!
  const sharedCoords = { provider: "s3", bucket: "dip-test", objectKey: "collision/contested-key.pdf", size: BigInt(99), checksum: "c1" };
  const fileA1 = await withTenant(
    { userId: userA },
    async (tx) => {
      const doc = await tx.document.create({ data: { userId: userA, title: "A1" } });
      return tx.file.create({
        data: {
          document: { connect: { id: doc.id } },
          originalName: "a.pdf",
          mimeType: "application/pdf",
          size: BigInt(99),
          storageKey: sharedCoords.objectKey,
          storageObject: buildStorageObjectConnectOrCreate({ userId: userA }, sharedCoords),
        },
      });
    },
    appClient,
  );
  const fileA2 = await withTenant(
    { userId: userA },
    async (tx) => {
      const doc = await tx.document.create({ data: { userId: userA, title: "A2" } });
      return tx.file.create({
        data: {
          document: { connect: { id: doc.id } },
          originalName: "a-copy.pdf",
          mimeType: "application/pdf",
          size: BigInt(99),
          storageKey: sharedCoords.objectKey,
          storageObject: buildStorageObjectConnectOrCreate({ userId: userA }, sharedCoords),
        },
      });
    },
    appClient,
  );
  assert.equal(fileA1.storageObjectId, fileA2.storageObjectId, "same-tenant connectOrCreate reuses owned StorageObject");

  // Tenant B colliding on the exact same (provider, bucket, objectKey) cannot see Tenant A's row,
  // attempts INSERT, and fails closed on unique constraint without ever linking to Tenant A's row.
  await assert.rejects(
    () =>
      withTenant(
        { userId: userB },
        async (tx) => {
          const docB = await tx.document.create({ data: { userId: userB, title: "B-collide" } });
          return tx.file.create({
            data: {
              document: { connect: { id: docB.id } },
              originalName: "b.pdf",
              mimeType: "application/pdf",
              size: BigInt(99),
              storageKey: sharedCoords.objectKey,
              storageObject: buildStorageObjectConnectOrCreate({ userId: userB }, sharedCoords),
            },
          });
        },
        appClient,
      ),
    /duplicate key value violates unique constraint/,
  );

  // Even if Tenant B supplies Tenant A's storageObjectId directly on File INSERT, cross-table trigger blocks it.
  await assert.rejects(
    () =>
      withTenant(
        { userId: userB },
        async (tx) => {
          const docB = await tx.document.create({ data: { userId: userB, title: "B-hijack" } });
          return tx.file.create({
            data: {
              documentId: docB.id,
              originalName: "hijack.pdf",
              mimeType: "application/pdf",
              size: BigInt(99),
              storageKey: "other-key.pdf",
              storageObjectId: fileA1.storageObjectId,
            },
          });
        },
        appClient,
      ),
    /STORAGE_OBJECT_TENANT_MISMATCH/,
  );

  // 9 & 11: Real `processDocumentJob` execution for an organization + API-client job under concurrent retries!
  const makePdf = async () => {
    const pdf = await PDFDocument.create();
    pdf.addPage().drawText("N1-A worker isolation");
    return new Uint8Array(await pdf.save());
  };
  const objects = new Map<string, Uint8Array>();
  const deletedKeys: string[] = [];
  const storage: ObjectStorage = {
    createUploadKey: ({ filename }) => `input/${filename}`,
    async put({ key, bytes, contentType, checksum }): Promise<StoredObject> {
      objects.set(key, bytes);
      return { key, bucket: "dip-test", contentType, size: bytes.byteLength, checksum };
    },
    async get(key) {
      const found = objects.get(key);
      if (!found) throw new Error("NOT_FOUND");
      return found;
    },
    async head(key) {
      const found = objects.get(key);
      return found ? { key, bucket: "dip-test", contentType: "application/pdf", size: found.byteLength } : undefined;
    },
    async exists(key) {
      return objects.has(key);
    },
    async deleteObject(key) {
      deletedKeys.push(key);
      objects.delete(key);
    },
    async close() {},
  };
  const cleanScanner: MalwareScanner = {
    async scan() {
      return { result: "CLEAN", engine: "stub", engineVersion: "1", signatureVersion: "1", scannedAt: new Date(0) };
    },
  };

  const inputBytesA = await makePdf();
  const inputBytesB = await makePdf();
  const jobId = randomUUID();
  const stepId = randomUUID();

  const seededInputs = await withTenantScope(
    { userId: userA, organizationId: orgA, apiClientId: clientA1 },
    async (tx) => {
      const doc = await tx.document.create({ data: { userId: userA, organizationId: orgA, title: "API merge input" } });
      const ids: string[] = [];
      for (const [idx, raw] of [inputBytesA, inputBytesB].entries()) {
        const key = `input/${userA}/${jobId}-${idx}.pdf`;
        await storage.put({ key, bytes: raw, contentType: "application/pdf" });
        const f = await tx.file.create({
          data: {
            document: { connect: { id: doc.id } },
            originalName: `in-${idx}.pdf`,
            mimeType: "application/pdf",
            size: BigInt(raw.byteLength),
            storageKey: key,
            pageCount: 1,
            storageObject: buildStorageObjectConnectOrCreate(
              { userId: userA, organizationId: orgA, apiClientId: clientA1 },
              { provider: "s3", bucket: "dip-test", objectKey: key, size: raw.byteLength },
            ),
          },
        });
        ids.push(f.id);
      }
      return ids;
    },
    appClient,
  );

  sim.jobs.set(jobId, {
    id: jobId,
    toolId: "merge-pdf",
    requesterId: userA,
    organizationId: orgA,
    apiClientId: clientA1,
    status: "QUEUED",
    params: { inputFileIds: seededInputs, options: {} },
    result: null,
    outputFileId: null,
    correlationId: randomUUID(),
    startedAt: null,
    completedAt: null,
    errorCode: null,
  });
  sim.jobSteps.set(stepId, { id: stepId, jobId, name: "merge-pdf", status: "QUEUED" });

  // Run two concurrent worker attempts (stalled-job recovery race) + an idempotent third retry.
  await Promise.all([
    processDocumentJob(
      { jobId, toolId: "merge-pdf", idempotencyKey: "k1", correlationId: "c1", userId: userA },
      { client: appClient, storage, scanner: cleanScanner, attemptId: "attempt-1" },
    ),
    processDocumentJob(
      { jobId, toolId: "merge-pdf", idempotencyKey: "k1", correlationId: "c1", userId: userA },
      { client: appClient, storage, scanner: cleanScanner, attemptId: "attempt-2" },
    ),
  ]);
  await processDocumentJob(
    { jobId, toolId: "merge-pdf", idempotencyKey: "k1", correlationId: "c1", userId: userA },
    { client: appClient, storage, scanner: cleanScanner, attemptId: "attempt-3" },
  );

  const finalJob = sim.jobs.get(jobId)!;
  assert.equal(finalJob.status, "SUCCEEDED");
  assert.ok(finalJob.outputFileId);
  assert.equal(sim.toolExecutions.filter((e) => e.jobId === jobId).length, 1, "exactly one attempt commits execution metadata");

  const committedOutputFile = sim.files.get(finalJob.outputFileId!)!;
  assert.ok(committedOutputFile.storageObjectId);
  const committedStorageObj = sim.storageObjects.get(committedOutputFile.storageObjectId!)!;
  assert.equal(committedStorageObj.ownerUserId, userA);
  assert.equal(committedStorageObj.organizationId, orgA);
  assert.equal(committedStorageObj.apiClientId, clientA1);
  assert.equal(deletedKeys.length, 1, "superseded concurrent attempt cleans up its unreferenced S3 output");
  assert.equal(objects.has(committedOutputFile.storageKey), true, "winning output object remains intact");
});

test("13-16. Orphan quarantine, download/result compatibility, narrow retention privileges, and FORCE RLS verification", async () => {
  const { sim, userA, userB, orgA, clientA1, clientA2 } = seedMultiTenantWorld();
  const appClient = sim.clientForRole("dip_app");
  const retentionClient = sim.clientForRole("dip_retention");
  const ownerClient = sim.clientForRole("table_owner");

  // 13: Unlinked historical orphan row (NULL ownership) is preserved, invisible to tenants, and unlinkable.
  const orphan = sim.insertRawStorageObjectAsOwner({
    ownerUserId: null,
    organizationId: null,
    apiClientId: null,
    provider: "s3",
    bucket: "dip-test",
    objectKey: "legacy/unlinked-orphan.pdf",
    size: BigInt(4096),
  });
  assert.equal(await findStorageObjectForUser({ userId: userA }, orphan.id, appClient), null);
  await assert.rejects(
    () =>
      withTenant(
        { userId: userA },
        async (tx) => {
          const doc = await tx.document.create({ data: { userId: userA, title: "link-orphan" } });
          return tx.file.create({
            data: {
              documentId: doc.id,
              originalName: "orphan.pdf",
              mimeType: "application/pdf",
              size: BigInt(4096),
              storageKey: orphan.objectKey,
              storageObjectId: orphan.id,
            },
          });
        },
        appClient,
      ),
    /STORAGE_OBJECT_TENANT_MISMATCH/,
  );

  // 14: Personal & Public API download/metadata helpers succeed for authorized owner and fail for other tenants or tombstoned objects.
  const payloadBytes = new TextEncoder().encode("%PDF-1.7 authorized");
  const fakeStorage: ObjectStorage = {
    createUploadKey: () => "",
    put: async () => ({ key: "", bucket: "dip-test", contentType: "application/pdf", size: 0 }),
    get: async () => payloadBytes,
    head: async () => undefined,
    exists: async () => true,
    deleteObject: async () => {},
    close: async () => {},
  };

  const personalFile = await withTenant(
    { userId: userA },
    async (tx) => {
      const doc = await tx.document.create({ data: { userId: userA, title: "personal-out" } });
      return tx.file.create({
        data: {
          document: { connect: { id: doc.id } },
          originalName: "personal.pdf",
          mimeType: "application/pdf",
          size: BigInt(payloadBytes.byteLength),
          storageKey: `output/${userA}/personal.pdf`,
          storageObject: buildStorageObjectConnectOrCreate(
            { userId: userA },
            { provider: "s3", bucket: "dip-test", objectKey: `output/${userA}/personal.pdf`, size: payloadBytes.byteLength },
          ),
        },
      });
    },
    appClient,
  );

  assert.equal((await findOutputFileForUser(userA, personalFile.id, appClient))?.storageKey, `output/${userA}/personal.pdf`);
  assert.equal(await findOutputFileForUser(userB, personalFile.id, appClient), null);

  const apiFile = await withTenantScope(
    { userId: userA, organizationId: orgA, apiClientId: clientA1 },
    async (tx) => {
      const doc = await tx.document.create({ data: { userId: userA, organizationId: orgA, title: "api-out" } });
      return tx.file.create({
        data: {
          document: { connect: { id: doc.id } },
          originalName: "api-result.pdf",
          mimeType: "application/pdf",
          size: BigInt(payloadBytes.byteLength),
          storageKey: `output/${userA}/api-result.pdf`,
          storageObject: buildStorageObjectConnectOrCreate(
            { userId: userA, organizationId: orgA, apiClientId: clientA1 },
            { provider: "s3", bucket: "dip-test", objectKey: `output/${userA}/api-result.pdf`, size: payloadBytes.byteLength },
          ),
        },
      });
    },
    appClient,
  );
  const apiJobId = randomUUID();
  sim.jobs.set(apiJobId, {
    id: apiJobId,
    toolId: "compress-pdf",
    requesterId: userA,
    organizationId: orgA,
    apiClientId: clientA1,
    status: "SUCCEEDED",
    params: {},
    result: { outputFileIds: [apiFile.id] },
    outputFileId: apiFile.id,
    correlationId: null,
    startedAt: new Date(),
    completedAt: new Date(),
    errorCode: null,
  });

  const principalA1: ApiPrincipal = {
    kind: "api_key",
    apiKeyId: randomUUID(),
    apiClientId: clientA1,
    organizationId: orgA,
    executionUserId: userA,
    scopes: ["*"],
  };
  const principalA2: ApiPrincipal = { ...principalA1, apiClientId: clientA2 };

  const apiResult = await getPublicJobResult(principalA1, apiJobId, appClient);
  assert.equal(apiResult.kind, "files");
  assert.equal(apiResult.files.length, 1);

  const downloaded = await downloadPublicJobResult(principalA1, apiJobId, apiFile.id, { client: appClient, storage: fakeStorage });
  assert.equal(downloaded.originalName, "api-result.pdf");
  assert.deepEqual(downloaded.bytes, payloadBytes);

  await assert.rejects(() => getPublicJobResult(principalA2, apiJobId, appClient), /NOT_FOUND|completed result was not found/);
  // Personal `/api/files/[fileId]` helper cannot expose an organization/API-client file!
  assert.equal(await findOutputFileForUser(userA, apiFile.id, appClient), null);

  // 15: Retention role has only SELECT + UPDATE(deletedAt) across tenants & orphans; INSERT/DELETE/other column UPDATE fail!
  const allForRetention = await retentionClient.$transaction((tx) => tx.storageObject.findMany());
  assert.equal(allForRetention.length, 3);

  const deletedNow = new Date();
  const marked = await retentionClient.$transaction((tx) =>
    tx.storageObject.updateMany({ where: { id: personalFile.storageObjectId! }, data: { deletedAt: deletedNow } }),
  );
  assert.equal(marked.count, 1);
  // Once tombstoned by retention, download access cleanly denies the deleted object.
  assert.equal(await findOutputFileForUser(userA, personalFile.id, appClient), null);

  await assert.rejects(
    () => retentionClient.$transaction((tx) => tx.storageObject.updateMany({ where: { id: orphan.id }, data: { checksum: "nope" } })),
    /permission denied/,
  );
  await assert.rejects(
    () =>
      retentionClient.$transaction((tx) =>
        tx.storageObject.create({ data: { ownerUserId: userA, provider: "s3", bucket: "dip-test", objectKey: "ret.pdf", size: BigInt(1) } }),
      ),
    /permission denied/,
  );
  await assert.rejects(
    () => retentionClient.$transaction((tx) => tx.storageObject.deleteMany()),
    /permission denied/,
  );

  // Immutability guard: attributed ownership and object coordinates cannot be mutated even through table_owner.
  await assert.rejects(
    () =>
      withTenant(
        { userId: userA },
        (tx) => tx.storageObject.updateMany({ where: { id: personalFile.storageObjectId! }, data: { objectKey: "moved.pdf" } }),
        ownerClient,
      ),
    /STORAGE_OBJECT_COORDINATES_IMMUTABLE/,
  );
  await assert.rejects(
    () =>
      withTenant(
        { userId: userA },
        (tx) => tx.storageObject.updateMany({ where: { id: personalFile.storageObjectId! }, data: { ownerUserId: userB } }),
        ownerClient,
      ),
    /STORAGE_OBJECT_OWNERSHIP_IMMUTABLE/,
  );

  // 16: FORCE ROW LEVEL SECURITY blocks unscoped table_owner reads when forceRls = true!
  assert.equal((await ownerClient.$transaction((tx) => tx.storageObject.findMany())).length, 0);
  sim.forceRls = false;
  assert.equal((await ownerClient.$transaction((tx) => tx.storageObject.findMany())).length, 3);
  sim.forceRls = true;
});

test("17. BLOCKER 2 regression: API Client B cannot link a File to or read API Client A's StorageObject/File when sharing organization and execution user", async () => {
  const { sim, userA, orgA, clientA1, clientA2 } = seedMultiTenantWorld();
  const appClient = sim.clientForRole("dip_app");

  // clientA1 and clientA2 both belong to orgA and both have createdByUserId === userA.
  const apiFileA1 = await withTenantScope(
    { userId: userA, organizationId: orgA, apiClientId: clientA1 },
    async (tx) => {
      const doc = await tx.document.create({ data: { userId: userA, organizationId: orgA, title: "Client A1 Doc" } });
      return tx.file.create({
        data: {
          document: { connect: { id: doc.id } },
          originalName: "a1-secret.pdf",
          mimeType: "application/pdf",
          size: BigInt(400),
          storageKey: `api/${orgA}/${clientA1}/secret.pdf`,
          storageObject: buildStorageObjectConnectOrCreate(
            { userId: userA, organizationId: orgA, apiClientId: clientA1 },
            { bucket: "dip-test", objectKey: `api/${orgA}/${clientA1}/secret.pdf`, size: 400 },
          ),
        },
      });
    },
    appClient,
  );
  assert.ok(apiFileA1.storageObjectId);

  // clientA2 CANNOT create a File referencing clientA1's StorageObjectId!
  await assert.rejects(
    () =>
      withTenantScope(
        { userId: userA, organizationId: orgA, apiClientId: clientA2 },
        async (tx) => {
          const doc2 = await tx.document.create({ data: { userId: userA, organizationId: orgA, title: "Client A2 Doc" } });
          return tx.file.create({
            data: {
              document: { connect: { id: doc2.id } },
              originalName: "hijack-a1.pdf",
              mimeType: "application/pdf",
              size: BigInt(400),
              storageKey: `api/${orgA}/${clientA1}/secret.pdf`,
              storageObject: { connect: { id: apiFileA1.storageObjectId! } },
            },
          });
        },
        appClient,
      ),
    /STORAGE_OBJECT_API_CLIENT_MISMATCH|row-level security/,
  );

  // Non-API org scope for userA also CANNOT create a File referencing clientA1's StorageObjectId!
  await assert.rejects(
    () =>
      withTenantScope(
        { userId: userA, organizationId: orgA },
        async (tx) => {
          const docOrg = await tx.document.create({ data: { userId: userA, organizationId: orgA, title: "Org Member Doc" } });
          return tx.file.create({
            data: {
              document: { connect: { id: docOrg.id } },
              originalName: "org-hijack-a1.pdf",
              mimeType: "application/pdf",
              size: BigInt(400),
              storageKey: `api/${orgA}/${clientA1}/secret.pdf`,
              storageObject: { connect: { id: apiFileA1.storageObjectId! } },
            },
          });
        },
        appClient,
      ),
    /STORAGE_OBJECT_API_CLIENT_MISMATCH|row-level security/,
  );

  // clientA2 CANNOT read clientA1's File (restrictive files_storage_object_rls_guard)!
  const visibleToA2 = await withTenantScope(
    { userId: userA, organizationId: orgA, apiClientId: clientA2 },
    (tx) => tx.file.findMany({ where: { id: apiFileA1.id } }),
    appClient,
  );
  assert.equal(visibleToA2.length, 0);

  // Worker pipeline running a job for clientA2 CANNOT consume clientA1's File.storageKey!
  let storageReads = 0;
  const guardedStorage: ObjectStorage = {
    createUploadKey: () => "",
    put: async () => ({ key: "", bucket: "dip-test", contentType: "application/pdf", size: 0 }),
    get: async () => {
      storageReads += 1;
      return new Uint8Array([1, 2, 3]);
    },
    head: async () => undefined,
    exists: async () => true,
    deleteObject: async () => {},
    close: async () => {},
  };

  const hijackJobId = randomUUID();
  sim.jobs.set(hijackJobId, {
    id: hijackJobId,
    toolId: "rotate-pdf",
    requesterId: userA,
    organizationId: orgA,
    apiClientId: clientA2,
    status: "QUEUED",
    params: { inputFileIds: [apiFileA1.id], options: { degrees: 90 } },
    result: null,
    outputFileId: null,
    correlationId: "corr-hijack",
    startedAt: null,
    completedAt: null,
    errorCode: null,
  });

  await assert.rejects(
    () =>
      processDocumentJob(
        { jobId: hijackJobId, toolId: "rotate-pdf", idempotencyKey: "idem-hijack", correlationId: "corr-hijack", userId: userA },
        { client: appClient, storage: guardedStorage },
      ),
    /Input file is missing/,
  );
  assert.equal(storageReads, 0, "storage.get must never be invoked when StorageObject access fails");
});

test("18. File.storageKey access guard and fail-closed RLS gate runner enforce strict boundaries", () => {
  const userA = randomUUID();
  const orgA = randomUUID();
  const clientA1 = randomUUID();
  const clientA2 = randomUUID();

  assert.equal(
    isAuthorizedFileStorageAccess(
      {
        storageKey: `ephemeral/${userA}/quarantine.pdf`,
        storageObjectId: null,
        document: { userId: userA, organizationId: null, status: "ACTIVE" },
      },
      { userId: userA },
    ),
    false,
  );
  assert.equal(
    isAuthorizedFileStorageAccess(
      {
        storageKey: `input/${userA}/unlinked-non-ephemeral.pdf`,
        storageObjectId: null,
        document: { userId: userA, organizationId: null, status: "ACTIVE" },
      },
      { userId: userA },
    ),
    false,
    "non-ephemeral File with storageObjectId=null must never be authorized for object storage reads",
  );
  assert.equal(
    isAuthorizedFileStorageAccess(
      {
        storageKey: `api/${orgA}/${clientA2}/victim.pdf`,
        storageObjectId: randomUUID(),
        document: { userId: userA, organizationId: orgA, status: "ACTIVE" },
        storageObject: {
          ownerUserId: userA,
          organizationId: orgA,
          apiClientId: clientA1,
          provider: "s3",
          bucket: "dip-test",
          objectKey: `api/${orgA}/${clientA1}/own.pdf`,
          deletedAt: null,
        },
      },
      { userId: userA, organizationId: orgA, apiClientId: clientA1 },
    ),
    false,
    "forged File.storageKey differing from StorageObject.objectKey must be rejected",
  );
  assert.equal(
    isAuthorizedFileStorageAccess(
      {
        storageKey: `api/${orgA}/${clientA1}/doc.pdf`,
        storageObjectId: randomUUID(),
        document: { userId: userA, organizationId: orgA, status: "ACTIVE" },
        storageObject: {
          ownerUserId: userA,
          organizationId: orgA,
          apiClientId: clientA1,
          provider: "s3",
          bucket: "dip-test",
          objectKey: `api/${orgA}/${clientA1}/doc.pdf`,
          deletedAt: null,
        },
      },
      { userId: userA, organizationId: orgA, apiClientId: clientA2 },
    ),
    false,
  );
  assert.equal(
    isAuthorizedFileStorageAccess(
      {
        storageKey: `api/${orgA}/${clientA1}/doc.pdf`,
        storageObjectId: randomUUID(),
        document: { userId: userA, organizationId: orgA, status: "ACTIVE" },
        storageObject: {
          ownerUserId: userA,
          organizationId: orgA,
          apiClientId: clientA1,
          provider: "s3",
          bucket: "dip-test",
          objectKey: `api/${orgA}/${clientA1}/doc.pdf`,
          deletedAt: new Date(),
        },
      },
      { userId: userA, organizationId: orgA, apiClientId: clientA1 },
    ),
    false,
  );
  assert.equal(
    isAuthorizedFileStorageAccess(
      {
        storageKey: `api/${orgA}/${clientA1}/doc.pdf`,
        storageObjectId: randomUUID(),
        document: { userId: userA, organizationId: orgA, status: "ACTIVE" },
        storageObject: {
          ownerUserId: userA,
          organizationId: orgA,
          apiClientId: clientA1,
          provider: "s3",
          bucket: "dip-test",
          objectKey: `api/${orgA}/${clientA1}/doc.pdf`,
          deletedAt: null,
        },
      },
      { userId: userA, organizationId: orgA, apiClientId: clientA1 },
      { provider: "s3", bucket: "other-bucket" },
    ),
    false,
  );
  assert.equal(
    isAuthorizedFileStorageAccess(
      {
        storageKey: `api/${orgA}/${clientA1}/doc.pdf`,
        storageObjectId: randomUUID(),
        document: { userId: userA, organizationId: orgA, status: "ACTIVE" },
        storageObject: {
          ownerUserId: userA,
          organizationId: orgA,
          apiClientId: clientA1,
          provider: "s3",
          bucket: "dip-test",
          objectKey: `api/${orgA}/${clientA1}/doc.pdf`,
          deletedAt: null,
        },
      },
      { userId: userA, organizationId: orgA, apiClientId: clientA1 },
    ),
    true,
  );

  // Fail-closed RLS gate environment & skip checks:
  assert.throws(() => validateIsolatedRlsGateEnv({}), /RLS_GATE_ENV_MISSING/);
  assert.throws(
    () =>
      validateIsolatedRlsGateEnv({
        DIP_RLS_TEST_OWNER_URL: "postgresql://placeholder@ep-example.neon.tech/exampledb",
        DIP_RLS_TEST_DATABASE_URL: "postgresql://dip_app:pass@localhost:5432/dip_rls_pg18",
        DIP_RETENTION_TEST_DATABASE_URL: "postgresql://dip_retention:pass@localhost:5432/dip_rls_pg18",
      }),
    /RLS_GATE_FORBIDDEN_HOST/,
  );
  const validEnv = validateIsolatedRlsGateEnv({
    DIP_RLS_TEST_OWNER_URL: "postgresql://postgres:postgres@localhost:5432/dip_rls_pg18",
    DIP_RLS_TEST_DATABASE_URL: "postgresql://dip_app:dip_rls_pg18_runtime@localhost:5432/dip_rls_pg18",
    DIP_RETENTION_TEST_DATABASE_URL: "postgresql://dip_retention:dip_rls_pg18_retention@localhost:5432/dip_rls_pg18",
    DIP_PG18_ADMIN_URL: "postgresql://postgres:postgres@localhost:5432/postgres",
    DIP_REQUIRE_PG18: "1",
  });
  assert.equal(validEnv.requirePg18, true);
  assert.equal(validEnv.adminUrl, "postgresql://postgres:postgres@localhost:5432/postgres");
  assert.throws(
    () =>
      validateIsolatedRlsGateEnv({
        DIP_RLS_TEST_OWNER_URL: "postgresql://postgres:postgres@localhost:5432/dip_rls_pg18",
        DIP_RLS_TEST_DATABASE_URL: "postgresql://dip_app:pass@localhost:5432/dip_rls_pg18",
        DIP_RETENTION_TEST_DATABASE_URL: "postgresql://dip_retention:pass@localhost:5432/dip_rls_pg18",
        DIP_PG18_ADMIN_URL: "postgresql://placeholder@ep-example.neon.tech/postgres",
      }),
    /RLS_GATE_FORBIDDEN_HOST/,
  );
  assert.ok(
    REQUIRED_RLS_TEST_FILES.includes("test/neon-role-compatibility.rls.integration.test.mjs"),
    "PostgreSQL 18 RLS security gate must enforce non-superuser Neon role compatibility test with 0 skips",
  );

  assert.throws(() => evaluateRlsTestCounts({ passed: 8, failed: 0, skipped: 1 }), /RLS_GATE_SKIPPED_FORBIDDEN/);
  assert.throws(() => evaluateRlsTestCounts({ passed: 8, failed: 1, skipped: 0 }), /RLS_GATE_TEST_FAILURE/);
  assert.throws(() => evaluateRlsTestCounts({ passed: 0, failed: 0, skipped: 0 }), /RLS_GATE_EMPTY_SUITE/);
  assert.doesNotThrow(() => evaluateRlsTestCounts({ passed: 9, failed: 0, skipped: 0 }));
});

test("19. Real generated PrismaClient validates checked FileCreateInput + buildStorageObjectConnectOrCreate and surfaces P2002/P2025 rather than PrismaClientValidationError", async () => {
  const userA = randomUUID();
  const userB = randomUUID();
  const orgA = randomUUID();
  const clientA1 = randomUUID();
  const clientA2 = randomUUID();
  const docA = randomUUID();
  const docB = randomUUID();
  const docApi = randomUUID();
  const soPersonalId = randomUUID();
  const soApiId = randomUUID();
  const createdFileId = randomUUID();

  let simulateDuplicateInsert = false;

  class ContractPool extends pg.Pool {
    override async connect(): Promise<pg.PoolClient> {
      let aborted = false;
      return {
        on: () => {},
        removeListener: () => {},
        query: async (sqlOrObj: string | { text: string; rowMode?: string }) => {
          const text = typeof sqlOrObj === "string" ? sqlOrObj : sqlOrObj.text;
          const asArray = typeof sqlOrObj === "object" && sqlOrObj.rowMode === "array";
          const wrap = (rows: Array<Record<string, unknown>>, fields: Array<{ name: string; dataTypeID: number }>) => ({
            rows: asArray ? rows.map((r) => fields.map((f) => r[f.name])) : rows,
            rowCount: rows.length,
            fields,
          });
          if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK") {
            if (text === "ROLLBACK") aborted = false;
            return wrap([], []);
          }
          if (aborted) {
            throw Object.assign(new Error("current transaction is aborted"), { code: "25P02", severity: "ERROR" });
          }
          if (text.includes('INSERT INTO "public"."storage_objects"')) {
            if (simulateDuplicateInsert) {
              aborted = true;
              throw Object.assign(
                new Error('duplicate key value violates unique constraint "storage_objects_provider_bucket_object_key_key"'),
                { code: "23505", severity: "ERROR", constraint: "storage_objects_provider_bucket_object_key_key" },
              );
            }
            const nextId = text.includes("prisma-api") ? soApiId : soPersonalId;
            return wrap([{ id: nextId }], [{ name: "id", dataTypeID: 2950 }]);
          }
          if (text.includes('INSERT INTO "public"."files"')) {
            return wrap(
              [{ id: createdFileId, storage_object_id: soPersonalId }],
              [
                { name: "id", dataTypeID: 2950 },
                { name: "storage_object_id", dataTypeID: 2950 },
              ],
            );
          }
          if (text.includes('FROM "public"."files"')) {
            return wrap(
              [{ id: createdFileId, storage_object_id: soPersonalId }],
              [
                { name: "id", dataTypeID: 2950 },
                { name: "storage_object_id", dataTypeID: 2950 },
              ],
            );
          }
          if (text.includes('FROM "public"."documents"')) {
            return wrap([{ id: docA }], [{ name: "id", dataTypeID: 2950 }]);
          }
          return wrap([], []);
        },
        release: () => {},
      } as unknown as pg.PoolClient;
    }
    override async end(): Promise<void> {}
  }

  const realPrisma = new RuntimePrismaClient({ adapter: new PrismaPg(new ContractPool()) });
  try {
    const okPersonal = await withTenantScope(
      { userId: userA },
      (tx) =>
        tx.file.create({
          data: {
            document: { connect: { id: docA } },
            storageKey: `prisma-connect/${userA}/ok.pdf`,
            mimeType: "application/pdf",
            originalName: "ok.pdf",
            size: BigInt(512),
            storageObject: buildStorageObjectConnectOrCreate(
              { userId: userA },
              { bucket: "dip-rls", objectKey: `prisma-connect/${userA}/ok.pdf`, size: 512 },
            ),
          },
          select: { id: true, storageObjectId: true },
        }),
      realPrisma,
    );
    assert.equal(okPersonal.storageObjectId, soPersonalId);

    const okApi = await withTenantScope(
      { userId: userA, organizationId: orgA, apiClientId: clientA1 },
      (tx) =>
        tx.file.create({
          data: {
            document: { connect: { id: docApi } },
            storageKey: `prisma-api/${orgA}/${clientA1}/ok.pdf`,
            mimeType: "application/pdf",
            originalName: "api-ok.pdf",
            size: BigInt(768),
            storageObject: buildStorageObjectConnectOrCreate(
              { userId: userA, organizationId: orgA, apiClientId: clientA1 },
              { bucket: "dip-rls", objectKey: `prisma-api/${orgA}/${clientA1}/ok.pdf`, size: 768 },
            ),
          },
          select: { id: true, storageObjectId: true },
        }),
      realPrisma,
    );
    assert.ok(okApi.id);

    simulateDuplicateInsert = true;
    await assert.rejects(
      () =>
        withTenantScope(
          { userId: userB },
          (tx) =>
            tx.file.create({
              data: {
                document: { connect: { id: docB } },
                storageKey: `prisma-connect/${userA}/ok.pdf`,
                mimeType: "application/pdf",
                originalName: "collide.pdf",
                size: BigInt(512),
                storageObject: buildStorageObjectConnectOrCreate(
                  { userId: userB },
                  { bucket: "dip-rls", objectKey: `prisma-connect/${userA}/ok.pdf`, size: 512 },
                ),
              },
              select: { id: true, storageObjectId: true },
            }),
          realPrisma,
        ),
      (err: unknown) => {
        assert.equal(err instanceof Prisma.PrismaClientValidationError, false);
        assert.equal(err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002", true);
        return true;
      },
    );

    await assert.rejects(
      () =>
        withTenantScope(
          { userId: userA, organizationId: orgA, apiClientId: clientA2 },
          (tx) =>
            tx.file.create({
              data: {
                document: { connect: { id: docApi } },
                storageKey: `prisma-api/${orgA}/${clientA2}/direct.pdf`,
                mimeType: "application/pdf",
                originalName: "direct.pdf",
                size: BigInt(768),
                storageObject: { connect: { id: soApiId } },
              },
              select: { id: true, storageObjectId: true },
            }),
          realPrisma,
        ),
      (err: unknown) => {
        assert.equal(err instanceof Prisma.PrismaClientValidationError, false);
        assert.equal(err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2025", true);
        return true;
      },
    );
  } finally {
    await realPrisma.$disconnect();
  }
});

test("21. Storage key coordinate integrity: unlinked non-ephemeral files and forged File.storageKey values fail closed across DB triggers/RLS and all storage.get consumers while preserving ephemeral job history", async () => {
  const { sim, userA, userB, orgA, clientA1 } = seedMultiTenantWorld();
  const appClient = sim.clientForRole("dip_app");

  // 1. Legitimate ephemeral job-history File (storageObjectId = null, storageKey = ephemeral/*) succeeds,
  //    stays tenant-scoped, and is never downloadable via findOutputFileForUser.
  const ephemeralHistory = await withTenant(
    { userId: userA },
    async (tx) => {
      const doc = await tx.document.create({ data: { userId: userA, title: "browser-history" } });
      return tx.file.create({
        data: {
          document: { connect: { id: doc.id } },
          originalName: "browser-history.pdf",
          mimeType: "application/pdf",
          size: BigInt(1024),
          storageKey: `ephemeral/${randomUUID()}-browser-history.pdf`,
        },
      });
    },
    appClient,
  );
  assert.equal(ephemeralHistory.storageObjectId, null);
  assert.equal(await findOutputFileForUser(userA, ephemeralHistory.id, appClient), null);

  // 2. Unlinked non-ephemeral File creation is rejected at DB trigger boundary.
  await assert.rejects(
    () =>
      withTenant(
        { userId: userA },
        async (tx) => {
          const doc = await tx.document.create({ data: { userId: userA, title: "unlinked-doc" } });
          return tx.file.create({
            data: {
              document: { connect: { id: doc.id } },
              originalName: "unlinked.pdf",
              mimeType: "application/pdf",
              size: BigInt(512),
              storageKey: `input/${userB}/victim.pdf`,
            },
          });
        },
        appClient,
      ),
    /FILE_STORAGE_OBJECT_REQUIRED/,
  );

  // 3. Forged File.storageKey linked to attacker's own StorageObject is rejected at DB trigger boundary.
  const ownAuthorizedFile = await withTenant(
    { userId: userA },
    async (tx) => {
      const doc = await tx.document.create({ data: { userId: userA, title: "own-doc" } });
      return tx.file.create({
        data: {
          document: { connect: { id: doc.id } },
          originalName: "own.pdf",
          mimeType: "application/pdf",
          size: BigInt(512),
          storageKey: `input/${userA}/own.pdf`,
          storageObject: buildStorageObjectConnectOrCreate(
            { userId: userA },
            { bucket: "dip-test", objectKey: `input/${userA}/own.pdf`, size: 512 },
          ),
        },
      });
    },
    appClient,
  );

  await assert.rejects(
    () =>
      withTenant(
        { userId: userA },
        async (tx) => {
          const doc = await tx.document.create({ data: { userId: userA, title: "forged-doc" } });
          return tx.file.create({
            data: {
              document: { connect: { id: doc.id } },
              originalName: "forged.pdf",
              mimeType: "application/pdf",
              size: BigInt(512),
              storageKey: `input/${userB}/victim.pdf`,
              storageObject: { connect: { id: ownAuthorizedFile.storageObjectId! } },
            },
          });
        },
        appClient,
      ),
    /FILE_STORAGE_KEY_MISMATCH/,
  );

  // 4. Defense in depth: even if raw store state were corrupted out-of-band (unlinked non-ephemeral row or
  //    forged storageKey != objectKey), findOutputFileForUser, getPublicJobResult, downloadPublicJobResult,
  //    and processDocumentJob ALL fail closed with zero storage.get invocations.
  let storageReads = 0;
  const guardedStorage: ObjectStorage = {
    createUploadKey: () => "",
    put: async (): Promise<StoredObject> => ({ key: "", bucket: "dip-test", contentType: "application/pdf", size: 0 }),
    get: async () => {
      storageReads += 1;
      return new Uint8Array();
    },
    head: async () => undefined,
    exists: async () => true,
    deleteObject: async () => {},
    close: async () => {},
  };
  const cleanScanner: MalwareScanner = {
    scan: async () => ({ result: "CLEAN", engine: "stub", engineVersion: "1", signatureVersion: "1", scannedAt: new Date() }),
  };

  // Tamper personal file to forged victim key and unlinked state in sequence:
  sim.files.get(ownAuthorizedFile.id)!.storageKey = `input/${userB}/victim.pdf`;
  assert.equal(await findOutputFileForUser(userA, ownAuthorizedFile.id, appClient), null);

  const forgedJobId = randomUUID();
  sim.jobs.set(forgedJobId, {
    id: forgedJobId,
    toolId: "compress-pdf",
    requesterId: userA,
    organizationId: null,
    apiClientId: null,
    status: "QUEUED",
    params: { inputFileIds: [ownAuthorizedFile.id], options: {} },
    result: null,
    outputFileId: null,
    correlationId: randomUUID(),
    startedAt: null,
    completedAt: null,
    errorCode: null,
  });
  await assert.rejects(
    () =>
      processDocumentJob(
        { jobId: forgedJobId, toolId: "compress-pdf", idempotencyKey: `forged-${forgedJobId}`, correlationId: randomUUID(), userId: userA },
        { client: appClient, storage: guardedStorage, scanner: cleanScanner },
      ),
    /Input file is missing/,
  );

  sim.files.get(ownAuthorizedFile.id)!.storageObjectId = null;
  assert.equal(await findOutputFileForUser(userA, ownAuthorizedFile.id, appClient), null);

  const apiFile = await withTenantScope(
    { userId: userA, organizationId: orgA, apiClientId: clientA1 },
    async (tx) => {
      const doc = await tx.document.create({ data: { userId: userA, organizationId: orgA, title: "api-tamper" } });
      return tx.file.create({
        data: {
          document: { connect: { id: doc.id } },
          originalName: "api.pdf",
          mimeType: "application/pdf",
          size: BigInt(256),
          storageKey: `api/${orgA}/${clientA1}/legit.pdf`,
          storageObject: buildStorageObjectConnectOrCreate(
            { userId: userA, organizationId: orgA, apiClientId: clientA1 },
            { bucket: "dip-test", objectKey: `api/${orgA}/${clientA1}/legit.pdf`, size: 256 },
          ),
        },
      });
    },
    appClient,
  );
  const apiJobId = randomUUID();
  sim.jobs.set(apiJobId, {
    id: apiJobId,
    toolId: "compress-pdf",
    requesterId: userA,
    organizationId: orgA,
    apiClientId: clientA1,
    status: "SUCCEEDED",
    params: {},
    result: { outputFileIds: [apiFile.id] },
    outputFileId: apiFile.id,
    correlationId: null,
    startedAt: new Date(),
    completedAt: new Date(),
    errorCode: null,
  });
  const principalA1: ApiPrincipal = {
    kind: "api_key",
    apiKeyId: randomUUID(),
    apiClientId: clientA1,
    organizationId: orgA,
    executionUserId: userA,
    scopes: ["*"],
  };

  sim.files.get(apiFile.id)!.storageKey = `api/${orgA}/other-client/secret.pdf`;
  const tamperedResult = await getPublicJobResult(principalA1, apiJobId, appClient);
  assert.equal(tamperedResult.kind, "files");
  assert.equal(tamperedResult.files.length, 0);
  await assert.rejects(
    () => downloadPublicJobResult(principalA1, apiJobId, apiFile.id, { client: appClient, storage: guardedStorage }),
    /NOT_FOUND|result file was not found/,
  );
  assert.equal(storageReads, 0, "storage.get must never be invoked for unlinked or forged File.storageKey rows");
});

test("22. Public API retention compatibility regression: owner metadata-only File update succeeds without API-client GUC and retention cleanup expires/deletes cleanly, while coordinate mutations and unauthorized dip_app updates fail closed", async () => {
  const { sim, userA, orgA, clientA1, clientA2 } = seedMultiTenantWorld();
  const appClient = sim.clientForRole("dip_app");
  const ownerClient = sim.clientForRole("table_owner");
  const retentionClient = sim.clientForRole("dip_retention");

  const apiKey = `input/${userA}/${randomUUID()}-expiry.pdf`;
  const apiFile = await withTenantScope(
    { userId: userA, organizationId: orgA, apiClientId: clientA1 },
    async (tx) => {
      const doc = await tx.document.create({ data: { userId: userA, organizationId: orgA, title: "public-api-expiry" } });
      return tx.file.create({
        data: {
          document: { connect: { id: doc.id } },
          originalName: "expiry.pdf",
          mimeType: "application/pdf",
          size: BigInt(512),
          storageKey: apiKey,
          storageObject: buildStorageObjectConnectOrCreate(
            { userId: userA, organizationId: orgA, apiClientId: clientA1 },
            { provider: "s3", bucket: "dip-release-b", objectKey: apiKey, size: 512 },
          ),
        },
      });
    },
    appClient,
  );

  // 1. Exact Public API HTTP E2E fixture aging pattern: table_owner updates File.createdAt
  //    WITHOUT setting any app.current_api_client_id GUC.
  const old = new Date("2020-01-01T00:00:00.000Z");
  const aged = await ownerClient.$transaction((tx) =>
    tx.file.update({ where: { id: apiFile.id }, data: { createdAt: old } }),
  );
  assert.equal(aged.createdAt.toISOString(), old.toISOString());
  assert.equal(aged.storageObjectId, apiFile.storageObjectId);
  assert.equal(aged.storageKey, apiKey);

  // 2. Rival API client (clientA2), non-API org session, and personal session under dip_app
  //    still fail closed on metadata-only File.update under restrictive RLS.
  await assert.rejects(
    () =>
      withTenantScope(
        { userId: userA, organizationId: orgA, apiClientId: clientA2 },
        (tx) => tx.file.update({ where: { id: apiFile.id }, data: { originalName: "tampered.pdf" } }),
        appClient,
      ),
    /P2025|not found/i,
  );
  await assert.rejects(
    () =>
      withTenant(
        { userId: userA },
        (tx) => tx.file.update({ where: { id: apiFile.id }, data: { originalName: "tampered.pdf" } }),
        appClient,
      ),
    /P2025|not found/i,
  );
  await assert.rejects(
    () => retentionClient.$transaction((tx) => tx.file.update({ where: { id: apiFile.id }, data: { createdAt: old } })),
    /permission denied/i,
  );

  // 3. Coordinate mutations and forged storageKey changes STILL fail closed for both table_owner and clientA1.
  await assert.rejects(
    () =>
      ownerClient.$transaction((tx) =>
        tx.file.update({ where: { id: apiFile.id }, data: { storageKey: `api/${orgA}/${clientA2}/forged.pdf` } }),
      ),
    /FILE_STORAGE_COORDINATES_IMMUTABLE/,
  );
  await assert.rejects(
    () =>
      withTenantScope(
        { userId: userA, organizationId: orgA, apiClientId: clientA1 },
        (tx) => tx.file.update({ where: { id: apiFile.id }, data: { storageKey: `api/${orgA}/${clientA2}/forged.pdf` } }),
        appClient,
      ),
    /FILE_STORAGE_COORDINATES_IMMUTABLE/,
  );
  await assert.rejects(
    () => ownerClient.$transaction((tx) => tx.file.update({ where: { id: apiFile.id }, data: { storageObjectId: null } })),
    /FILE_STORAGE_OBJECT_REQUIRED/,
  );

  // 4. Retention cleanup deletes the aged API-client S3 object and tombstones StorageObject.deletedAt via dip_retention.
  const deletedKeys: string[] = [];
  const fakeStorage: ObjectStorage = {
    createUploadKey: () => "",
    put: async (): Promise<StoredObject> => ({ key: "", bucket: "dip-release-b", contentType: "application/pdf", size: 0 }),
    get: async () => new Uint8Array(),
    head: async () => undefined,
    exists: async () => false,
    deleteObject: async (key: string) => {
      deletedKeys.push(key);
    },
    close: async () => {},
  };
  const cleanupOutcome = await runRetentionCleanup({
    now: new Date("2026-11-21T00:00:00.000Z"),
    dryRun: false,
    scope: { provider: "s3", bucket: "dip-release-b" },
    storage: fakeStorage,
    repository: {
      loadActiveDocuments: async () => {
        const storedRows = await retentionClient.$transaction((tx) => tx.storageObject.findMany());
        const storedById = new Map(storedRows.map((row) => [row.id, row]));
        const currentFile = sim.files.get(apiFile.id)!;
        const currentDoc = sim.documents.get(apiFile.documentId)!;
        return currentDoc.status === "ACTIVE"
          ? [
              {
                id: currentDoc.id,
                user: { subscriptions: [{ plan: { code: "FREE" } }] },
                files: [
                  {
                    id: currentFile.id,
                    createdAt: currentFile.createdAt,
                    storageObject: currentFile.storageObjectId ? storedById.get(currentFile.storageObjectId) ?? null : null,
                  },
                ],
              },
            ]
          : [];
      },
      loadProtectedFileIds: async () => new Set<string>(),
      markStorageObjectDeleted: async (storageObjectId, deletedAt) => {
        await retentionClient.$transaction((tx) =>
          tx.storageObject.updateMany({ where: { id: storageObjectId }, data: { deletedAt } }),
        );
      },
      markDocumentDeleted: async (documentId) => {
        sim.documents.get(documentId)!.status = "DELETED";
      },
    },
  });
  assert.equal(cleanupOutcome.deletedObjects, 1);
  assert.equal(cleanupOutcome.deletedDocuments, 1);
  assert.deepEqual(deletedKeys, [apiKey]);
  assert.notEqual(sim.storageObjects.get(apiFile.storageObjectId!)?.deletedAt, null);
});
