import { withTenant } from "@/lib/db/tenant";
import { isAuthorizedFileStorageAccess } from "@/lib/storage/metadata";
import { AgentError } from "./errors";
import type { AgentRequest, ResolvedAgentFile, ResolvedAgentScope } from "./types";

export type AgentFileLookup = (userId: string, fileIds: readonly string[]) => Promise<readonly ResolvedAgentFile[]>;
const databaseLookup: AgentFileLookup = (userId, fileIds) =>
  withTenant(
    { userId },
    (tx) =>
      tx.file
        .findMany({
          where: {
            id: { in: [...fileIds] },
            document: { userId, organizationId: null, status: "ACTIVE" },
            storageObjectId: { not: null },
            NOT: { storageKey: { startsWith: "ephemeral/" } },
            storageObject: {
              ownerUserId: userId,
              organizationId: null,
              apiClientId: null,
              deletedAt: null,
            },
          },
          select: {
            id: true,
            mimeType: true,
            size: true,
            pageCount: true,
            storageKey: true,
            storageObjectId: true,
            storageObject: {
              select: {
                ownerUserId: true,
                organizationId: true,
                apiClientId: true,
                provider: true,
                bucket: true,
                objectKey: true,
                deletedAt: true,
              },
            },
          },
        })
        .then((files) =>
          files
            .filter((file) => isAuthorizedFileStorageAccess(file, { userId }))
            .map((file) => ({
              id: file.id,
              mimeType: file.mimeType,
              size: Number(file.size),
              ...(file.pageCount === null ? {} : { pageCount: file.pageCount }),
            })),
        ),
  );

export async function resolveAgentScope(request: AgentRequest, userId: string, lookup: AgentFileLookup = databaseLookup): Promise<ResolvedAgentScope> {
  const requested = [...new Set(Object.values(request.scope.inputs).flat())]; if (!requested.length) throw new AgentError("AGENT_SCOPE_EMPTY", "Agent document scope cannot be empty.", "$.scope");
  const files = await lookup(userId, requested); const byId = new Map(files.map((file) => [file.id, file]));
  if (files.length !== requested.length || requested.some((id) => !byId.has(id))) throw new AgentError("AGENT_SCOPE_UNAUTHORIZED", "Every scoped File ID must belong to the authenticated user.", "$.scope");
  const inputs = Object.fromEntries(Object.entries(request.scope.inputs).map(([name, ids]) => [name, Object.freeze(ids.map((id) => byId.get(id)!))]));
  return Object.freeze({ inputs: Object.freeze(inputs), fileIds: Object.freeze(requested) });
}
