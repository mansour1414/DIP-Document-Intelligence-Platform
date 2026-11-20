
/**
 * The only module in the retention subsystem that can mutate PostgreSQL.
 *
 * Keeping every statement here has two purposes:
 *
 *   1. `service.ts` (the planner and orchestrator) then contains no write
 *      statement at all, so a dry-run is non-mutating by construction rather
 *      than by convention. The scheduled dry-run test slices `service.ts` and
 *      asserts the absence of writes; that assertion stays meaningful because
 *      this file is the sole escape hatch.
 *   2. Tests inject a fake repository whose write methods throw. If any dry-run
 *      path ever reached a write, the test fails loudly instead of silently
 *      mutating a fixture.
 *
 * Reading is intentionally *not* restricted to the metadata-only shape: the
 * planner needs `provider`, `bucket` and `objectKey` to prove an object is inside
 * the configured storage scope before it is even considered for deletion.
 */

/** Non-terminal job states. A file referenced by any of these is never deleted. */
export const ACTIVE_JOB_STATUSES = ["QUEUED", "RUNNING", "RETRYING"] as const;

export type RetentionStorageObjectRow = {
  id: string;
  provider: string;
  bucket: string;
  objectKey: string;
  deletedAt: Date | null;
};

export type RetentionFileRow = {
  id: string;
  createdAt: Date;
  storageObject: RetentionStorageObjectRow | null;
};

export type RetentionDocumentRow = {
  id: string;
  user: { subscriptions: ReadonlyArray<{ plan: { code: string } }> };
  files: ReadonlyArray<RetentionFileRow>;
};

/**
 * Port used by the retention sweep.
 *
 * `markStorageObjectDeleted`/`markDocumentDeleted` are **apply-only**. A
 * dry-run never calls them; a read-only implementation may omit them entirely,
 * in which case `runRetentionCleanup` refuses to run in apply mode rather than
 * silently deleting storage objects it cannot record.
 */
export type RetentionRepository = {
  loadActiveDocuments(now: Date): Promise<ReadonlyArray<RetentionDocumentRow>>;
  loadProtectedFileIds(): Promise<Set<string>>;
  markStorageObjectDeleted?(storageObjectId: string, deletedAt: Date): Promise<void>;
  markDocumentDeleted?(documentId: string): Promise<void>;
};

/**
 * Documents are read with their files, storage objects and the user's newest
 * active subscription, because the applicable retention period is decided per
 * document from that subscription's plan.
 */
/**
 * The Prisma client is resolved lazily.
 *
 * Importing it at module scope would construct a client as a side effect of
 * `import`, which is exactly what a dry-run entrypoint must not do before it has
 * validated its configuration. Deferring it also lets the planner be tested with
 * an injected repository and no database at all.
 */
async function prisma() {
  const { db } = await import("@/lib/db");
  return db;
}

async function loadActiveDocuments(now: Date) {
  const db = await prisma();
  return db.document.findMany({
    where: { status: "ACTIVE" },
    include: {
      files: { include: { storageObject: true }, orderBy: { createdAt: "asc" } },
      user: {
        include: {
          subscriptions: {
            where: {
              status: { in: ["ACTIVE", "TRIALING"] },
              startsAt: { lte: now },
              OR: [{ currentPeriodEnd: null }, { currentPeriodEnd: { gt: now } }],
            },
            include: { plan: true },
            orderBy: { createdAt: "desc" },
            take: 1,
          },
        },
      },
    },
  });
}

/**
 * Files referenced by live jobs must never be deleted.
 *
 * Jobs are read **without a lower age bound**: a stale QUEUED/RUNNING/RETRYING
 * row still represents work that has not reached a terminal state, so expiring
 * it in the same sweep must not also release its inputs for deletion.
 */
async function loadProtectedFileIds(): Promise<Set<string>> {
  const db = await prisma();
  const activeJobs = await db.job.findMany({
    where: { status: { in: [...ACTIVE_JOB_STATUSES] } },
    select: { inputFileId: true, outputFileId: true, params: true },
  });
  const protectedIds = new Set<string>();
  for (const job of activeJobs) {
    if (job.inputFileId) protectedIds.add(job.inputFileId);
    if (job.outputFileId) protectedIds.add(job.outputFileId);
    const ids = (job.params as { inputFileIds?: unknown })?.inputFileIds;
    if (Array.isArray(ids)) for (const id of ids) if (typeof id === "string") protectedIds.add(id);
  }
  return protectedIds;
}

/**
 * Default production repository.
 *
 * Column-scoped `UPDATE` privileges on `jobs`, `documents` and
 * `storage_objects` are the only writes the `dip_retention` role holds; nothing
 * here deletes a row.
 */
export const prismaRetentionRepository: RetentionRepository = {
  loadActiveDocuments,
  loadProtectedFileIds,
  async markStorageObjectDeleted(storageObjectId, deletedAt) {
    const db = await prisma();
    await db.storageObject.update({ where: { id: storageObjectId }, data: { deletedAt } });
  },
  async markDocumentDeleted(documentId) {
    const db = await prisma();
    await db.document.update({ where: { id: documentId }, data: { status: "DELETED" } });
  },
};
