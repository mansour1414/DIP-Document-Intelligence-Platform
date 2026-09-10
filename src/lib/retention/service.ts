import { db } from "@/lib/db";
import { getStorage, type ObjectStorage } from "@/lib/storage";
import { retentionPolicy } from "./config";
import { logger } from "@/lib/logging";
import { recordMetric } from "@/lib/observability/metrics";

export type CleanupResult = { scanned: number; deletedObjects: number; deletedDocuments: number; failures: number; dryRun: boolean };

export async function runRetentionCleanup(input: { now?: Date; dryRun?: boolean; storage?: ObjectStorage } = {}): Promise<CleanupResult> {
  const now = input.now ?? new Date(); const dryRun = input.dryRun ?? true; const storage = input.storage ?? getStorage();
  const documents = await db.document.findMany({ where: { status: "ACTIVE" }, include: { files: { include: { storageObject: true }, orderBy: { createdAt: "asc" } }, user: { include: { subscriptions: { where: { status: { in: ["ACTIVE", "TRIALING"] }, startsAt: { lte: now }, OR: [{ currentPeriodEnd: null }, { currentPeriodEnd: { gt: now } }] }, include: { plan: true }, orderBy: { createdAt: "desc" }, take: 1 } } } } });
  const activeJobs = await db.job.findMany({ where: { status: { in: ["QUEUED", "RUNNING", "RETRYING"] } }, select: { inputFileId: true, outputFileId: true, params: true } });
  const protectedIds = new Set<string>();
  for (const job of activeJobs) { if (job.inputFileId) protectedIds.add(job.inputFileId); if (job.outputFileId) protectedIds.add(job.outputFileId); const ids = (job.params as { inputFileIds?: unknown })?.inputFileIds; if (Array.isArray(ids)) for (const id of ids) if (typeof id === "string") protectedIds.add(id); }
  let deletedObjects = 0, deletedDocuments = 0, failures = 0;
  for (const document of documents) {
    const plan = document.user.subscriptions[0]?.plan.code === "PRO" ? "PRO" : "FREE";
    const cutoff = now.getTime() - retentionPolicy.plans[plan].inputDays * 86_400_000;
    if (!document.files.length || document.files.some((file) => file.createdAt.getTime() >= cutoff || protectedIds.has(file.id))) continue;
    if (dryRun) { logger.info("retention.document_candidate", { document_id: document.id, policy_version: retentionPolicy.version }); continue; }
    let complete = true;
    for (const file of document.files) {
      const object = file.storageObject;
      if (!object || object.deletedAt) continue;
      try { await storage.deleteObject(object.objectKey); await db.storageObject.update({ where: { id: object.id }, data: { deletedAt: now } }); deletedObjects += 1; }
      catch (error) { complete = false; failures += 1; recordMetric("cleanup_failure_total", 1, "count", { status: "failed" }); logger.error("retention.storage_delete_failed", { document_id: document.id, storage_object_id: object.id, error_code: error instanceof Error ? error.name : "UNKNOWN" }); }
    }
    if (complete) { await db.document.update({ where: { id: document.id }, data: { status: "DELETED" } }); deletedDocuments += 1; }
  }
  logger.info("retention.completed", { scanned: documents.length, deleted_objects: deletedObjects, deleted_documents: deletedDocuments, failures, dry_run: dryRun, policy_version: retentionPolicy.version });
  return { scanned: documents.length, deletedObjects, deletedDocuments, failures, dryRun };
}
