import { db } from "@/lib/db";

/**
 * Tenant-scoped read helpers shared by the job status and output download
 * routes. Both queries always constrain on the authenticated user id, so a
 * caller can never read another user's job or output file.
 *
 * Kept in one place so the authorization predicate has a single, testable
 * definition.
 */

export const jobStatusSelect = {
  id: true,
  toolId: true,
  status: true,
  result: true,
  errorCode: true,
  error: true,
  correlationId: true,
} as const;

export function findJobForUser(userId: string, jobId: string) {
  return db.job.findFirst({ where: { id: jobId, requesterId: userId }, select: jobStatusSelect });
}

export const outputFileSelect = { originalName: true, mimeType: true, storageKey: true } as const;

export function findOutputFileForUser(userId: string, fileId: string) {
  return db.file.findFirst({ where: { id: fileId, document: { userId } }, select: outputFileSelect });
}
