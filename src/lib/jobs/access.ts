import type { PrismaClient } from "@prisma/client";
import { db } from "@/lib/db";
import { withTenant } from "@/lib/db/tenant";

/**
 * Tenant-scoped read helpers shared by the job status and output download
 * routes.
 *
 * Every read runs inside `withTenant`, so the `app.current_user_id` RLS context
 * (`jobs_tenant_policy`, `files_tenant_policy`) applies to the query, *and* the
 * explicit owner predicate is still part of the `where` clause. Authorization is
 * therefore enforced twice and can never depend on the caller remembering to set
 * the session context.
 *
 * The optional client exists so database-backed tests can exercise the same code
 * against a least-privilege runtime role. Production callers never pass it.
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

export const outputFileSelect = { originalName: true, mimeType: true, storageKey: true } as const;

export function findJobForUser(userId: string, jobId: string, client: PrismaClient = db) {
  return withTenant({ userId }, (tx) => tx.job.findFirst({ where: { id: jobId, requesterId: userId }, select: jobStatusSelect }), client);
}

export function findOutputFileForUser(userId: string, fileId: string, client: PrismaClient = db) {
  return withTenant({ userId }, (tx) => tx.file.findFirst({ where: { id: fileId, document: { userId } }, select: outputFileSelect }), client);
}
