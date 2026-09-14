import type { Prisma } from "@prisma/client";

export async function writeBusinessAudit(tx: Prisma.TransactionClient, event: { organizationId: string; actorUserId?: string; action: string; resource: string; resourceId?: string; details?: Prisma.InputJsonValue }) {
  const details = JSON.stringify(event.details ?? {});
  await tx.$executeRaw`
    INSERT INTO audit_logs(id, user_id, organization_id, action, resource, resource_id, details, created_at)
    VALUES (gen_random_uuid(), ${event.actorUserId ?? null}::uuid, ${event.organizationId}::uuid, ${event.action}, ${event.resource}, ${event.resourceId ?? null}::uuid, ${details}::jsonb, now())
  `;
}
