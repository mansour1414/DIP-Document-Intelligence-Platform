import { randomUUID } from "node:crypto";
import { withOrganization, withTenant } from "@/lib/db/tenant";
import { assertMembershipChangeAllowed, BusinessAuthorizationError, type OrganizationRole } from "./policy";
import { writeBusinessAudit } from "./audit";

const clean = (value: string, max = 100) => { const result = value.trim(); if (!result || result.length > max) throw new Error("INVALID_INPUT"); return result; };
const slugify = (value: string) => clean(value).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 90);

export async function createOrganization(actorUserId: string, name: string) {
  const id = randomUUID(); const normalizedName = clean(name); const slug = `${slugify(name)}-${id.slice(0, 8)}`;
  await withTenant({ userId: actorUserId }, (tx) => tx.$queryRaw`SELECT create_organization_with_owner(${id}::uuid, ${normalizedName}, ${slug})`);
  await withOrganization({ userId: actorUserId, organizationId: id }, (tx) => writeBusinessAudit(tx, { organizationId: id, actorUserId, action: "organization.created", resource: "organization", resourceId: id, details: { name: normalizedName } }));
  return { id, name: normalizedName, slug, status: "ACTIVE" as const };
}

async function actorRole(tx: Parameters<Parameters<typeof withOrganization>[1]>[0], organizationId: string, actorUserId: string) {
  const member = await tx.membership.findUnique({ where: { userId_organizationId: { userId: actorUserId, organizationId } }, select: { role: true } });
  if (!member) throw new BusinessAuthorizationError("FORBIDDEN"); return member.role as OrganizationRole;
}

export async function addMembership(actorUserId: string, organizationId: string, targetUserId: string, role: OrganizationRole = "MEMBER") {
  return withOrganization({ userId: actorUserId, organizationId }, async (tx) => {
    const actor = await actorRole(tx, organizationId, actorUserId); assertMembershipChangeAllowed({ actorId: actorUserId, actorRole: actor, targetUserId, nextRole: role });
    try {
      const membership = await tx.membership.create({ data: { organizationId, userId: targetUserId, role } });
      await writeBusinessAudit(tx, { organizationId, actorUserId, action: "membership.created", resource: "membership", resourceId: membership.id, details: { targetUserId, role } }); return membership;
    } catch (error) { if ((error as { code?: string }).code === "P2002") throw new BusinessAuthorizationError("CONFLICT"); throw error; }
  });
}

export async function changeMembershipRole(actorUserId: string, organizationId: string, targetUserId: string, nextRole: OrganizationRole) {
  return withOrganization({ userId: actorUserId, organizationId }, async (tx) => {
    const actor = await actorRole(tx, organizationId, actorUserId); const current = await tx.membership.findUnique({ where: { userId_organizationId: { userId: targetUserId, organizationId } } });
    if (!current) throw new BusinessAuthorizationError("NOT_FOUND");
    assertMembershipChangeAllowed({ actorId: actorUserId, actorRole: actor, targetUserId, currentRole: current.role as OrganizationRole, nextRole });
    if (current.role === "OWNER" && nextRole !== "OWNER" && await tx.membership.count({ where: { organizationId, role: "OWNER" } }) <= 1) throw new BusinessAuthorizationError("LAST_OWNER");
    const membership = await tx.membership.update({ where: { id: current.id }, data: { role: nextRole } });
    await writeBusinessAudit(tx, { organizationId, actorUserId, action: "membership.role_changed", resource: "membership", resourceId: current.id, details: { targetUserId, from: current.role, to: nextRole } }); return membership;
  });
}
