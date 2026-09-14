export type OrganizationRole = "OWNER" | "ADMIN" | "MEMBER";

export class BusinessAuthorizationError extends Error {
  constructor(readonly code: "FORBIDDEN" | "PRIVILEGE_ESCALATION" | "LAST_OWNER" | "NOT_FOUND" | "CONFLICT") { super(code); }
}

export function assertCanManageApi(actorRole: OrganizationRole) {
  if (actorRole !== "OWNER" && actorRole !== "ADMIN") throw new BusinessAuthorizationError("FORBIDDEN");
}

export function assertMembershipChangeAllowed(input: { actorId: string; actorRole: OrganizationRole; targetUserId: string; currentRole?: OrganizationRole; nextRole?: OrganizationRole }) {
  if (input.actorRole === "MEMBER") throw new BusinessAuthorizationError("FORBIDDEN");
  if (input.actorId === input.targetUserId) throw new BusinessAuthorizationError("PRIVILEGE_ESCALATION");
  if (input.actorRole === "ADMIN" && (input.currentRole && input.currentRole !== "MEMBER" || input.nextRole && input.nextRole !== "MEMBER")) throw new BusinessAuthorizationError("PRIVILEGE_ESCALATION");
}
