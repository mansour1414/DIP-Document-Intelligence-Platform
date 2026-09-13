import { hashPassword } from "@/lib/auth/password";
import { createSessionToken } from "@/lib/auth/session";
import { createSignupHandler } from "@/lib/auth/handlers";
import { grantSignupCreditsInTransaction } from "@/lib/billing/credits";
import { logger } from "@/lib/logging";
import { withAuthIdentity } from "@/lib/db/auth-identity";

export const POST = createSignupHandler({
  findByEmail: (email) => withAuthIdentity(email, (tx, normalizedEmail) => tx.user.findUnique({ where: { email: normalizedEmail }, select: { id: true } })),
  createAccount: async ({ email, password, displayName }) => { const passwordHash = await hashPassword(password); return withAuthIdentity(email, async (tx, normalizedEmail) => { if (await tx.user.findUnique({ where: { email: normalizedEmail }, select: { id: true } })) throw Object.assign(new Error("EMAIL_IN_USE"), { code: "EMAIL_IN_USE" }); try { const user = await tx.user.create({ data: { email: normalizedEmail, displayName, passwordHash }, select: { id: true } }); await tx.$queryRaw`SELECT set_config('app.current_user_id', ${user.id}, true)`; await grantSignupCreditsInTransaction(tx, user.id); return user; } catch (error) { if (typeof error === "object" && error && "code" in error && error.code === "P2002") throw Object.assign(new Error("EMAIL_IN_USE"), { code: "EMAIL_IN_USE" }); throw error; } }); },
  createToken: createSessionToken,
  onError: () => logger.error("auth.signup.failed", { error_code: "SIGNUP_FAILED" }),
});
