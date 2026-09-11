import { db } from "@/lib/db";
import { hashPassword } from "@/lib/auth/password";
import { createSessionToken } from "@/lib/auth/session";
import { createSignupHandler } from "@/lib/auth/handlers";
import { grantSignupCreditsInTransaction } from "@/lib/billing/credits";
import { logger } from "@/lib/logging";

export const POST = createSignupHandler({
  findByEmail: (email) => db.user.findUnique({ where: { email }, select: { id: true } }),
  createAccount: async ({ email, password, displayName }) => { const passwordHash = await hashPassword(password); return db.$transaction(async (tx) => { const user = await tx.user.create({ data: { email, displayName, passwordHash }, select: { id: true } }); await tx.$queryRaw`SELECT set_config('app.current_user_id', ${user.id}, true)`; await grantSignupCreditsInTransaction(tx, user.id); return user; }); },
  createToken: createSessionToken,
  onError: () => logger.error("auth.signup.failed", { error_code: "SIGNUP_FAILED" }),
});
