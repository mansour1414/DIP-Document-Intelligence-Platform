import { verifyPassword } from "@/lib/auth/password";
import { createSessionToken } from "@/lib/auth/session";
import { createSigninHandler } from "@/lib/auth/handlers";
import { logger } from "@/lib/logging";
import { withAuthIdentity } from "@/lib/db/auth-identity";

export const POST = createSigninHandler({
  findByEmail: (email) => withAuthIdentity(email, (tx, normalizedEmail) => tx.user.findUnique({ where: { email: normalizedEmail }, select: { id: true, passwordHash: true, status: true } })),
  verify: verifyPassword,
  createToken: createSessionToken,
  onError: () => logger.error("auth.signin.failed", { error_code: "AUTH_SERVICE_UNAVAILABLE" }),
});
