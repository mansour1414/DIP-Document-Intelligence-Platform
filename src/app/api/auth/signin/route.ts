import { db } from "@/lib/db";
import { verifyPassword } from "@/lib/auth/password";
import { createSessionToken } from "@/lib/auth/session";
import { createSigninHandler } from "@/lib/auth/handlers";
import { logger } from "@/lib/logging";

export const POST = createSigninHandler({
  findByEmail: (email) => db.user.findUnique({ where: { email }, select: { id: true, passwordHash: true, status: true } }),
  verify: verifyPassword,
  createToken: createSessionToken,
  onError: () => logger.error("auth.signin.failed", { error_code: "AUTH_SERVICE_UNAVAILABLE" }),
});
