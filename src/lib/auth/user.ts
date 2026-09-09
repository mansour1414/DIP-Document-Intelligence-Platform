import { cookies } from "next/headers";
import { db } from "@/lib/db";
import { sessionCookie, verifySessionToken } from "@/lib/auth/session";

export async function currentUser() {
  const token = (await cookies()).get(sessionCookie.name)?.value;
  const id = verifySessionToken(token);
  if (!id) return null;
  return db.user.findUnique({ where: { id }, select: { id: true, email: true, displayName: true, locale: true, status: true } });
}

export async function requireUser() {
  const user = await currentUser();
  if (!user || user.status !== "ACTIVE") throw new Error("AUTH_REQUIRED");
  return user;
}
