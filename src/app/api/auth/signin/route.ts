import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { verifyPassword } from "@/lib/auth/password";
import { createSessionToken, sessionCookie } from "@/lib/auth/session";

export async function POST(request: Request) {
  const body = await request.json() as { email?: unknown; password?: unknown };
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const password = typeof body.password === "string" ? body.password : "";
  const user = await db.user.findUnique({ where: { email }, select: { id: true, passwordHash: true, status: true } });
  if (!user || !user.passwordHash || user.status !== "ACTIVE" || !await verifyPassword(password, user.passwordHash)) return NextResponse.json({ code: "INVALID_CREDENTIALS", message: "Email or password is incorrect." }, { status: 401 });
  const response = NextResponse.json({ ok: true }); response.cookies.set(sessionCookie.name, createSessionToken(user.id), sessionCookie); return response;
}
