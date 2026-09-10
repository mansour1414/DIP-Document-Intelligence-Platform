import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { hashPassword } from "@/lib/auth/password";
import { createSessionToken, sessionCookie } from "@/lib/auth/session";
import { grantSignupCredits } from "@/lib/billing/credits";

export async function POST(request: Request) {
  try {
    const body = await request.json() as { email?: unknown; password?: unknown; displayName?: unknown };
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = typeof body.password === "string" ? body.password : "";
    const displayName = typeof body.displayName === "string" ? body.displayName.trim().slice(0, 100) : null;
    if (!/^\S+@\S+\.\S+$/.test(email) || password.length < 10) return NextResponse.json({ code: "INVALID_INPUT", message: "Use a valid email and a password of at least 10 characters." }, { status: 400 });
    if (await db.user.findUnique({ where: { email }, select: { id: true } })) return NextResponse.json({ code: "EMAIL_IN_USE", message: "An account already exists for this email." }, { status: 409 });
    const user = await db.user.create({ data: { email, displayName, passwordHash: await hashPassword(password) }, select: { id: true } });
    await grantSignupCredits(user.id);
    const response = NextResponse.json({ ok: true }, { status: 201 }); response.cookies.set(sessionCookie.name, createSessionToken(user.id), sessionCookie); return response;
  } catch { return NextResponse.json({ code: "SIGNUP_FAILED", message: "We could not create your account." }, { status: 500 }); }
}
