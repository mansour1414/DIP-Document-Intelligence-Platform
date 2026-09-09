import { NextResponse } from "next/server";
import { sessionCookie } from "@/lib/auth/session";

export async function POST(request: Request) { const response = NextResponse.redirect(new URL("/", request.url), 303); response.cookies.set(sessionCookie.name, "", { ...sessionCookie, maxAge: 0 }); return response; }
