import { NextResponse } from "next/server";
import { currentUser } from "@/lib/auth/user";
export async function GET() { try { const user = await currentUser(); return NextResponse.json({ authenticated: Boolean(user?.status === "ACTIVE") }, { headers: { "Cache-Control": "no-store" } }); } catch { return NextResponse.json({ authenticated: false }, { headers: { "Cache-Control": "no-store" } }); } }
