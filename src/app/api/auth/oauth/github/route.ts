import { randomBytes } from "crypto";
import { NextResponse } from "next/server";

const stateCookie = "dip_oauth_state";

export async function GET(request: Request) {
  const clientId = process.env.GITHUB_CLIENT_ID;
  if (!clientId) return NextResponse.json({ code: "OAUTH_NOT_CONFIGURED", message: "GitHub OAuth is not configured." }, { status: 503 });
  const state = randomBytes(24).toString("base64url");
  const callback = new URL("/api/auth/oauth/github/callback", process.env.NEXT_PUBLIC_APP_URL ?? request.url);
  const authorize = new URL("https://github.com/login/oauth/authorize"); authorize.searchParams.set("client_id", clientId); authorize.searchParams.set("redirect_uri", callback.toString()); authorize.searchParams.set("scope", "read:user user:email"); authorize.searchParams.set("state", state);
  const response = NextResponse.redirect(authorize); response.cookies.set(stateCookie, state, { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 600, path: "/" }); return response;
}
