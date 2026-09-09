import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { createSessionToken, sessionCookie } from "@/lib/auth/session";
import { grantSignupCredits } from "@/lib/billing/credits";

type GitHubProfile = { id: number; login: string; name: string | null; email: string | null };

export async function GET(request: Request) {
  const url = new URL(request.url); const code = url.searchParams.get("code"); const state = url.searchParams.get("state"); const expected = request.headers.get("cookie")?.match(/(?:^|; )dip_oauth_state=([^;]+)/)?.[1];
  if (!code || !state || !expected || state !== expected) return NextResponse.redirect(new URL("/login?error=oauth_state", request.url));
  const clientId = process.env.GITHUB_CLIENT_ID; const clientSecret = process.env.GITHUB_CLIENT_SECRET;
  if (!clientId || !clientSecret) return NextResponse.redirect(new URL("/login?error=oauth_config", request.url));
  try {
    const callback = new URL("/api/auth/oauth/github/callback", process.env.NEXT_PUBLIC_APP_URL ?? request.url);
    const tokenResponse = await fetch("https://github.com/login/oauth/access_token", { method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json" }, body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code, redirect_uri: callback.toString() }) });
    const token = await tokenResponse.json() as { access_token?: string }; if (!token.access_token) throw new Error("Token exchange failed");
    const profileResponse = await fetch("https://api.github.com/user", { headers: { Authorization: `Bearer ${token.access_token}`, Accept: "application/vnd.github+json" } }); const profile = await profileResponse.json() as GitHubProfile; if (!profileResponse.ok || !profile.id) throw new Error("Profile lookup failed");
    const account = await db.account.findUnique({ where: { provider_providerAccountId: { provider: "github", providerAccountId: String(profile.id) } }, select: { userId: true } });
    let user: { id: string };
    if (account) user = { id: account.userId };
    else { user = await db.user.create({ data: { email: profile.email?.toLowerCase() ?? `github-${profile.id}@users.noreply.github.com`, displayName: profile.name ?? profile.login, subscriptions: { create: { plan: "FREE", status: "ACTIVE" } }, accounts: { create: { provider: "github", providerAccountId: String(profile.id), accessToken: token.access_token } } }, select: { id: true } }); await grantSignupCredits(user.id); }
    const response = NextResponse.redirect(new URL("/dashboard", request.url)); response.cookies.set(sessionCookie.name, createSessionToken(user.id), sessionCookie); response.cookies.set("dip_oauth_state", "", { httpOnly: true, sameSite: "lax", maxAge: 0, path: "/" }); return response;
  } catch { return NextResponse.redirect(new URL("/login?error=oauth_failed", request.url)); }
}
