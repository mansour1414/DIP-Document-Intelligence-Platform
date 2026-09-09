import { createHmac, timingSafeEqual } from "crypto";

const COOKIE_NAME = "dip_session";
const maxAgeSeconds = 60 * 60 * 24 * 7;

function secret() {
  const value = process.env.AUTH_SECRET;
  if (!value && process.env.NODE_ENV === "production") throw new Error("AUTH_SECRET is required in production");
  return value ?? "development-only-secret";
}

export function createSessionToken(userId: string) {
  const payload = Buffer.from(JSON.stringify({ sub: userId, exp: Math.floor(Date.now() / 1000) + maxAgeSeconds })).toString("base64url");
  const signature = createHmac("sha256", secret()).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

export function verifySessionToken(token?: string): string | null {
  if (!token) return null;
  const [payload, signature] = token.split(".");
  if (!payload || !signature) return null;
  const expected = createHmac("sha256", secret()).update(payload).digest("base64url");
  if (signature.length !== expected.length || !timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  const value = JSON.parse(Buffer.from(payload, "base64url").toString()) as { sub: string; exp: number };
  return value.exp > Date.now() / 1000 ? value.sub : null;
}

export const sessionCookie = { name: COOKIE_NAME, maxAge: maxAgeSeconds, httpOnly: true, sameSite: "lax" as const, secure: process.env.NODE_ENV === "production", path: "/" };
