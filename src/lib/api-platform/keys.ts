import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const TOKEN_PATTERN = /^dip_v1_([A-Za-z0-9_-]{16})_([A-Za-z0-9_-]{43})$/;

function pepper() {
  const value = process.env.API_KEY_PEPPER;
  if (!value && process.env.NODE_ENV === "production") throw new Error("API_KEY_PEPPER is required in production");
  return value ?? "development-only-api-key-pepper";
}

export function generateApiKeyMaterial() {
  const prefix = randomBytes(12).toString("base64url");
  const secret = randomBytes(32).toString("base64url");
  return { prefix, plaintext: `dip_v1_${prefix}_${secret}`, verifier: apiKeyVerifier(secret) };
}

export function apiKeyVerifier(secret: string) { return createHmac("sha256", pepper()).update(secret).digest("hex"); }

export function parseApiKey(value: string | null | undefined) {
  const match = value?.match(TOKEN_PATTERN); return match ? { prefix: match[1], secret: match[2] } : null;
}

export function verifyApiKeySecret(secret: string, expected: string) {
  const actual = apiKeyVerifier(secret); const left = Buffer.from(actual, "hex"); const right = Buffer.from(expected, "hex");
  return left.length === right.length && timingSafeEqual(left, right);
}

export function bearerApiKey(authorization: string | null) {
  if (!authorization) return null; const match = /^Bearer\s+([^\s]+)$/i.exec(authorization); return match?.[1] ?? null;
}
