import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from "node:crypto";
import { getReadyQueueConnection } from "@/lib/queue";

export const PHASE1_SECRET_TTL_SECONDS = 5 * 60;
export const phase1SecretToolIds = new Set(["protect-pdf", "unlock-pdf", "pdf-permissions"]);
export type Phase1SecretPurpose = "protect-pdf" | "unlock-pdf" | "pdf-permissions";
export type Phase1SecretPayload = { userPassword?: string; ownerPassword?: string; password?: string; authorizedUseAcknowledged?: true };
type Envelope = { v: 1; iv: string; tag: string; ciphertext: string };
export type SecretStore = { set(key: string, value: string, ttlSeconds: number): Promise<void>; take(key: string): Promise<string | null>; delete(key: string): Promise<void> };

function keyBytes(value = process.env.PHASE1_SECRET_ENCRYPTION_KEY) {
  if (!value) throw Object.assign(new Error("Phase 1 secret encryption is not configured."), { code: "SECRET_HANDOFF_UNAVAILABLE" });
  if (!/^[A-Za-z0-9+/]{43}=$/u.test(value)) throw Object.assign(new Error("Phase 1 secret encryption key must be canonical base64."), { code: "SECRET_HANDOFF_UNAVAILABLE" });
  const bytes = Buffer.from(value, "base64");
  if (bytes.byteLength !== 32) throw Object.assign(new Error("Phase 1 secret encryption key must be 32 base64-encoded bytes."), { code: "SECRET_HANDOFF_UNAVAILABLE" });
  return bytes;
}

function redisStore(): SecretStore {
  return {
    async set(key, value, ttl) { const redis = await getReadyQueueConnection(); const result = await redis.set(key, value, "EX", ttl, "NX"); if (result !== "OK") throw new Error("SECRET_REFERENCE_COLLISION"); },
    async take(key) { const redis = await getReadyQueueConnection(); return redis.getdel(key); },
    async delete(key) { const redis = await getReadyQueueConnection(); await redis.del(key); },
  };
}

const redisKey = (reference: string) => `dip:phase1-secret:v1:${reference}`;
const aad = (tenantId: string, jobId: string, purpose: Phase1SecretPurpose) => Buffer.from(`v1\0${tenantId}\0${jobId}\0${purpose}`);

export function validatePhase1Secrets(purpose: Phase1SecretPurpose, value: Phase1SecretPayload) {
  const validPassword = (password: unknown, allowEmpty = false) => typeof password === "string" && (allowEmpty || password.length > 0) && password.length <= 128 && !password.startsWith("@") && !/[\0\r\n]/u.test(password);
  if (purpose === "protect-pdf" && (!validPassword(value.userPassword) || !validPassword(value.ownerPassword))) throw Object.assign(new Error("A valid user and owner password are required."), { code: "SECRET_INPUT_INVALID" });
  if (purpose === "unlock-pdf" && (!validPassword(value.password) || value.authorizedUseAcknowledged !== true)) throw Object.assign(new Error("A valid password and authorized-use acknowledgement are required."), { code: "SECRET_INPUT_INVALID" });
  if (purpose === "pdf-permissions" && (!validPassword(value.ownerPassword) || (value.userPassword !== undefined && !validPassword(value.userPassword, true)))) throw Object.assign(new Error("A valid owner password is required."), { code: "SECRET_INPUT_INVALID" });
  return value;
}

export async function putPhase1Secret(input: { tenantId: string; jobId: string; purpose: Phase1SecretPurpose; payload: Phase1SecretPayload }, store: SecretStore = redisStore()) {
  validatePhase1Secrets(input.purpose, input.payload);
  const reference = randomUUID(); const iv = randomBytes(12); const cipher = createCipheriv("aes-256-gcm", keyBytes(), iv); cipher.setAAD(aad(input.tenantId, input.jobId, input.purpose));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(input.payload), "utf8"), cipher.final()]);
  const envelope: Envelope = { v: 1, iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), ciphertext: ciphertext.toString("base64") };
  await store.set(redisKey(reference), JSON.stringify(envelope), PHASE1_SECRET_TTL_SECONDS);
  return reference;
}

export async function takePhase1Secret(input: { reference: string; tenantId: string; jobId: string; purpose: Phase1SecretPurpose }, store: SecretStore = redisStore()) {
  const encoded = await store.take(redisKey(input.reference));
  if (!encoded) throw Object.assign(new Error("The password handoff expired or was already consumed."), { code: "SECRET_REFERENCE_EXPIRED" });
  try {
    const envelope = JSON.parse(encoded) as Envelope; if (envelope.v !== 1) throw new Error("version");
    const decipher = createDecipheriv("aes-256-gcm", keyBytes(), Buffer.from(envelope.iv, "base64")); decipher.setAAD(aad(input.tenantId, input.jobId, input.purpose)); decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
    const payload = JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, "base64")), decipher.final()]).toString("utf8")) as Phase1SecretPayload;
    return validatePhase1Secrets(input.purpose, payload);
  } catch (error) { throw Object.assign(new Error("The password handoff could not be authenticated."), { code: "SECRET_REFERENCE_INVALID", cause: error }); }
}

export async function deletePhase1Secret(reference: string | undefined, store: SecretStore = redisStore()) { if (reference) await store.delete(redisKey(reference)); }

export async function enforceUnlockRateLimit(tenantId: string) {
  const redis = await getReadyQueueConnection(); const key = `dip:unlock-rate:v1:${tenantId}`; const count = await redis.incr(key); if (count === 1) await redis.expire(key, 60);
  if (count > 5) throw Object.assign(new Error("Unlock requests are limited to five per minute."), { code: "UNLOCK_RATE_LIMITED" });
}

export function phase1SecretsFromForm(toolId: string, form: FormData): Phase1SecretPayload | undefined {
  if (!phase1SecretToolIds.has(toolId)) return undefined;
  const field = (name: string) => { const value = form.get(name); return typeof value === "string" ? value : ""; };
  if (toolId === "unlock-pdf") return validatePhase1Secrets("unlock-pdf", { password: field("password"), authorizedUseAcknowledged: field("authorizedUseAcknowledged") === "true" ? true : undefined });
  if (toolId === "protect-pdf") return validatePhase1Secrets("protect-pdf", { userPassword: field("userPassword"), ownerPassword: field("ownerPassword") });
  return validatePhase1Secrets("pdf-permissions", { userPassword: field("userPassword"), ownerPassword: field("ownerPassword") });
}
