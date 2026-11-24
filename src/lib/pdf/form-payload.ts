/**
 * `fill-forms` — encrypted, tenant- and job-bound storage for submitted values.
 *
 * ## Why this exists (FF-03)
 *
 * The review found that a submitted `fields` map was written verbatim into
 * `Job.params` and stayed there forever. Every terminal state — SUCCEEDED,
 * FAILED, CANCELLED, EXPIRED — left the caller's actual values (a name, a
 * passport number, a salary) sitting in a durable JSON column, returned by the
 * status API and copied into any dump or backup of that table.
 *
 * The values now go to a short-lived encrypted envelope in the queue's Redis,
 * exactly as Phase 1 passwords already do (`src/lib/secrets/phase1.ts`): same
 * AES-256-GCM envelope, same key material, same AAD-binding idea. Only an opaque
 * reference is persisted in `Job.params`.
 *
 * ## Deliberate differences from `phase1.ts`
 *
 * `takePhase1Secret` uses Redis `GETDEL`: a password may be decrypted once and is
 * gone. That is right for a password and wrong here, because a fill job may
 * legitimately be retried (`attempts: 3`) or re-entered by a duplicate BullMQ
 * delivery after a worker restart. A destructive read would turn every retry
 * into a permanent failure, and two overlapping attempts would race for a single
 * copy. This module therefore reads **non-destructively**; the payload is
 * removed by the lifecycle (see `purgeFormFields`) or by the TTL backstop.
 *
 * ## Binding
 *
 * The AAD is `v1\0<tenantId>\0<jobId>\0fill-forms/fields`. A reference copied
 * from another tenant's job therefore fails authentication rather than returning
 * someone else's values, and the reference itself is a random UUID that carries
 * no information.
 *
 * ## TTL
 *
 * The TTL is `abandonedGraceMs()` for the current runtime configuration: the
 * exact window after which the approved retention sweep may declare the job
 * abandoned. Making the payload live *longer* than a job may legitimately wait
 * would only lengthen exposure; making it shorter would drop values for a
 * perfectly valid queued job. This coupling to retention policy is reported for
 * owner approval — see `docs/stage2-fill-forms.md`.
 */
import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from "node:crypto";
import { getReadyQueueConnection } from "@/lib/queue";
import { abandonedGraceMs } from "@/lib/retention/job-expiry";
import type { RawFieldMap } from "@/lib/pdf/form-types";

const PURPOSE = "fill-forms/fields";
const KEY_PREFIX = "dip:fill-forms-fields:v1:";

type Envelope = { v: 1; iv: string; tag: string; ciphertext: string };

/** Minimal store surface, injectable so tests never need Redis. */
export type FormPayloadStore = {
  /** `SET key value EX ttl NX`; must fail if the key exists. */
  set(key: string, value: string, ttlSeconds: number): Promise<void>;
  /** Plain `GET`. Never destructive: a retry must be able to read again. */
  get(key: string): Promise<string | null>;
  delete(key: string): Promise<void>;
};

function redisStore(): FormPayloadStore {
  return {
    async set(key, value, ttl) {
      const redis = await getReadyQueueConnection();
      const result = await redis.set(key, value, "EX", ttl, "NX");
      if (result !== "OK") throw unavailability("The form payload reference could not be stored.");
    },
    async get(key) { return (await getReadyQueueConnection()).get(key); },
    async delete(key) { await (await getReadyQueueConnection()).del(key); },
  };
}

function unavailability(message: string) {
  return Object.assign(new Error(message), { code: "FORM_PAYLOAD_UNAVAILABLE" });
}

/**
 * The approved 32-byte key, shared with Phase 1 secrets.
 *
 * Reusing the existing key avoids a new environment variable, a new secret to
 * rotate and a deployment change; separation between the two uses comes from the
 * AAD purpose, so an envelope cannot be moved between them even with the same
 * key. Introducing a separate key would be an operational change and is listed
 * as a decision for the owner.
 */
function keyBytes(value = process.env.PHASE1_SECRET_ENCRYPTION_KEY) {
  if (!value || !/^[A-Za-z0-9+/]{43}=$/u.test(value)) throw unavailability("Form payload encryption is not configured.");
  const bytes = Buffer.from(value, "base64");
  if (bytes.byteLength !== 32) throw unavailability("The form payload encryption key must be 32 base64-encoded bytes.");
  return bytes;
}

const aad = (tenantId: string, jobId: string) => Buffer.from(`v1\0${tenantId}\0${jobId}\0${PURPOSE}`);

/** Payload lifetime in seconds: the approved abandoned-job grace. */
export function formPayloadTtlSeconds() {
  return Math.max(60, Math.ceil(abandonedGraceMs() / 1_000));
}

/**
 * Encrypt `fields` for one job and return the opaque reference.
 *
 * The caller stores the *reference* in `Job.params` and nothing else.
 */
export async function putFormFields(
  input: { tenantId: string; jobId: string; fields: RawFieldMap },
  store: FormPayloadStore = redisStore(),
): Promise<string> {
  const reference = randomUUID();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", keyBytes(), iv);
  cipher.setAAD(aad(input.tenantId, input.jobId));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(input.fields), "utf8"), cipher.final()]);
  const envelope: Envelope = { v: 1, iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), ciphertext: ciphertext.toString("base64") };
  await store.set(KEY_PREFIX + reference, JSON.stringify(envelope), formPayloadTtlSeconds());
  return reference;
}

/**
 * Decrypt the values for one job.
 *
 * Non-destructive by design: the payload survives every retry of the same job
 * and concurrent attempts read the same copy. `tenantId` and `jobId` are bound
 * into the AAD, so a reference from a different tenant or job fails
 * authentication instead of yielding foreign data.
 */
export async function readFormFields(
  input: { reference: string; tenantId: string; jobId: string },
  store: FormPayloadStore = redisStore(),
): Promise<RawFieldMap> {
  const encoded = await store.get(KEY_PREFIX + input.reference);
  if (!encoded) throw Object.assign(new Error("The form values are no longer available."), { code: "FORM_PAYLOAD_EXPIRED" });
  let envelope: Envelope;
  try {
    envelope = JSON.parse(encoded) as Envelope;
    if (envelope.v !== 1) throw new Error("version");
  } catch { throw Object.assign(new Error("The form values could not be read."), { code: "FORM_PAYLOAD_INVALID" }); }
  try {
    const decipher = createDecipheriv("aes-256-gcm", keyBytes(), Buffer.from(envelope.iv, "base64"));
    decipher.setAAD(aad(input.tenantId, input.jobId));
    decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
    const plaintext = Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, "base64")), decipher.final()]).toString("utf8");
    return JSON.parse(plaintext) as RawFieldMap;
  } catch {
    // Wrong tenant, wrong job, tampered envelope and wrong key all land here.
    throw Object.assign(new Error("The form values could not be authenticated."), { code: "FORM_PAYLOAD_INVALID" });
  }
}

/**
 * Remove the payload. Idempotent: every lifecycle path may call it, including
 * ones that race with a successful purge elsewhere.
 */
export async function purgeFormFields(reference: string | undefined, store: FormPayloadStore = redisStore()) {
  if (!reference) return;
  await store.delete(KEY_PREFIX + reference);
}
