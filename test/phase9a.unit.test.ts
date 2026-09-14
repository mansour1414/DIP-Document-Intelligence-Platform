import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { assertCanManageApi, assertMembershipChangeAllowed, BusinessAuthorizationError } from "../src/lib/business/policy";
import { apiKeyVerifier, bearerApiKey, generateApiKeyMaterial, parseApiKey, verifyApiKeySecret } from "../src/lib/api-platform/keys";
import { apiRequestHash } from "../src/lib/api-platform/idempotency";
import { principalFromApiKeyCandidate } from "../src/lib/api-platform/auth";
import { redactLogContext } from "../src/lib/logging";

test("API keys use random one-time plaintext and store only a verifier", () => {
  const first = generateApiKeyMaterial(); const second = generateApiKeyMaterial();
  assert.notEqual(first.plaintext, second.plaintext); assert.match(first.plaintext, /^dip_v1_[A-Za-z0-9_-]{16}_[A-Za-z0-9_-]{43}$/);
  const parsed = parseApiKey(first.plaintext)!; assert.equal(parsed.prefix, first.prefix); assert.equal(verifyApiKeySecret(parsed.secret, first.verifier), true); assert.equal(verifyApiKeySecret(parsed.secret, apiKeyVerifier("wrong")), false);
  assert.equal(parseApiKey("malformed"), null); assert.equal(bearerApiKey(`Bearer ${first.plaintext}`), first.plaintext); assert.equal(bearerApiKey(`Basic ${first.plaintext}`), null);
});

test("organization policy prevents member and self privilege escalation", () => {
  assert.throws(() => assertCanManageApi("MEMBER"), (error: unknown) => error instanceof BusinessAuthorizationError && error.code === "FORBIDDEN");
  assert.throws(() => assertMembershipChangeAllowed({ actorId: "u1", actorRole: "MEMBER", targetUserId: "u1", nextRole: "OWNER" }), /FORBIDDEN/);
  assert.throws(() => assertMembershipChangeAllowed({ actorId: "u1", actorRole: "ADMIN", targetUserId: "u1", currentRole: "ADMIN", nextRole: "OWNER" }), /PRIVILEGE_ESCALATION/);
  assert.throws(() => assertMembershipChangeAllowed({ actorId: "u1", actorRole: "ADMIN", targetUserId: "u2", currentRole: "MEMBER", nextRole: "ADMIN" }), /PRIVILEGE_ESCALATION/);
  assert.doesNotThrow(() => assertMembershipChangeAllowed({ actorId: "u1", actorRole: "OWNER", targetUserId: "u2", currentRole: "MEMBER", nextRole: "ADMIN" }));
});

test("API auth rejects unknown, revoked, expired, and inactive-client keys", () => {
  const secret = "s".repeat(43); const base = { key_id: crypto.randomUUID(), key_hash: apiKeyVerifier(secret), key_status: "ACTIVE", expires_at: null, api_client_id: crypto.randomUUID(), client_status: "ACTIVE", organization_id: crypto.randomUUID(), organization_status: "ACTIVE", execution_user_id: crypto.randomUUID(), scopes: ["jobs:create"] };
  assert.equal(principalFromApiKeyCandidate(secret, base).organizationId, base.organization_id);
  assert.throws(() => principalFromApiKeyCandidate(secret, undefined), /API_AUTHENTICATION_FAILED/);
  assert.throws(() => principalFromApiKeyCandidate("x".repeat(43), base), /API_AUTHENTICATION_FAILED/);
  assert.throws(() => principalFromApiKeyCandidate(secret, { ...base, key_status: "REVOKED" }), /API_AUTHENTICATION_FAILED/);
  assert.throws(() => principalFromApiKeyCandidate(secret, { ...base, client_status: "INACTIVE" }), /API_AUTHENTICATION_FAILED/);
  assert.throws(() => principalFromApiKeyCandidate(secret, { ...base, expires_at: new Date(0) }), /API_AUTHENTICATION_FAILED/);
});

test("API idempotency hash binds method, route and body", () => {
  const hash = apiRequestHash("POST", "/v1/jobs", "{}"); assert.equal(hash, apiRequestHash("post", "/v1/jobs", "{}")); assert.notEqual(hash, apiRequestHash("POST", "/v1/jobs", "{\"x\":1}")); assert.notEqual(hash, apiRequestHash("POST", "/v1/other", "{}"));
});

test("Phase 9A auth remains outside execution paths and logging redacts credentials", async () => {
  const root = new URL("../", import.meta.url); const auth = await readFile(new URL("src/lib/api-platform/auth.ts", root), "utf8"); const logging = await readFile(new URL("src/lib/logging.ts", root), "utf8");
  assert.doesNotMatch(auth, /queue|worker|createToolJob|startWorkflowRun|agent/i); assert.match(logging, /authorization/); assert.equal(redactLogContext({ authorization: "Bearer secret" }).authorization, "[REDACTED]"); assert.equal(redactLogContext({ api_key: "secret" }).api_key, "[REDACTED]");
});
