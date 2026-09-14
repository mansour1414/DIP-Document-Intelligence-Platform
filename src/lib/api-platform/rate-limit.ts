import { createHmac } from "node:crypto";
import { getReadyQueueConnection } from "@/lib/queue";
import type { ApiPrincipal } from "./auth";

const script = `
local client = redis.call('INCR', KEYS[1])
if client == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[3]) end
local organization = redis.call('INCR', KEYS[2])
if organization == 1 then redis.call('PEXPIRE', KEYS[2], ARGV[3]) end
local allowed = client <= tonumber(ARGV[1]) and organization <= tonumber(ARGV[2])
return {allowed and 1 or 0, client, organization, redis.call('PTTL', KEYS[1]), redis.call('PTTL', KEYS[2])}
`;
function identifier(kind: string, value: string) { return createHmac("sha256", process.env.RATE_LIMIT_KEY_SECRET ?? "development-only-rate-limit-secret").update(`${kind}:${value}`).digest("hex"); }

export async function consumeApiRateLimit(principal: ApiPrincipal, limits: { client: number; organization: number; windowMs: number }) {
  if (limits.client < 1 || limits.organization < 1 || limits.windowMs < 1000) throw new Error("INVALID_RATE_LIMIT");
  const bucket = Math.floor(Date.now() / limits.windowMs); const redis = await getReadyQueueConnection();
  const result = await redis.eval(script, 2, `dip:api:client:${identifier("client", principal.apiClientId)}:${bucket}`, `dip:api:organization:${identifier("organization", principal.organizationId)}:${bucket}`, limits.client, limits.organization, limits.windowMs) as number[];
  return { allowed: result[0] === 1, clientCount: result[1], organizationCount: result[2], retryAfterMs: Math.max(result[3], result[4], 0) };
}
