import Redis from "ioredis";
import pg from "pg";

const { Client } = pg;
const databaseUrl = process.env.DATABASE_URL;
const redisUrl = process.env.REDIS_URL;
if (!databaseUrl || !redisUrl) throw new Error("DATABASE_URL and REDIS_URL are required");

const deadline = Date.now() + 30_000;
let lastError;
while (Date.now() < deadline) {
  const database = new Client({ connectionString: databaseUrl, connectionTimeoutMillis: 2_000 });
  const redis = new Redis(redisUrl, { lazyConnect: true, connectTimeout: 2_000, commandTimeout: 2_000, maxRetriesPerRequest: 0, enableOfflineQueue: false });
  try {
    await database.connect();
    await database.query("SELECT 1");
    await redis.connect();
    if (await redis.ping() !== "PONG") throw new Error("Redis did not return PONG");
    const dbTarget = new URL(databaseUrl); const redisTarget = new URL(redisUrl);
    console.log(`Dependencies ready: postgres=${dbTarget.hostname}:${dbTarget.port || "5432"}, redis=${redisTarget.hostname}:${redisTarget.port || "6379"}`);
    await database.end(); await redis.quit(); process.exit(0);
  } catch (error) {
    lastError = error;
    await database.end().catch(() => undefined); redis.disconnect();
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
}
throw new Error(`Dependencies were not ready before deadline: ${lastError instanceof Error ? lastError.message : "unknown error"}`);
