const required = ["DATABASE_URL", "REDIS_URL", "NEXT_PUBLIC_APP_URL"] as const;

export type AppEnvironment = "development" | "test" | "production";

export function readEnvironment() {
  const environment = (process.env.NODE_ENV ?? "development") as AppEnvironment;
  const missing = required.filter((name) => !process.env[name]);
  if (environment === "production" && missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(", ")}`);
  }
  return {
    environment,
    databaseUrl: process.env.DATABASE_URL,
    redisUrl: process.env.REDIS_URL,
    appUrl: process.env.NEXT_PUBLIC_APP_URL ?? "http://localhost:3000",
    storage: {
      endpoint: process.env.STORAGE_ENDPOINT,
      bucket: process.env.STORAGE_BUCKET,
      accessKey: process.env.STORAGE_ACCESS_KEY,
      secretKey: process.env.STORAGE_SECRET_KEY,
    },
  };
}
