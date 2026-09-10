import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { config } from "dotenv";

config({ path: ".env.local", override: false });

test("Neon Object Storage supports real put/get/delete", { skip: process.env.RUN_STORAGE_E2E !== "1" }, async () => {
  const { getStorage, closeStorage } = await import("../src/lib/storage/index");
  const storage = getStorage();
  const key = `temporary/e2e/${crypto.randomUUID()}.txt`;
  const bytes = new TextEncoder().encode("dip-object-storage-e2e");
  const checksum = createHash("sha256").update(bytes).digest("base64");
  try {
    await storage.put({ key, bytes, contentType: "text/plain", checksum });
    assert.equal(await storage.exists(key), true);
    const metadata = await storage.head(key);
    assert.equal(metadata?.contentType, "text/plain");
    assert.equal(metadata?.size, bytes.byteLength);
    if (metadata?.checksum) assert.equal(metadata.checksum, checksum);
    assert.deepEqual(await storage.get(key), bytes);
    await storage.deleteObject(key);
    assert.equal(await storage.exists(key), false);
  } finally {
    await storage.deleteObject(key).catch(() => undefined);
    await closeStorage();
  }
});
