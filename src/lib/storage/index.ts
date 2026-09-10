import { randomUUID } from "crypto";
import { DeleteObjectCommand, GetObjectCommand, HeadObjectCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { readEnvironment } from "@/lib/env";
import { runtimeLimits } from "@/lib/runtime/config";
import { measure } from "@/lib/observability/metrics";

export type StoredObject = { key: string; bucket: string; contentType: string; size: number; checksum?: string };
export interface ObjectStorage {
  createUploadKey(input: { userId: string; filename: string; scope?: "input" | "output" | "temporary" }): string;
  put(input: { key: string; bytes: Uint8Array; contentType: string; checksum?: string }): Promise<StoredObject>;
  get(key: string): Promise<Uint8Array>;
  exists(key: string): Promise<boolean>;
  deleteObject(key: string): Promise<void>;
}

function safeName(filename: string) { return filename.replace(/[^a-zA-Z0-9._-]/g, "_").slice(-160) || "file"; }

/** Provider-neutral S3 contract. Neon Storage, R2, MinIO and AWS share this adapter. */
export function createS3Storage(): ObjectStorage {
  const config = readEnvironment().storage;
  if (!config.bucket) throw new Error("STORAGE_NOT_CONFIGURED");
  const bucket = config.bucket;
  const client = new S3Client({ endpoint: config.endpoint, region: config.region, forcePathStyle: true, credentials: config.accessKey && config.secretKey ? { accessKeyId: config.accessKey, secretAccessKey: config.secretKey } : undefined });
  async function withAbort<T>(operation: "read" | "write" | "head" | "delete", work: (signal: AbortSignal) => Promise<T>) {
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), runtimeLimits.storageTimeoutMs); timer.unref?.();
    try { return await measure(`storage_${operation}_latency`, {}, () => work(controller.signal)); }
    finally { clearTimeout(timer); }
  }
  return {
    createUploadKey({ userId, filename, scope = "input" }) { return `${scope}/${userId}/${randomUUID()}-${safeName(filename)}`; },
    async put({ key, bytes, contentType, checksum }) { await withAbort("write", (abortSignal) => client.send(new PutObjectCommand({ Bucket: bucket, Key: key, Body: bytes, ContentType: contentType, ChecksumSHA256: checksum }), { abortSignal })); return { key, bucket, contentType, size: bytes.byteLength, checksum }; },
    async get(key) { const response = await withAbort("read", (abortSignal) => client.send(new GetObjectCommand({ Bucket: config.bucket, Key: key }), { abortSignal })); return response.Body?.transformToByteArray() ?? new Uint8Array(); },
    async exists(key) { try { await withAbort("head", (abortSignal) => client.send(new HeadObjectCommand({ Bucket: config.bucket, Key: key }), { abortSignal })); return true; } catch { return false; } },
    async deleteObject(key) { await withAbort("delete", (abortSignal) => client.send(new DeleteObjectCommand({ Bucket: config.bucket, Key: key }), { abortSignal })); },
  };
}
let configuredStorage: ObjectStorage | undefined;
export function getStorage() { return configuredStorage ??= createS3Storage(); }
