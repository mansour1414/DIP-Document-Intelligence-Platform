import { randomUUID } from "crypto";

export type StorageObject = { key: string; contentType: string; size: number };
export interface ObjectStorage {
  createUploadKey(input: { userId: string; filename: string }): string;
  deleteObject(key: string): Promise<void>;
}

/** Provider-neutral contract. The production adapter targets S3-compatible APIs/R2. */
export const storage: ObjectStorage = {
  createUploadKey({ userId, filename }) {
    const safeName = filename.replace(/[^a-zA-Z0-9._-]/g, "_");
    return `uploads/${userId}/${randomUUID()}-${safeName}`;
  },
  async deleteObject() {
    throw new Error("No object-storage adapter is configured");
  },
};
