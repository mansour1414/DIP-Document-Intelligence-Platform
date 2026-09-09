import { randomUUID } from "crypto";
import { db } from "@/lib/db";
import { consumeCredits } from "@/lib/billing/credits";

export async function beginJob(input: { userId: string; toolId: string; filename: string; size?: number; mimeType?: string }) {
  await consumeCredits(input.userId, input.toolId, `tool:${input.toolId}`);
  const document = await db.document.create({ data: { userId: input.userId, title: input.filename.slice(0, 255), files: { create: { originalName: input.filename.slice(0, 255), mimeType: input.mimeType ?? "application/pdf", size: BigInt(input.size ?? 0), storageKey: `ephemeral/${randomUUID()}-${input.filename.slice(0, 80)}` } } }, select: { files: { select: { id: true } } } });
  return db.job.create({ data: { toolId: input.toolId, idempotencyKey: randomUUID(), requesterId: input.userId, inputFileId: document.files[0].id, status: "RUNNING", startedAt: new Date(), params: {} }, select: { id: true } });
}

export async function finishJob(id: string, success: boolean, error?: string) {
  return db.job.update({ where: { id }, data: { status: success ? "SUCCEEDED" : "FAILED", completedAt: new Date(), error: error ? { message: error } : undefined } });
}
