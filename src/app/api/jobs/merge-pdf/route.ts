import { randomUUID } from "crypto";
import { requireUser } from "@/lib/auth/user";
import { createMergePdfJob } from "@/lib/jobs/orchestrator";
import { UploadValidationError } from "@/lib/uploads/validation";

export const runtime = "nodejs";
export async function POST(request: Request) {
  try {
    const user = await requireUser(); const form = await request.formData();
    const files = form.getAll("files").filter((value): value is File => value instanceof File);
    const idempotencyKey = request.headers.get("idempotency-key") ?? randomUUID();
    const correlationId = request.headers.get("x-correlation-id") ?? randomUUID();
    const job = await createMergePdfJob({ userId: user.id, idempotencyKey, correlationId, uploads: await Promise.all(files.map(async (file) => ({ filename: file.name, mimeType: file.type, bytes: new Uint8Array(await file.arrayBuffer()) }))) });
    return Response.json({ jobId: job.id, status: job.status.toLowerCase(), correlationId, reused: job.reused }, { status: job.reused ? 200 : 202 });
  } catch (error) {
    const auth = error instanceof Error && error.message === "AUTH_REQUIRED";
    const known = error instanceof UploadValidationError;
    return Response.json({ code: auth ? "AUTH_REQUIRED" : known ? error.code : error instanceof Error ? error.message : "INTERNAL_ERROR", message: auth ? "Sign in to process documents." : known ? error.message : "Unable to queue merge job." }, { status: auth ? 401 : known ? 422 : 400 });
  }
}
