import { randomUUID } from "crypto";
import { requireUser } from "@/lib/auth/user";
import { createToolJob } from "@/lib/jobs/orchestrator";
import { workerToolIds } from "@/lib/tools/registry";
import { UploadValidationError } from "@/lib/uploads/validation";

export const runtime = "nodejs";
export async function POST(request: Request, { params }: { params: Promise<{ tool: string }> }) {
  const { tool } = await params;
  if (!workerToolIds.has(tool)) return Response.json({ code: "TOOL_NOT_WORKER_ENABLED", message: "This tool has not moved to the worker pipeline yet." }, { status: 409 });
  try {
    const user = await requireUser(); const form = await request.formData(); const files = form.getAll("files").filter((value): value is File => value instanceof File);
    const rawOptions = form.get("options"); let options: Record<string, string | number | boolean> = {};
    if (typeof rawOptions === "string" && rawOptions) { const parsed = JSON.parse(rawOptions) as unknown; if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("INVALID_OPTIONS"); options = parsed as Record<string, string | number | boolean>; }
    const idempotencyKey = request.headers.get("idempotency-key") ?? randomUUID(); const correlationId = request.headers.get("x-correlation-id") ?? randomUUID();
    const job = await createToolJob({ userId: user.id, toolId: tool, idempotencyKey, correlationId, options, uploads: await Promise.all(files.map(async (file) => ({ filename: file.name, mimeType: file.type, bytes: new Uint8Array(await file.arrayBuffer()) }))) });
    return Response.json({ jobId: job.id, status: job.status.toLowerCase(), correlationId, reused: job.reused }, { status: job.reused ? 200 : 202 });
  } catch (error) {
    const auth = error instanceof Error && error.message === "AUTH_REQUIRED"; const known = error instanceof UploadValidationError;
    return Response.json({ code: auth ? "AUTH_REQUIRED" : known ? error.code : error instanceof Error ? error.message : "INTERNAL_ERROR", message: auth ? "Sign in to process documents." : known ? error.message : "Unable to queue tool job." }, { status: auth ? 401 : known ? 422 : 400 });
  }
}
