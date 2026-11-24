import { randomUUID } from "crypto";
import { requireUser } from "@/lib/auth/user";
import { createToolJob } from "@/lib/jobs/orchestrator";
import { workerToolIds } from "@/lib/tools/registry";
import { UploadValidationError } from "@/lib/uploads/validation";
import { ToolOptionsValidationError } from "@/lib/tools/options";
import { phase1SecretsFromForm } from "@/lib/secrets/phase1";

export const runtime = "nodejs";
export async function POST(request: Request, { params }: { params: Promise<{ tool: string }> }) {
  const { tool } = await params;
  if (!workerToolIds.has(tool)) return Response.json({ code: "TOOL_NOT_WORKER_ENABLED", message: "This tool has not moved to the worker pipeline yet." }, { status: 409 });
  try {
    const user = await requireUser(); const form = await request.formData(); const files = form.getAll("files").filter((value): value is File => value instanceof File);
    const rawOptions = form.get("options"); let options: Record<string, string | number | boolean> = {};
    if (typeof rawOptions === "string" && rawOptions) { const parsed = JSON.parse(rawOptions) as unknown; if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("INVALID_OPTIONS"); options = parsed as Record<string, string | number | boolean>; }
    // `fields` is a typed per-field payload (see tools/options.ts). It is parsed
    // here only to hand it over as data; its shape and semantics are validated by
    // `parseFieldsPayload()` in the orchestrator and again in the worker.
    const rawFields = form.get("fields"); let fields: Record<string, unknown> | undefined;
    if (typeof rawFields === "string" && rawFields) {
      if (rawFields.length > 64 * 1024) return Response.json({ code: "FIELDS_INPUT_INVALID", message: "Form field values exceed the 64 KB limit." }, { status: 422 });
      let parsed: unknown;
      // Malformed JSON is a client error with a precise code, not an
      // INTERNAL_ERROR from the outer handler.
      try { parsed = JSON.parse(rawFields) as unknown; }
      catch { return Response.json({ code: "FIELDS_INPUT_INVALID", message: "Form field values are not valid JSON." }, { status: 422 }); }
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return Response.json({ code: "FIELDS_INPUT_INVALID", message: "Form field values must be a JSON object." }, { status: 422 });
      fields = parsed as Record<string, unknown>;
    }
    const idempotencyKey = request.headers.get("idempotency-key") ?? randomUUID(); const correlationId = request.headers.get("x-correlation-id") ?? randomUUID();
    const job = await createToolJob({ userId: user.id, toolId: tool, idempotencyKey, correlationId, options, ...(fields ? { fields } : {}), secrets: phase1SecretsFromForm(tool, form), uploads: await Promise.all(files.map(async (file) => ({ filename: file.name, mimeType: file.type, bytes: new Uint8Array(await file.arrayBuffer()) }))) });
    return Response.json({ jobId: job.id, status: job.status.toLowerCase(), correlationId, reused: job.reused }, { status: job.reused ? 200 : 202 });
  } catch (error) {
    const auth = error instanceof Error && error.message === "AUTH_REQUIRED"; const upload = error instanceof UploadValidationError; const options = error instanceof ToolOptionsValidationError;
    const coded = typeof error === "object" && error && "code" in error ? String(error.code) : undefined;
    const formError = coded === "FIELDS_INPUT_INVALID" || coded === "FORM_VALUE_INVALID" || coded === "FORM_UNSUPPORTED" || coded === "FORM_NOT_FOUND" || coded === "FORM_RESTRICTED";
    const message = formError && error instanceof Error ? error.message : auth ? "Sign in to process documents." : upload || options ? error.message : "Unable to queue tool job.";
    return Response.json({ code: auth ? "AUTH_REQUIRED" : upload ? error.code : options ? error.code : coded ?? "INTERNAL_ERROR", message }, { status: auth ? 401 : upload || options || coded === "SECRET_INPUT_INVALID" || formError ? 422 : coded === "UNLOCK_RATE_LIMITED" ? 429 : 400 });
  }
}
