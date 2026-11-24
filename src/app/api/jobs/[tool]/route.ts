import { randomUUID } from "crypto";
import { requireUser } from "@/lib/auth/user";
import { createToolJob } from "@/lib/jobs/orchestrator";
import { FormFillError, assertNoDuplicateJsonKeys, fieldsPayloadBytes } from "@/lib/pdf/form-validation";
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
    if (rawFields !== null) {
      // Exactly one `fields` part (FF-10). `form.get()` silently returns the
      // first of several parts, so a request that repeats the field would be
      // accepted under a value the client did not intend.
      if (form.getAll("fields").length !== 1 || typeof rawFields !== "string") return Response.json({ code: "FIELDS_INPUT_INVALID", message: "Form field values must be sent exactly once, as a JSON string." }, { status: 422 });
      if (rawFields) {
        // The limit is 64 KiB of **UTF-8**, not 64 Ki code units: Arabic text is
        // two bytes per character, so a `.length` check accepted 70 KB of
        // payload (FF-10).
        if (fieldsPayloadBytes(rawFields) > 64 * 1024) return Response.json({ code: "FIELDS_INPUT_INVALID", message: "Form field values exceed the 64 KB limit." }, { status: 422 });
        let parsed: unknown;
        // Duplicate object keys are rejected before `JSON.parse` can collapse
        // them and silently keep the last one.
        try { assertNoDuplicateJsonKeys(rawFields); parsed = JSON.parse(rawFields) as unknown; }
        catch (error) {
          const duplicate = error instanceof FormFillError && error.code === "FORM_VALUE_INVALID";
          return Response.json({ code: "FIELDS_INPUT_INVALID", message: duplicate ? "Form field values must not repeat a field name." : "Form field values are not valid JSON." }, { status: 422 });
        }
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return Response.json({ code: "FIELDS_INPUT_INVALID", message: "Form field values must be a JSON object." }, { status: 422 });
        fields = parsed as Record<string, unknown>;
      }
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
