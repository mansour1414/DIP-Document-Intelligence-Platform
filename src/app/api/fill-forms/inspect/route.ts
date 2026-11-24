import { requireUser } from "@/lib/auth/user";
import { runtimeLimits } from "@/lib/runtime/config";
import { getToolDefinition } from "@/lib/tools/registry";
import { validateUpload } from "@/lib/uploads/validation";
import { requireCleanUpload } from "@/lib/malware";
import { inspectFormPdf } from "@/lib/pdf/form-fill";
import { FormFillError } from "@/lib/pdf/form-schema";
import { logger } from "@/lib/logging";
import { recordMetric } from "@/lib/observability/metrics";

/**
 * Read-only AcroForm inspection for the `fill-forms` workspace.
 *
 * The browser needs the field list — names, types, current values, options,
 * read-only/required flags — to render the interface. It must not *parse the PDF
 * itself* for anything that turns into a write later, and it must not receive
 * bytes back. This route therefore runs the very same inventory code the worker
 * will run, against a malware-scanned upload, and returns only descriptors.
 *
 * Nothing is persisted: no job, no storage object, no file row. The browser then
 * submits the *same* file to `POST /api/jobs/fill-forms`, where the worker
 * re-reads the inventory and validates every submitted value against it, so a
 * tampered descriptor list cannot influence the output.
 */
export const runtime = "nodejs";
export const maxDuration = 60;

export async function POST(request: Request) {
  try {
    await requireUser();
    const form = await request.formData();
    const file = form.get("file");
    if (!(file instanceof File)) return Response.json({ code: "VALIDATION_ERROR", message: "One PDF file is required." }, { status: 400 });
    if (file.size > getToolDefinition("fill-forms").limits.maxBytes) return Response.json({ code: "SIZE_LIMIT_EXCEEDED", message: "The PDF exceeds the size limit." }, { status: 422 });
    const bytes = new Uint8Array(await file.arrayBuffer());
    const validation = await validateUpload({ toolId: "fill-forms", declaredMime: file.type || "application/pdf", bytes });
    if (validation.pageCount && validation.pageCount > runtimeLimits.maxPages) return Response.json({ code: "PAGE_LIMIT_EXCEEDED", message: "The PDF exceeds the page limit." }, { status: 422 });
    await requireCleanUpload(bytes);
    const started = performance.now();
    const inventory = await inspectFormPdf(bytes);
    recordMetric("fill_forms_inspect_ms", performance.now() - started, "ms", { tool_id: "fill-forms", status: "succeeded" });
    return Response.json({ inventory }, { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    const auth = error instanceof Error && error.message === "AUTH_REQUIRED";
    const known = error instanceof FormFillError;
    const coded = typeof error === "object" && error && "code" in error ? String(error.code) : undefined;
    if (!known) logger.warn("fill_forms.inspect_failed", { error_code: coded ?? "INSPECTION_FAILED" });
    return Response.json(
      { code: auth ? "AUTH_REQUIRED" : known ? error.code : coded ?? "INSPECTION_FAILED", message: auth ? "Sign in to inspect a form." : known ? error.message : "The form could not be inspected." },
      { status: auth ? 401 : 422 },
    );
  }
}
