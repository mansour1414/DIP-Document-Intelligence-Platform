import { requireUser } from "@/lib/auth/user";
import { runtimeLimits } from "@/lib/runtime/config";
import { getToolDefinition } from "@/lib/tools/registry";
import { requireCleanUpload } from "@/lib/malware";
import { admitFormInspection, assertCheapPdfShape, inspectFormPdf, type InspectAdmission } from "@/lib/pdf/form-inspection";
import { FormFillError } from "@/lib/pdf/form-validation";
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

/**
 * Multipart framing overhead allowed on top of the PDF itself.
 *
 * A `multipart/form-data` body is bigger than the file it carries: the boundary
 * lines, the part headers and the terminating delimiter. 8 KiB covers any
 * realistic filename and boundary without letting the overhead itself become a
 * bypass of the byte limit.
 */
const MULTIPART_OVERHEAD_BYTES = 8 * 1024;

/**
 * Read the declared length before touching the body (FF-04).
 *
 * The review found `request.formData()` called first, so the *whole* multipart
 * body — up to the platform's own ceiling — was buffered into memory before the
 * 100 MiB check could reject it. A `Content-Length` header is attacker-supplied,
 * so it is only used to reject early: the real limit is still enforced on the
 * file's `size` after parsing. Both checks exist on purpose, and neither is a
 * substitute for the other.
 */
function declaredLength(request: Request) {
  const header = request.headers.get("content-length");
  if (!header) return undefined;
  const parsed = Number(header);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : undefined;
}

export async function POST(request: Request) {
  let admission: InspectAdmission | undefined;
  try {
    const user = await requireUser();
    const tool = getToolDefinition("fill-forms");
    const limitBytes = tool.limits.maxBytes;
    const declared = declaredLength(request);
    if (declared !== undefined && declared > limitBytes + MULTIPART_OVERHEAD_BYTES) {
      // Rejected before `formData()`: the body is never buffered.
      return Response.json({ code: "SIZE_LIMIT_EXCEEDED", message: "The PDF exceeds the size limit." }, { status: 422 });
    }
    // Per-tenant admission before the body is read, so a caller cannot queue
    // unbounded work ahead of the limits.
    admission = await admitFormInspection(user.id);
    const form = await request.formData();
    const file = form.get("file");
    if (!(file instanceof File)) return Response.json({ code: "VALIDATION_ERROR", message: "One PDF file is required." }, { status: 400 });
    if (file.size > limitBytes) return Response.json({ code: "SIZE_LIMIT_EXCEEDED", message: "The PDF exceeds the size limit." }, { status: 422 });
    if (file.size < 64) return Response.json({ code: "VALIDATION_ERROR", message: "The file is too small to be a PDF." }, { status: 422 });
    const bytes = new Uint8Array(await file.arrayBuffer());
    // Cheap, parser-free checks first: signature, trailer, page-marker count.
    assertCheapPdfShape(bytes);
    // Screening before the expensive parse, not after it. `requireCleanUpload`
    // caps the bytes with the configured scanner; a scan failure is a rejection
    // (the malware gate is never softened here).
    await requireCleanUpload(bytes);
    const started = performance.now();
    const inventory = await inspectFormPdf(bytes, { budgetMs: 20_000, maxPages: runtimeLimits.maxPages });
    recordMetric("fill_forms_inspect_ms", performance.now() - started, "ms", { tool_id: "fill-forms", status: "succeeded" });
    return Response.json({ inventory }, { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    const auth = error instanceof Error && error.message === "AUTH_REQUIRED";
    const known = error instanceof FormFillError;
    const coded = typeof error === "object" && error && "code" in error ? String(error.code) : undefined;
    if (!known) logger.warn("fill_forms.inspect_failed", { error_code: coded ?? "INSPECTION_FAILED" });
    // Client errors carry the allowlisted message; anything else is reported
    // with a generic one so an unexpected library message is never echoed.
    return Response.json(
      { code: auth ? "AUTH_REQUIRED" : known ? error.code : coded ?? "INSPECTION_FAILED", message: auth ? "Sign in to inspect a form." : known ? error.message : "The form could not be inspected." },
      { status: auth ? 401 : coded === "SIZE_LIMIT_EXCEEDED" ? 422 : 422 },
    );
  } finally {
    await admission?.release().catch(() => undefined);
  }
}
