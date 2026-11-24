import { createHash } from "crypto";
import { PDFDocument } from "pdf-lib";
import { controlledPreflightToolIds, getToolDefinition, isolatedInspectionToolIds } from "@/lib/tools/registry";

export class UploadValidationError extends Error { constructor(public code: string, message: string) { super(message); } }
const signatures: Record<string, number[][]> = {
  "application/pdf": [[0x25, 0x50, 0x44, 0x46, 0x2d]],
  "image/jpeg": [[0xff, 0xd8, 0xff]], "image/png": [[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]],
  "application/msword": [[0xd0, 0xcf, 0x11, 0xe0]], "application/vnd.ms-excel": [[0xd0, 0xcf, 0x11, 0xe0]], "application/vnd.ms-powerpoint": [[0xd0, 0xcf, 0x11, 0xe0]],
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [[0x50, 0x4b, 0x03, 0x04]],
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [[0x50, 0x4b, 0x03, 0x04]],
  "application/vnd.openxmlformats-officedocument.presentationml.presentation": [[0x50, 0x4b, 0x03, 0x04]],
};
/**
 * Validate one upload and, where required, derive its page count.
 *
 * ## Where parsing is allowed to happen
 *
 * This function runs inside the API process, so `PDFDocument.load()` here is
 * *untrusted input parsed with the web server's privileges*. Only tools whose
 * structural risk is already bounded may parse here. Two groups are exempt:
 *
 * - `controlledPreflightToolIds` (Repair PDF, Unlock PDF): their legitimate input
 *   is damaged or undecryptable, so parsing cannot be their gate.
 * - `isolatedInspectionToolIds` (Fill Forms): parsing happened in-process *before*
 *   this function's caller reached its own bounded child, which defeated that
 *   isolation. Fill Forms now carries its authoritative page count from the
 *   isolated inspection instead (see `inspectionPages`).
 *
 * Everything else — ordinary PDF tools — is deliberately unchanged here. Their
 * shared parser exposure is a separate, tracked finding (B31-01 residual); removing
 * it is a larger change than this correction authorises.
 */
export async function validateUpload(input: { toolId: string; declaredMime: string; bytes: Uint8Array; inspectionPages?: number }) {
  const tool = getToolDefinition(input.toolId);
  if (!input.bytes.byteLength || input.bytes.byteLength > tool.limits.maxBytes) throw new UploadValidationError("SIZE_LIMIT_EXCEEDED", "File is empty or exceeds the tool size limit.");
  if (!tool.mime.input.includes(input.declaredMime)) throw new UploadValidationError("MIME_NOT_ALLOWED", "Declared MIME type is not accepted by this tool.");
  const matches = (signatures[input.declaredMime] ?? []).some((signature) => signature.every((byte, i) => input.bytes[i] === byte));
  const mimeType = matches ? input.declaredMime : undefined;
  if (!mimeType) throw new UploadValidationError("MAGIC_BYTES_INVALID", "File signature does not match an accepted format.");
  let pageCount: number | undefined;
  if (mimeType === "application/pdf") {
    const controlledWorkerPreflight = controlledPreflightToolIds.has(input.toolId);
    if (controlledWorkerPreflight) return { mimeType, pageCount, checksum: createHash("sha256").update(input.bytes).digest("base64"), controlledWorkerPreflight: true };
    // Fill Forms: the parse already happened in the bounded child, so this process
    // must not load the document. The caller supplies that authoritative count.
    // It is always a number on the orchestrator's path: `assertFillableInput` returns
    // only after `processPdfBounded` has rejected a non-integer or negative `pages`,
    // and a failed inspection throws before validation is reached. A missing value is
    // therefore an unknown count, not a zero — it is left undefined rather than
    // coerced, because `pageCount ?? 0` downstream would silently clear a page limit.
    if (isolatedInspectionToolIds.has(input.toolId)) {
      const inspectionPages = input.inspectionPages;
      if (inspectionPages !== undefined && (!Number.isInteger(inspectionPages) || inspectionPages < 0)) throw new UploadValidationError("PDF_INVALID", "PDF page count is invalid.");
      if (inspectionPages !== undefined && tool.limits.maxPages && inspectionPages > tool.limits.maxPages) throw new UploadValidationError("PAGE_LIMIT_EXCEEDED", "PDF exceeds the page limit.");
      return { mimeType, pageCount: inspectionPages, checksum: createHash("sha256").update(input.bytes).digest("base64") };
    }
    try { pageCount = (await PDFDocument.load(input.bytes, { ignoreEncryption: false })).getPageCount(); } catch { throw new UploadValidationError("PDF_INVALID", "PDF cannot be parsed."); }
    if (tool.limits.maxPages && pageCount > tool.limits.maxPages) throw new UploadValidationError("PAGE_LIMIT_EXCEEDED", "PDF exceeds the page limit.");
  }
  return { mimeType, pageCount, checksum: createHash("sha256").update(input.bytes).digest("base64") };
}
