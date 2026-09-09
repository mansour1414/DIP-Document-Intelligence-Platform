import { createHash } from "crypto";
import { PDFDocument } from "pdf-lib";
import { getToolDefinition } from "@/lib/tools/registry";

export class UploadValidationError extends Error { constructor(public code: string, message: string) { super(message); } }
const signatures: Record<string, number[][]> = {
  "application/pdf": [[0x25, 0x50, 0x44, 0x46, 0x2d]],
  "image/jpeg": [[0xff, 0xd8, 0xff]], "image/png": [[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]],
  "application/msword": [[0xd0, 0xcf, 0x11, 0xe0]], "application/vnd.ms-excel": [[0xd0, 0xcf, 0x11, 0xe0]], "application/vnd.ms-powerpoint": [[0xd0, 0xcf, 0x11, 0xe0]],
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [[0x50, 0x4b, 0x03, 0x04]],
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [[0x50, 0x4b, 0x03, 0x04]],
  "application/vnd.openxmlformats-officedocument.presentationml.presentation": [[0x50, 0x4b, 0x03, 0x04]],
};
export async function validateUpload(input: { toolId: string; declaredMime: string; bytes: Uint8Array }) {
  const tool = getToolDefinition(input.toolId);
  if (!input.bytes.byteLength || input.bytes.byteLength > tool.limits.maxBytes) throw new UploadValidationError("SIZE_LIMIT_EXCEEDED", "File is empty or exceeds the tool size limit.");
  if (!tool.mime.input.includes(input.declaredMime)) throw new UploadValidationError("MIME_NOT_ALLOWED", "Declared MIME type is not accepted by this tool.");
  const matches = (signatures[input.declaredMime] ?? []).some((signature) => signature.every((byte, i) => input.bytes[i] === byte));
  const mimeType = matches ? input.declaredMime : undefined;
  if (!mimeType) throw new UploadValidationError("MAGIC_BYTES_INVALID", "File signature does not match an accepted format.");
  let pageCount: number | undefined;
  if (mimeType === "application/pdf") {
    try { pageCount = (await PDFDocument.load(input.bytes, { ignoreEncryption: false })).getPageCount(); } catch { throw new UploadValidationError("PDF_INVALID", "PDF cannot be parsed."); }
    if (tool.limits.maxPages && pageCount > tool.limits.maxPages) throw new UploadValidationError("PAGE_LIMIT_EXCEEDED", "PDF exceeds the page limit.");
  }
  return { mimeType, pageCount, checksum: createHash("sha256").update(input.bytes).digest("base64") };
}
