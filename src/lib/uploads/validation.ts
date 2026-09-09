import { createHash } from "crypto";
import { PDFDocument } from "pdf-lib";
import { getToolDefinition } from "@/lib/tools/registry";

export class UploadValidationError extends Error { constructor(public code: string, message: string) { super(message); } }
const signatures: Record<string, number[]> = { "application/pdf": [0x25, 0x50, 0x44, 0x46, 0x2d] };
export async function validateUpload(input: { toolId: string; declaredMime: string; bytes: Uint8Array }) {
  const tool = getToolDefinition(input.toolId);
  if (!input.bytes.byteLength || input.bytes.byteLength > tool.limits.maxBytes) throw new UploadValidationError("SIZE_LIMIT_EXCEEDED", "File is empty or exceeds the tool size limit.");
  const mimeType = tool.mime.input.find((mime) => signatures[mime]?.every((byte, i) => input.bytes[i] === byte));
  if (!mimeType) throw new UploadValidationError("MAGIC_BYTES_INVALID", "File signature does not match an accepted format.");
  if (input.declaredMime && input.declaredMime !== mimeType) throw new UploadValidationError("MIME_MISMATCH", "Declared MIME type does not match file content.");
  let pageCount: number | undefined;
  try { pageCount = (await PDFDocument.load(input.bytes, { ignoreEncryption: false })).getPageCount(); } catch { throw new UploadValidationError("PDF_INVALID", "PDF cannot be parsed."); }
  if (tool.limits.maxPages && pageCount > tool.limits.maxPages) throw new UploadValidationError("PAGE_LIMIT_EXCEEDED", "PDF exceeds the page limit.");
  return { mimeType, pageCount, checksum: createHash("sha256").update(input.bytes).digest("base64") };
}
