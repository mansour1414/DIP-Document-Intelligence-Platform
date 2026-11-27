/**
 * Upload validation, split into two stages so that no untrusted document is
 * parsed on the API thread.
 *
 * ## Why two stages
 *
 * The single `validateUpload` mixed parser-free checks with `PDFDocument.load()`.
 * That made the *only* entry point a parser entry point, so any caller that
 * needed a page count necessarily parsed. Worse, for Fill Forms it parsed *before*
 * the bounded inspection child, defeating the isolation the tool relies on.
 *
 * - **Stage 1** — `validateUploadBytes`: size, declared MIME, magic bytes. No
 *   parser. Cheap enough to run before malware screening.
 * - **Stage 2** — `validateInspectedPdf`: consumes the isolated inspection result,
 *   enforces page limits against it, and carries the authoritative count forward.
 *   It never parses and never guesses.
 *
 * ## What each tool does
 *
 * - `fill-forms` — stage 1 here, page count from the bounded child (stage 2).
 * - `repair-pdf` / `unlock-pdf` — stage 1 here only; their legitimate input is
 *   damaged or undecryptable, so the worker decides what the document is.
 * - Everything else — stage 1 here, then `validateUploadWithParse` for the page
 *   count. That in-process parse is **residual shared exposure**, recorded rather
 *   than silently preserved or silently removed: converting every ordinary tool to
 *   the isolated child is a larger change than this round authorises.
 */
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

/** What the parser-free stage establishes. */
export type ByteValidation = {
  mimeType: string;
  checksum: string;
  pageCount?: number;
  /** True when the worker, not this process, must decide what the document is. */
  controlledWorkerPreflight?: true;
};

/**
 * A positive, safe-integer page count.
 *
 * `0` is rejected on purpose: an empty document is not a document whose page
 * count is merely unknown. Accepting it would let `pageCount ?? 0` downstream
 * turn "no pages" into a quota pass.
 */
export function assertAuthoritativePages(value: unknown, source: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new UploadValidationError("PAGE_LIMIT_EXCEEDED", `The document page count from ${source} is not a positive whole number.`);
  }
  return value;
}

/**
 * Stage 1 — parser-free. Size, declared MIME and magic bytes only.
 *
 * Safe to call before malware screening: it allocates nothing proportional to the
 * document and never invokes a parser.
 */
export function validateUploadBytes(input: { toolId: string; declaredMime: string; bytes: Uint8Array }): ByteValidation {
  const tool = getToolDefinition(input.toolId);
  if (!input.bytes.byteLength || input.bytes.byteLength > tool.limits.maxBytes) throw new UploadValidationError("SIZE_LIMIT_EXCEEDED", "File is empty or exceeds the tool size limit.");
  if (!tool.mime.input.includes(input.declaredMime)) throw new UploadValidationError("MIME_NOT_ALLOWED", "Declared MIME type is not accepted by this tool.");
  const matches = (signatures[input.declaredMime] ?? []).some((signature) => signature.every((byte, index) => input.bytes[index] === byte));
  if (!matches) throw new UploadValidationError("MAGIC_BYTES_INVALID", "File signature does not match an accepted format.");
  const checksum = createHash("sha256").update(input.bytes).digest("base64");
  // The tools whose structural verdict belongs to the worker.
  if (input.declaredMime === "application/pdf" && controlledPreflightToolIds.has(input.toolId)) {
    return { mimeType: input.declaredMime, checksum, controlledWorkerPreflight: true };
  }
  return { mimeType: input.declaredMime, checksum };
}

/**
 * Stage 2 — consume the isolated inspection result.
 *
 * Enforces the registry page limit against the child's own count and returns it
 * for file metadata and plan enforcement. A missing count is a refusal, not an
 * undefined to be defaulted later.
 */
export function validateInspectedPdf(input: { toolId: string; bytes: Uint8Array; bytes_: ByteValidation; inspectedPages: number }): ByteValidation & { pageCount: number } {
  const tool = getToolDefinition(input.toolId);
  const pages = assertAuthoritativePages(input.inspectedPages, "isolated inspection");
  if (tool.limits.maxPages && pages > tool.limits.maxPages) throw new UploadValidationError("PAGE_LIMIT_EXCEEDED", "PDF exceeds the page limit.");
  return { ...input.bytes_, pageCount: pages };
}

/**
 * The page-counting parse for tools that are not isolated.
 *
 * Named explicitly so its residual risk is visible at every call site rather than
 * hidden inside a function called "validate".
 */
export async function validateUploadWithParse(input: { toolId: string; declaredMime: string; bytes: Uint8Array }): Promise<ByteValidation> {
  const stage1 = validateUploadBytes(input);
  if (stage1.mimeType !== "application/pdf" || stage1.controlledWorkerPreflight) return stage1;
  const tool = getToolDefinition(input.toolId);
  if (isolatedInspectionToolIds.has(input.toolId)) {
    // Never reached by the orchestrator, which always supplies an inspection
    // result; reaching it means a caller wired the boundary wrongly. Fail closed
    // rather than quietly parsing the document it was supposed to isolate.
    throw new UploadValidationError("PDF_INVALID", "This tool requires an isolated inspection result and must not be validated by parsing.");
  }
  let pageCount: number;
  try { pageCount = (await PDFDocument.load(input.bytes, { ignoreEncryption: false })).getPageCount(); }
  catch { throw new UploadValidationError("PDF_INVALID", "PDF cannot be parsed."); }
  if (!pageCount) throw new UploadValidationError("PDF_INVALID", "PDF contains no pages.");
  if (tool.limits.maxPages && pageCount > tool.limits.maxPages) throw new UploadValidationError("PAGE_LIMIT_EXCEEDED", "PDF exceeds the page limit.");
  return { ...stage1, pageCount };
}
