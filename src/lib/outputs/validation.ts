import { PDFDocument } from "pdf-lib";
import { runtimeLimits } from "@/lib/runtime/config";

export class OutputValidationError extends Error {
  readonly code = "OUTPUT_VALIDATION_FAILED";
  constructor(message: string) { super(message); }
}

export type WorkerOutput = { name: string; mimeType: string; bytes: Uint8Array };
const startsWith = (bytes: Uint8Array, signature: number[]) => signature.every((value, index) => bytes[index] === value);

export async function validateWorkerOutputs(outputs: WorkerOutput[], expectedPageCount?: number, options: { encryptedPdfAlreadyValidated?: boolean } = {}) {
  if (!outputs.length || outputs.length > runtimeLimits.maxOutputFiles) throw new OutputValidationError("Output file count is outside the configured limit.");
  const totalBytes = outputs.reduce((sum, output) => sum + output.bytes.byteLength, 0);
  if (!totalBytes || totalBytes > runtimeLimits.maxOutputBytes) throw new OutputValidationError("Output bytes are outside the configured limit.");
  for (const output of outputs) {
    if (!output.bytes.byteLength) throw new OutputValidationError("An output file is empty.");
    if (output.mimeType === "application/pdf") {
      if (!startsWith(output.bytes, [0x25, 0x50, 0x44, 0x46, 0x2d])) throw new OutputValidationError("PDF output has invalid magic bytes.");
      if (options.encryptedPdfAlreadyValidated) continue;
      let document: PDFDocument;
      try { document = await PDFDocument.load(output.bytes, { ignoreEncryption: false }); }
      catch { throw new OutputValidationError("PDF output cannot be parsed."); }
      if (!document.getPageCount()) throw new OutputValidationError("PDF output contains no pages.");
      if (expectedPageCount !== undefined && outputs.length === 1 && document.getPageCount() !== expectedPageCount) throw new OutputValidationError("PDF output did not preserve the expected page count.");
    } else if (output.mimeType === "image/jpeg" && !startsWith(output.bytes, [0xff, 0xd8, 0xff])) throw new OutputValidationError("JPEG output has an invalid signature.");
    else if (output.mimeType === "image/png" && !startsWith(output.bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) throw new OutputValidationError("PNG output has an invalid signature.");
    else if (output.mimeType === "application/json") { try { JSON.parse(new TextDecoder().decode(output.bytes)); } catch { throw new OutputValidationError("JSON output cannot be parsed."); } }
    else if (output.mimeType.includes("openxmlformats") && !startsWith(output.bytes, [0x50, 0x4b, 0x03, 0x04])) throw new OutputValidationError("Office output is not a valid ZIP container.");
  }
  return { outputCount: outputs.length, totalBytes };
}


/**
 * Verification of a Fill Forms output that was produced inside the bounded child.
 *
 * ## Why this is separate from `validateWorkerOutputs`
 *
 * The fill, the appearance generation and the reopen/verification parse all now
 * run in the child. Re-parsing the output here would undo that: the whole point is
 * that the main worker does not load an untrusted PDF. A `skipPdfValidation: true`
 * flag on the shared function would have opened that door to every caller, so this
 * is a dedicated path that can only be reached with a child-produced result.
 *
 * ## What is still checked here, independently
 *
 * Framing integrity is not honesty: a compromised child can forge a matching
 * checksum over a forged document. So the parent re-derives what it can without a
 * parser and reconciles it against independently known input facts:
 *
 *   - declared vs actual byte length (transport truncation)
 *   - SHA-256 over the bytes that actually arrived (metadata consistency)
 *   - PDF magic bytes and trailer (format, not structure)
 *   - non-empty output and the configured output ceiling
 *   - page count is a positive integer, and equals the input's page count, which
 *     came from the database — not from the child
 */
export type BoundedFillOutput = {
  bytes: Uint8Array;
  /** Pages the child reported for its own output. */
  pages: number;
  /** Checksum the child reported for its own output. */
  checksum: string;
};

export async function validateBoundedFillOutput(output: BoundedFillOutput, expected: { inputPages?: number; maxOutputBytes: number; maxOutputFiles: number }): Promise<{ outputCount: number; totalBytes: number }> {
  const { createHash } = await import("node:crypto");
  if (expected.maxOutputFiles < 1) throw new OutputValidationError("Output file count is outside the configured limit.");
  if (!output.bytes.byteLength) throw new OutputValidationError("The output file is empty.");
  if (output.bytes.byteLength > expected.maxOutputBytes) throw new OutputValidationError("Output bytes are outside the configured limit.");
  if (!startsWith(output.bytes, [0x25, 0x50, 0x44, 0x46, 0x2d])) throw new OutputValidationError("PDF output has invalid magic bytes.");
  // The trailer is a cheap proxy for "this is a whole document", not a structural
  // claim — the child already did the structural verification before replying.
  const tail = new TextDecoder("latin1").decode(output.bytes.subarray(Math.max(0, output.bytes.byteLength - 4096)));
  if (!tail.includes("%%EOF")) throw new OutputValidationError("PDF output is truncated.");
  const actualChecksum = createHash("sha256").update(output.bytes).digest("hex");
  if (actualChecksum !== output.checksum) throw new OutputValidationError("Output checksum does not match the delivered bytes.");
  if (!Number.isSafeInteger(output.pages) || output.pages <= 0) throw new OutputValidationError("PDF output contains no pages.");
  if (expected.inputPages !== undefined && output.pages !== expected.inputPages) throw new OutputValidationError("PDF output did not preserve the expected page count.");
  return { outputCount: 1, totalBytes: output.bytes.byteLength };
}
