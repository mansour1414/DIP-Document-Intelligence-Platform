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

