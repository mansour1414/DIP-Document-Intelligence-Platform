/**
 * Bounded child entry for untrusted PDF parsing (see `form-worker.ts`).
 *
 * Reads one document from stdin, replies with exactly one JSON line on stdout,
 * and never writes anything else there — the parent parses the last non-empty
 * line and treats anything else as a protocol failure.
 *
 * Everything the parent needs is derived from **one** parse:
 *
 *   1. cheap, parser-free shape checks (signature, trailer, page markers);
 *   2. one `PDFDocument.load`;
 *   3. the structural restriction walk over the object graph;
 *   4. the AcroForm inventory.
 *
 * The previous route loaded the document three times (probe, budget re-parse,
 * inventory). Consolidating that here removes the redundant parses the architect
 * flagged, and makes "the bytes were checked" and "the bytes were parsed" refer
 * to the same object graph rather than three separately-timed reads.
 *
 * Failures are reported as data, not as crashes: a rejected document must reach
 * the caller as a coded result with an allowlisted message. Only a genuine bug or
 * an out-of-memory abort ends the process without a JSON line.
 */
import { PDFDocument } from "pdf-lib";
import { readFormInventory } from "@/lib/pdf/form-schema";
import { FormFillError } from "@/lib/pdf/form-validation";
import { FORM_ERROR_MESSAGES } from "@/lib/pdf/form-types";
import {
  assertCheapPdfShape,
  assertFillableRestrictions,
  scanStructureInDocument,
  scanEncryptionMarkers,
  type Restrictions,
} from "@/lib/pdf/form-inspection";

type Reply =
  | { ok: true; inventory: unknown; pages: number }
  | { ok: false; code: string; message: string; details?: unknown };

function reasonOf(error: unknown): string {
  if (error && typeof error === "object" && "reason" in error) return String((error as { reason: unknown }).reason);
  return "STRUCTURE_UNREADABLE";
}

async function inspect(bytes: Uint8Array): Promise<Reply> {
  assertCheapPdfShape(bytes);
  if (scanEncryptionMarkers(bytes)) throw new FormFillError("FORM_RESTRICTED", FORM_ERROR_MESSAGES.FORM_RESTRICTED, { restriction: "ENCRYPTED" });

  let document: PDFDocument;
  try { document = await PDFDocument.load(bytes, { ignoreEncryption: false, updateMetadata: false }); }
  catch (error) {
    const encrypted = /encrypted/iu.test(error instanceof Error ? error.message : "");
    throw new FormFillError(
      encrypted ? "FORM_RESTRICTED" : "FORM_UNSUPPORTED",
      encrypted ? FORM_ERROR_MESSAGES.FORM_RESTRICTED : FORM_ERROR_MESSAGES.FORM_UNSUPPORTED,
      { parse: encrypted ? "ENCRYPTED" : "UNREADABLE" },
    );
  }

  // Same walk the route used to run, against the document that was already
  // loaded and is already in this process.
  let structural: { xfa: boolean; signed: boolean };
  try { structural = scanStructureInDocument(document); }
  catch (error) {
    const reason = reasonOf(error);
    throw new FormFillError("FORM_RESTRICTED", FORM_ERROR_MESSAGES.FORM_RESTRICTED, { structure: reason });
  }
  const restrictions: Restrictions = { encrypted: false, xfa: structural.xfa, signed: structural.signed };
  assertFillableRestrictions(restrictions);

  let inventory;
  try { inventory = readFormInventory(document); }
  catch (error) {
    if (error instanceof FormFillError) throw error;
    throw new FormFillError("FORM_UNSUPPORTED", FORM_ERROR_MESSAGES.FORM_UNSUPPORTED, {
      structure: error instanceof RangeError ? "FIELD_GRAPH_TOO_DEEP" : "INVENTORY_UNREADABLE",
    });
  }
  return { ok: true, inventory, pages: document.getPageCount() };
}

const chunks: Uint8Array[] = [];
process.stdin.on("data", (chunk: Buffer) => chunks.push(new Uint8Array(chunk)));
process.stdin.on("end", () => {
  const total = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  chunks.length = 0;
  inspect(bytes)
    .then((reply) => { process.stdout.write(`${JSON.stringify(reply)}\n`); process.exitCode = 0; })
    .catch((error: unknown) => {
      const coded = error instanceof FormFillError;
      const reply: Reply = {
        ok: false,
        // Unexpected failures are still reported as a generic allowlisted code:
        // the parent must never persist an arbitrary library message.
        code: coded ? error.code : "FORM_UNSUPPORTED",
        message: coded ? error.message : FORM_ERROR_MESSAGES.FORM_UNSUPPORTED,
        ...(coded && error.details ? { details: error.details } : {}),
      };
      process.stdout.write(`${JSON.stringify(reply)}\n`);
      process.exitCode = 0;
    });
});
