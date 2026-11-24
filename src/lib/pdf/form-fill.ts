/**
 * Stage 2 `fill-forms` — server-side fill engine.
 *
 * Everything here runs inside the document worker (or a test), never in the
 * browser. The contract with the pipeline is:
 *
 *   inspectFormPdf(bytes)                  read-only inventory for the UI
 *   fillFormPdf(bytes, fields, options)    the bounded, all-or-nothing write
 *
 * `fillFormPdf` refuses before the first write when the document is encrypted,
 * signed/certified, XFA-based, has ambiguous (duplicated) field names, or has
 * no supported fields at all. It then re-opens its own output and verifies the
 * requested values, the untouched fields and the widget appearances; a
 * verification failure throws and the pipeline never stores the bytes.
 */
import { PDFArray, PDFDict, PDFDocument, PDFName, PDFRef, StandardFonts } from "pdf-lib";
import type { PDFFont } from "pdf-lib";
import {
  applyFillValues,
  assertFillableDocument,
  formFieldKind,
  readFormInventory,
  verifyFilledForm,
  type FormFieldKind,
  type FormFillValue,
  type FormInventory,
  type RawFieldMap,
} from "@/lib/pdf/form-schema";
import { FormFillError, validateFillValues, valueSnapshot } from "@/lib/pdf/form-validation";
import { canRasterise, fontCanEncode, installRasterAppearance } from "@/lib/pdf/form-appearance";

export const FORM_ENGINE = "pdf-lib";
export const FORM_ENGINE_VERSION = "1.17.1";

export type FillOptions = { flatten?: boolean };

export type FillReport = {
  filled: Array<{ name: string; kind: FormFieldKind; previous: string | boolean | string[] | null; next: FormFillValue }>;
  untouched: number;
  pages: number;
  flatten: boolean;
  /** Field names whose appearance had to be rasterised (non-WinAnsi text). */
  rasterAppearances: string[];
  engine: string;
  engineVersion: string;
};

/**
 * Restriction probes.
 *
 * Two layers, on purpose:
 *
 *   1. **Structural** (authoritative). The document's own object graph is walked
 *      — catalog → `/AcroForm`, `/Perms`, every field's `/FT` — so XFA packets,
 *      signature fields and certification signatures are found even when they
 *      live inside a compressed object stream (`/ObjStm`), which no raw-byte
 *      scan can see. `pdf-lib` cannot enumerate these for us: `getForm()`
 *      *deletes* a `/XFA` entry and only logs a warning, so anything that must
 *      survive detection is read from the graph before that happens.
 *
 *   2. **Byte** (defence in depth). A literal scan for `/ByteRange`, `/Encrypt`,
 *      `/XFA` and friends still runs, because a damaged-but-parseable file may
 *      keep the marker outside the objects we can reach, and because an unsigned
 *      revision of a previously signed file keeps its old `/ByteRange`.
 *
 * A document is rejected when *either* layer fires.
 */
type Restrictions = { encrypted: boolean; signed: boolean; xfa: boolean };

const signatureType = (value: unknown) => String((value as { toString?: () => string } | undefined)?.toString?.() ?? "");

function scanBytes(bytes: Uint8Array) {
  const text = new TextDecoder("latin1").decode(bytes);
  return {
    encrypted: /\/Encrypt\s+\d+\s+\d+\s+R/u.test(text) || /\/Encrypt\s*<</u.test(text),
    xfa: /\/XFA\b/u.test(text),
    signed: /\/ByteRange\s*\[/u.test(text) || /\/FT\s*\/Sig\b/u.test(text) || /\/DocMDP\b/u.test(text),
  };
}

/**
 * Walk the parsed object graph.
 *
 * `lookup(key, Type)` *throws* when the entry is absent, so plain `lookup(key)`
 * plus an `instanceof` check is used: an earlier version asserted the type and
 * swallowed the exception, which made every uncompressed document look
 * "uninspectable" and silently disabled this whole layer.
 */
async function scanStructure(bytes: Uint8Array): Promise<Omit<Restrictions, "encrypted"> | undefined> {
  let document: PDFDocument;
  try { document = await PDFDocument.load(bytes, { ignoreEncryption: false, updateMetadata: false }); }
  catch { return undefined; }
  try {
    const catalog = document.catalog;
    const acro = catalog.lookup(PDFName.of("AcroForm"));
    const form = acro instanceof PDFDict ? acro : undefined;
    const perms = catalog.lookup(PDFName.of("Perms"));
    // `/Perms /DocMDP` is how a certified document records its policy; it exists
    // independently of any signature-dictionary text.
    const certified = perms instanceof PDFDict && Boolean(perms.lookup(PDFName.of("DocMDP")));
    if (!form) return { xfa: false, signed: certified };
    if (form.has(PDFName.of("XFA"))) return { xfa: true, signed: true };
    // SigFlags bit 1 ("SignaturesExist") and bit 2 ("AppendOnly") both mean the
    // producer knows signatures are present — possibly in a field this walk did
    // not reach. A false positive here only refuses a fill that was never safe
    // to perform; a false negative would write into a signed document.
    const sigFlags = Number(signatureType(form.lookup(PDFName.of("SigFlags"))) || "0");
    const flagsSigned = (sigFlags & 1) === 1 || (sigFlags & 2) === 2;
    const fields = form.lookup(PDFName.of("Fields"));
    const hasSignatureField = (fields instanceof PDFArray ? fields.asArray() : []).some((entry) => {
      const field = entry instanceof PDFRef ? document.context.lookup(entry) : entry;
      // Signature fields may be nested under non-terminal parents; `getFields()`
      // flattens them, but that is exactly the call which deletes /XFA, so the
      // top-level list is combined with the byte layer instead.
      return field instanceof PDFDict && signatureType(field.lookup(PDFName.of("FT"))) === "/Sig";
    });
    return { xfa: false, signed: certified || hasSignatureField || flagsSigned };
  } catch {
    // An unreadable graph is not "safe": the byte layer still decides, and the
    // parse in `loadUnencrypted` will reject anything genuinely broken.
    return undefined;
  }
}

/** Read every restriction signal that applies to these bytes. */
async function probeRestrictions(bytes: Uint8Array): Promise<Restrictions> {
  const bytesView = scanBytes(bytes);
  const structural = await scanStructure(bytes);
  return {
    encrypted: bytesView.encrypted,
    xfa: bytesView.xfa || structural?.xfa === true,
    signed: bytesView.signed || structural?.signed === true,
  };
}

async function loadUnencrypted(bytes: Uint8Array) {
  try { return await PDFDocument.load(bytes, { ignoreEncryption: false }); }
  catch (error) {
    if (scanBytes(bytes).encrypted || /encrypted/iu.test(error instanceof Error ? error.message : "")) throw new FormFillError("FORM_RESTRICTED", "Encrypted PDFs cannot be filled by this tool.");
    throw new FormFillError("FORM_UNSUPPORTED", "The PDF could not be parsed as a fillable document.");
  }
}

function assertFillableRestrictions(restrictions: Restrictions) {
  if (restrictions.encrypted) throw new FormFillError("FORM_RESTRICTED", "Encrypted PDFs cannot be filled by this tool.");
  if (restrictions.xfa) throw new FormFillError("FORM_UNSUPPORTED", "XFA forms are not supported; only AcroForm fields can be filled.");
  if (restrictions.signed) throw new FormFillError("FORM_RESTRICTED", "Signed or certified PDFs cannot be modified safely.");
}

/** Read-only inventory. Never mutates the document and never writes bytes. */
export async function inspectFormPdf(bytes: Uint8Array): Promise<FormInventory> {
  if (scanBytes(bytes).encrypted) throw new FormFillError("FORM_RESTRICTED", "Encrypted PDFs cannot be inspected by this tool.");
  const restrictions = await probeRestrictions(bytes);
  assertFillableRestrictions(restrictions);
  const document = await loadUnencrypted(bytes);
  return readFormInventory(document);
}

type AppearancePlan = { name: string; value: string; multiline: boolean };

/**
 * Fill the form and produce the output bytes.
 *
 * `flatten` is applied last and only after verification: it removes the
 * interactive widgets while keeping their (already verified) appearances, which
 * is what a permanent, non-editable filled copy means.
 */
export async function fillFormPdf(bytes: Uint8Array, fields: RawFieldMap, options: FillOptions = {}): Promise<{ name: string; mimeType: "application/pdf"; bytes: Uint8Array; report: FillReport }> {
  const restrictions = await probeRestrictions(bytes);
  assertFillableRestrictions(restrictions);
  const document = await loadUnencrypted(bytes);
  const inventory = readFormInventory(document);
  // Encryption and signature/certification are already settled by the probe
  // above (byte *and* structural); the inventory gate covers the form itself.
  assertFillableDocument(inventory, { encrypted: false, signed: false });
  const values = validateFillValues(inventory, fields);
  const previous = valueSnapshot(inventory);
  const applied = applyFillValues(document, values);

  // Appearance handling. The vector path is preferred because it keeps text
  // selectable and preserves the widget's own font metrics; only values that
  // cannot be encoded in WinAnsi fall back to a rasterised appearance.
  const helvetica = await document.embedFont(StandardFonts.Helvetica);
  const rasterAppearances: string[] = [];
  const plans: AppearancePlan[] = [];
  const form = document.getForm();
  for (const item of applied) {
    const field = form.getField(item.name);
    const kind = formFieldKind(field);
    if (kind === "checkbox" || kind === "radio") {
      // pdf-lib regenerates these appearance states itself and they are
      // encoding-free; never touch them with the raster path.
      (field as unknown as { defaultUpdateAppearances: (font: PDFFont) => void }).defaultUpdateAppearances(helvetica);
      continue;
    }
    const text = Array.isArray(item.next) ? item.next.join(", ") : String(item.next);
    const descriptor = inventory.fields.find((candidate) => candidate.name === item.name);
    if (!fontCanEncode(helvetica, text)) {
      // WinAnsi cannot carry the value. Arabic (and Latin text with Arabic
      // neighbours) is rendered through the approved canvas rasteriser; any
      // other script has no vendored face and would render as tofu.
      if (!canRasterise(text)) throw new FormFillError("FORM_UNSUPPORTED", `Field "${item.name}" uses a script this tool cannot render. Only Latin, Arabic and their punctuation are supported.`, { field: item.name });
      plans.push({ name: item.name, value: text, multiline: descriptor?.multiline === true });
      continue;
    }
    (field as unknown as { defaultUpdateAppearances: (font: PDFFont) => void }).defaultUpdateAppearances(helvetica);
  }
  for (const plan of plans) {
    await installRasterAppearance(document, form.getField(plan.name), plan.value, { multiline: plan.multiline });
    rasterAppearances.push(plan.name);
  }

  // Clear a stale /NeedAppearances flag: every touched widget now carries a
  // concrete appearance, and leaving the flag set asks readers to regenerate
  // (and possibly discard) what was verified here.
  try { (form as unknown as { acroForm: { dict: { delete(key: PDFName): void } } }).acroForm.dict.delete(PDFName.of("NeedAppearances")); } catch { /* header-only forms */ }

  const firstPass = await document.save({ useObjectStreams: true, updateFieldAppearances: false });
  await verifyFilledForm(firstPass, values, { untouched: previous });

  if (options.flatten === true) {
    const reopened = await PDFDocument.load(firstPass, { ignoreEncryption: false });
    try { reopened.getForm().flatten({ updateFieldAppearances: false }); }
    catch { throw new FormFillError("FORM_UNSUPPORTED", "This form cannot be flattened safely."); }
    const flattened = await reopened.save({ useObjectStreams: true, updateFieldAppearances: false });
    // Flattening removes the fields, so values can no longer be read back; the
    // page count and re-openability are what remain verifiable.
    const check = await PDFDocument.load(flattened, { ignoreEncryption: false });
    if (check.getPageCount() !== inventory.pages) throw new FormFillError("FORM_OUTPUT_UNVERIFIED", "Flattening changed the page count.");
    return {
      name: "filled-form.pdf", mimeType: "application/pdf", bytes: flattened,
      report: { filled: applied, untouched: inventory.fields.length - applied.length, pages: inventory.pages, flatten: true, rasterAppearances, engine: FORM_ENGINE, engineVersion: FORM_ENGINE_VERSION },
    };
  }

  return {
    name: "filled-form.pdf", mimeType: "application/pdf", bytes: firstPass,
    report: { filled: applied, untouched: inventory.fields.length - applied.length, pages: inventory.pages, flatten: false, rasterAppearances, engine: FORM_ENGINE, engineVersion: FORM_ENGINE_VERSION },
  };
}

/** Field names that must not be silently dropped when a caller mis-spells one. */
export function unknownFieldNames(inventory: FormInventory, fields: Record<string, unknown>) {
  const known = new Set(inventory.fields.map((field) => field.name));
  return Object.keys(fields).filter((name) => !known.has(name));
}

/** Exposed so the pipeline can report a precise engine label in metrics. */
export function formEngineLabel() { return { engine: FORM_ENGINE, engineVersion: FORM_ENGINE_VERSION }; }

export { FormFillError };
export type { FormFieldKind, FormFillValue, FormInventory };
export { applyFillValues, readFormInventory, validateFillValues, verifyFilledForm };
