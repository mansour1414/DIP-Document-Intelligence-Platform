/**
 * Stage 2 `fill-forms` — server-side fill engine.
 *
 * Everything here runs inside the document worker (or a test), never in the
 * browser. The contract with the pipeline is:
 *
 *   inspectFormPdf(bytes)                  read-only inventory for the UI
 *   fillFormPdf(bytes, fields, options)    the bounded, all-or-nothing write
 *
 * `inspectFormPdf` and the restriction probes live in `form-inspection.ts`, a
 * renderer-free module, because the inspect route must not import the rasteriser
 * (FF-01). This module owns the write path only.
 *
 * `fillFormPdf` refuses before the first write when the document is encrypted,
 * signed/certified, XFA-based, has ambiguous (duplicated) field names, or has
 * no supported fields at all. It then re-opens its own output and verifies the
 * requested values, the untouched fields and the widget appearances; a
 * verification failure throws and the pipeline never stores the bytes.
 */
import { PDFArray, PDFDict, PDFDocument, PDFName, PDFRef, StandardFonts } from "pdf-lib";
import type { PDFFont, PDFObject } from "pdf-lib";
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
import { FORM_ERROR_MESSAGES } from "@/lib/pdf/form-types";
import { AppearanceLegibilityError, appearanceBox, assertValueFitsWidget, canRasterise, fontCanEncode, installRasterAppearance } from "@/lib/pdf/form-appearance";
// The restriction probes live in a renderer-free module (FF-01); they are
// re-exported here so the worker keeps one entry point.
import { assertFillableRestrictions, probeRestrictions, scanBytes } from "@/lib/pdf/form-inspection";

export { inspectFormPdf } from "@/lib/pdf/form-inspection";

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

async function loadUnencrypted(bytes: Uint8Array) {
  try { return await PDFDocument.load(bytes, { ignoreEncryption: false }); }
  catch (error) {
    if (scanBytes(bytes).encrypted || /encrypted/iu.test(error instanceof Error ? error.message : "")) throw new FormFillError("FORM_RESTRICTED", FORM_ERROR_MESSAGES.FORM_RESTRICTED);
    throw new FormFillError("FORM_UNSUPPORTED", FORM_ERROR_MESSAGES.FORM_UNSUPPORTED);
  }
}

/**
 * Reference identities of every widget of every field (FF-05).
 *
 * Collected *before* flattening, because afterwards the fields that own them no
 * longer exist. The identity is the widget dictionary's indirect reference,
 * which survives flattening — that is exactly what stays behind in `/Annots`.
 *
 * pdf-lib exposes no `.ref` on `PDFObject`, and an earlier version of this
 * helper silently collected nothing because it read one. The reference is
 * therefore recovered from the context's indirect-object table by **object
 * identity**: a widget that came from the file is the very object registered
 * under its reference. A widget written inline (a direct dictionary) has no
 * reference and cannot dangle.
 */
function flattenedWidgetRefs(document: PDFDocument): Set<string> {
  const widgets = new Set<PDFObject>();
  for (const field of document.getForm().getFields()) {
    for (const widget of field.acroField.getWidgets()) widgets.add((widget as unknown as { dict: PDFObject }).dict);
  }
  const references = new Set<string>();
  if (!widgets.size) return references;
  for (const [ref, object] of document.context.enumerateIndirectObjects()) {
    if (widgets.has(object)) references.add(ref.toString());
  }
  return references;
}

/**
 * Remove the given references from every page's `/Annots`, keeping everything
 * else and preserving the array's order.
 *
 * An `/Annots` entry that is a direct dictionary (not a reference) is never a
 * flattened widget and is kept. `/Annots` itself may be an indirect reference;
 * it is resolved and written back in place.
 */
function pruneAnnotations(document: PDFDocument, references: Set<string>): { removed: number; pages: number } {
  let removed = 0;
  let pages = 0;
  for (const page of document.getPages()) {
    const raw = (page.node as unknown as { Annots?: () => PDFArray | undefined }).Annots?.();
    if (!raw) continue;
    // `Annots()` may return an indirect reference wrapper; `context.lookup`
    // resolves it so the array can be rewritten in place.
    const resolved = (raw instanceof PDFArray ? raw : document.context.lookup(raw as unknown as PDFRef)) as PDFArray | undefined;
    if (!(resolved instanceof PDFArray)) continue;
    const kept: PDFObject[] = [];
    let changed = false;
    for (let position = 0; position < resolved.size(); position += 1) {
      const entry = resolved.get(position);
      if (entry instanceof PDFRef && references.has(entry.toString())) { removed += 1; changed = true; continue; }
      if (entry !== undefined) kept.push(entry as PDFObject);
    }
    if (!changed) continue;
    // An empty `/Annots` array is dropped entirely rather than written back as
    // `[]`: readers and validators both treat a missing entry as "no
    // annotations", while an empty array is legal but noisy.
    if (kept.length) page.node.set(PDFName.of("Annots"), document.context.obj(kept) as PDFArray);
    else (page.node as unknown as { delete: (key: PDFName) => void }).delete(PDFName.of("Annots"));
    pages += 1;
  }
  return { removed, pages };
}

/**
 * Count page annotations that no longer resolve, and annotation entries that are
 * still form widgets. Both are zero in a correctly flattened document: a widget
 * that survives in `/Annots` is either a dangling reference (its field is gone)
 * or a form control that was supposed to be flattened away.
 */
function danglingAnnotations(document: PDFDocument): { unresolved: number; widgets: number; annots: number } {
  let unresolved = 0;
  let widgets = 0;
  let annots = 0;
  for (const page of document.getPages()) {
    const array = (page.node as unknown as { Annots?: () => PDFArray | undefined }).Annots?.();
    if (!array) continue;
    for (let position = 0; position < array.size(); position += 1) {
      const entry = array.get(position);
      annots += 1;
      let target: PDFObject | undefined = entry;
      if (entry instanceof PDFRef) {
        target = document.context.lookup(entry) as PDFObject | undefined;
        if (target === undefined) { unresolved += 1; continue; }
      }
      if (target instanceof PDFDict) {
        const subtype = target.get(PDFName.of("Subtype"));
        if (String(subtype ?? "") === "/Widget") widgets += 1;
      }
    }
  }
  return { unresolved, widgets, annots };
}

type AppearancePlan = { name: string; value: string; multiline: boolean; vector: boolean };

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
    // FF-07: an option list is a *set*, not a sentence. pdf-lib's own appearance
    // provider draws every option and highlights the selected ones, which is
    // correct — but the raster fallback below can only paint one string, and
    // joining the selection with commas misrepresents the field on the page. An
    // Arabic selection therefore cannot use the raster path and is rejected
    // explicitly rather than shown as "أ, ب". Latin selections keep the vector
    // provider, so `/V` stays a real array and the rendering stays accurate.
    if (Array.isArray(item.next)) {
      const raster = (field as unknown as { defaultUpdateAppearances: (font: PDFFont) => void });
      const options = inventory.fields.find((candidate) => candidate.name === item.name)?.options ?? [];
      const allEncodable = item.next.every((option) => fontCanEncode(helvetica, option)) && (options.length === 0 || fontCanEncode(helvetica, options.join(" ")));
      if (!allEncodable) throw new FormFillError("FORM_VALUE_INVALID", FORM_ERROR_MESSAGES.FORM_VALUE_INVALID, { issues: [{ issue: "UNRENDERABLE_SCRIPT" }] });
      raster.defaultUpdateAppearances(helvetica);
      continue;
    }
    const text = String(item.next);
    const descriptor = inventory.fields.find((candidate) => candidate.name === item.name);
    // FF-07 round 2 — the silent-clipping bug, exactly.
    //
    // This branch used to split on *encodability*: Latin values that WinAnsi could
    // carry took pdf-lib's `defaultUpdateAppearances`, which draws a single line
    // and clips whatever does not fit, with no fit check at all. Only non-WinAnsi
    // (Arabic) values reached `installRasterAppearance` and therefore the
    // legibility gate. The result was that the one case the review reported — a
    // long value truncated inside its widget — was the case that bypassed the
    // check, while the case nobody complained about was protected.
    //
    // Every text value now goes through the same legibility gate. Encodability
    // only decides *which face* renders it, never whether it is measured.
    if (!fontCanEncode(helvetica, text) && !canRasterise(text)) {
      // No vendored face covers this script; rendering it would produce tofu.
      throw new FormFillError("FORM_UNSUPPORTED", `Field "${item.name}" uses a script this tool cannot render. Only Latin, Arabic and their punctuation are supported.`, { field: item.name });
    }
    // Whether or not this value needs the raster face, it is measured first. A
    // value that cannot be shown legibly is rejected here, before any appearance
    // is written, so a partially-painted document can never be produced.
    const widget = field.acroField.getWidgets()[0];
    const box = widget ? appearanceBox(widget) : undefined;
    if (box) {
      try { assertValueFitsWidget(text, { width: box.width, height: box.height, multiline: descriptor?.multiline === true }); }
      catch (error) {
        if (error instanceof AppearanceLegibilityError) throw new FormFillError("FORM_VALUE_INVALID", FORM_ERROR_MESSAGES.FORM_VALUE_INVALID, { issues: [{ issue: error.reason, field: item.name }] });
        throw error;
      }
    }
    plans.push({ name: item.name, value: text, multiline: descriptor?.multiline === true, vector: fontCanEncode(helvetica, text) });
  }
  for (const plan of plans) {
    // FF-07: an unrenderable value must fail the whole request, never produce a
    // document that silently clips or omits part of it. The error is a rejection
    // with no partial output; the message stays content-free, and the reason is
    // structured.
    if (plan.vector) {
      // Latin stays vector/selectable text — the check above proved it fits, which
      // is what `defaultUpdateAppearances` never did.
      (form.getField(plan.name) as unknown as { defaultUpdateAppearances: (font: PDFFont) => void }).defaultUpdateAppearances(helvetica);
      continue;
    }
    try { await installRasterAppearance(document, form.getField(plan.name), plan.value, { multiline: plan.multiline }); }
    catch (error) {
      // The rejection keeps its own identity: a geometry failure is not a script
      // failure, and a caller must be able to tell them apart.
      if (error instanceof AppearanceLegibilityError) throw new FormFillError("FORM_VALUE_INVALID", FORM_ERROR_MESSAGES.FORM_VALUE_INVALID, { issues: [{ issue: error.reason }] });
      throw error;
    }
    rasterAppearances.push(plan.name);
  }

  // Clear a stale /NeedAppearances flag: every touched widget now carries a
  // concrete appearance, and leaving the flag set asks readers to regenerate
  // (and possibly discard) what was verified here.
  try { (form as unknown as { acroForm: { dict: { delete(key: PDFName): void } } }).acroForm.dict.delete(PDFName.of("NeedAppearances")); } catch { /* header-only forms */ }

  const firstPass = await document.save({ useObjectStreams: true, updateFieldAppearances: false });
  // `verifyFilledForm` reopens `firstPass` and reports the page count it actually
  // contains. That number was previously discarded, and the report below fell back to
  // `inventory.pages` — the *input's* count. The two are equal for a correct fill,
  // which is exactly why the substitution was invisible: a transformation that dropped
  // or added a page would still have been reported with the input's count, and the
  // parent compares the reported count against the input count it already holds, so the
  // check would have agreed with itself.
  const verified = await verifyFilledForm(firstPass, values, { untouched: previous });
  // Preservation is asserted here, against the reopened document, so a mismatch fails
  // in the child that produced it rather than being reported as a success.
  if (verified.pages !== inventory.pages) {
    throw new FormFillError("FORM_OUTPUT_UNVERIFIED", FORM_ERROR_MESSAGES.FORM_OUTPUT_UNVERIFIED, { issue: "PAGE_COUNT_CHANGED" });
  }

  if (options.flatten === true) {
    const reopened = await PDFDocument.load(firstPass, { ignoreEncryption: false });
    const widgets = flattenedWidgetRefs(reopened);
    try { reopened.getForm().flatten({ updateFieldAppearances: false }); }
    catch { throw new FormFillError("FORM_UNSUPPORTED", FORM_ERROR_MESSAGES.FORM_UNSUPPORTED, { flatten: "FAILED" }); }
    // FF-05: `flatten()` removes the widgets' *fields* and paints their
    // appearance onto the page, but it leaves the widget references behind in
    // `/Page /Annots`. Every one of those is a dangling reference: pypdf counts
    // 15 unresolved `/Annots` and Poppler reports 15 `Invalid XRef entry`, even
    // though the document re-opens and the page count is unchanged. A reopen and
    // a page-count check cannot see that.
    const pruned = pruneAnnotations(reopened, widgets);
    const flattened = await reopened.save({ useObjectStreams: true, updateFieldAppearances: false });
    if (pruned.removed !== widgets.size) throw new FormFillError("FORM_OUTPUT_UNVERIFIED", FORM_ERROR_MESSAGES.FORM_OUTPUT_UNVERIFIED, { flatten: "ANNOTATION_COUNT_MISMATCH" });
    const check = await PDFDocument.load(flattened, { ignoreEncryption: false });
    // This is the flattened output's own page count, read from the bytes that will be
    // returned — not the input's count and not the pre-flatten intermediate's.
    const flattenedPages = check.getPageCount();
    if (flattenedPages !== inventory.pages) throw new FormFillError("FORM_OUTPUT_UNVERIFIED", FORM_ERROR_MESSAGES.FORM_OUTPUT_UNVERIFIED, { flatten: "PAGE_COUNT_CHANGED" });
    // Structural post-condition: no page may reference a widget that no longer
    // exists. Checked on the re-read bytes, not on the in-memory document, so a
    // serialisation regression cannot hide behind an unsaved edit.
    const dangling = danglingAnnotations(check);
    if (dangling.unresolved || dangling.widgets) throw new FormFillError("FORM_OUTPUT_UNVERIFIED", FORM_ERROR_MESSAGES.FORM_OUTPUT_UNVERIFIED, { flatten: "DANGLING_ANNOTATIONS", ...dangling });
    return {
      name: "filled-form.pdf", mimeType: "application/pdf", bytes: flattened,
      report: { filled: applied, untouched: inventory.fields.length - applied.length, pages: flattenedPages, flatten: true, rasterAppearances, engine: FORM_ENGINE, engineVersion: FORM_ENGINE_VERSION },
    };
  }

  return {
    name: "filled-form.pdf", mimeType: "application/pdf", bytes: firstPass,
    // The page count of the bytes being returned, as reopened and verified above.
    report: { filled: applied, untouched: inventory.fields.length - applied.length, pages: verified.pages, flatten: false, rasterAppearances, engine: FORM_ENGINE, engineVersion: FORM_ENGINE_VERSION },
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
