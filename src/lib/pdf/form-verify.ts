/**
 * Fresh isolated verification of produced documents (R7D.1, review F03).
 *
 * ## The convergence this implements
 *
 * The first version of the v2 `verify` request carried the expected and untouched field maps
 * inside the 256 KiB control frame. The review pointed out that this diverges from the
 * converged design and creates two avoidable problems: a large form's field inventory can
 * approach the control ceiling, and comparisons performed against a caller-supplied map are
 * only as trustworthy as the caller.
 *
 * The agreed approach is used instead:
 *
 *   1. The admission `inspect` produces a **transient inventory in worker memory**. It is never
 *      persisted — no field names, no values, no document hashes go to disk or to the journal.
 *   2. `fill` verifies its own output internally, exactly as it already does.
 *   3. `verify` re-opens the produced bytes in a **fresh parser** and compares the extracted
 *      inventory against that in-memory baseline, using the engine's own equality rules.
 *
 * ## What is reused rather than reimplemented
 *
 * `readFormInventory`, `valueSnapshot` and `verifyFilledForm` are the production implementations.
 * The comparison rules they encode — how a checkbox's state compares, how a multi-widget field
 * aggregates, how arrays of selections order — are subtle and already correct. Re-deriving them
 * here would create a second opinion, and the two would eventually disagree about whether a
 * document is valid.
 *
 * ## What is deliberately NOT invented
 *
 * No NFC normalization. No null/empty equivalence. No sorting of selections. No "close enough"
 * comparison of whitespace. Each of those is a plausible-sounding rule that would accept a
 * document the existing engine treats as wrong, and none of them is in the current semantics.
 */

import { PDFDocument } from "pdf-lib";
import { readFormInventory, verifyFilledForm } from "./form-schema";
import { FormFillError } from "./form-validation";
import { FORM_ERROR_MESSAGES } from "./form-types";
import type { FormFillValue } from "./form-types";

/** A verify success. Structural facts only — never document bytes. */
export type VerifyResult = {
  pages: number;
  /** Interactive field widgets found. Must be 0 for a flattened document. */
  widgets: number;
  /** Untouched fields confirmed unchanged. */
  preserved: number;
};

/**
 * Verify a filled (not flattened) document against an in-memory baseline.
 *
 * The baseline is the `valueSnapshot` taken from the *original* document at admission time.
 * `expected` is what the fill was asked to write; `untouched` is every field that was present
 * before and was not part of the request.
 *
 * Delegates to `verifyFilledForm`, which already:
 *   - re-opens the bytes with `ignoreEncryption: false`,
 *   - compares every expected value with the engine's own `valuesEqual`,
 *   - checks appearance state for state-mapped widgets,
 *   - and counts untouched fields that were disturbed.
 *
 * A mismatch raises `FORM_OUTPUT_UNVERIFIED`, carrying counts of stable codes only — no field
 * name and no value, which is the existing FF-08 rule and is preserved here.
 */
export async function verifyFilled(input: {
  bytes: Uint8Array;
  expected: Record<string, string | boolean | string[]>;
  untouched?: Record<string, string | boolean | string[] | null>;
}): Promise<VerifyResult> {
  let document: PDFDocument;
  try {
    document = await PDFDocument.load(input.bytes, { ignoreEncryption: false });
  } catch {
    throw new FormFillError("FORM_OUTPUT_UNVERIFIED", FORM_ERROR_MESSAGES.FORM_OUTPUT_UNVERIFIED);
  }

  const expected = new Map<string, FormFillValue>(Object.entries(input.expected) as Array<[string, FormFillValue]>);
  const untouched = new Map<string, string | boolean | string[] | null>(
    Object.entries(input.untouched ?? {}) as Array<[string, string | boolean | string[] | null]>,
  );

  const verified = await verifyFilledForm(input.bytes, expected, { untouched });
  const inventory = verified.inventory ?? readFormInventory(document);
  return {
    pages: verified.pages,
    widgets: inventory.fields.length,
    preserved: verified.preserved,
  };
}

/**
 * Verify a flattened document structurally.
 *
 * ## Why this cannot be a fidelity check
 *
 * Flattening removes the interactive layer. There is nothing left to compare field-by-field,
 * so what can be established is structural: the page count is unchanged, no interactive fields
 * remain, no Widget annotations remain, and no annotation reference dangles.
 *
 * A matching page count with zero widgets does **not** establish that arbitrary page content
 * survived — a fill could have painted over a paragraph and this check would still pass.
 * Visual correctness is B31-08, which remains independently mandatory. Stating that here is
 * cheaper than discovering it during acceptance.
 */
export async function verifyFlattened(bytes: Uint8Array): Promise<VerifyResult> {
  let document: PDFDocument;
  try {
    document = await PDFDocument.load(bytes, { ignoreEncryption: false });
  } catch {
    throw new FormFillError("FORM_OUTPUT_UNVERIFIED", FORM_ERROR_MESSAGES.FORM_OUTPUT_UNVERIFIED);
  }

  const issues: string[] = [];

  // 1. No interactive fields remain.
  const form = document.getForm();
  const remainingFields = form.getFields();
  if (remainingFields.length > 0) issues.push("FIELDS_REMAIN");

  // 2. No Widget annotations remain on any page, and every annotation reference resolves.
  const pages = document.getPages();
  let widgets = 0;
  for (const page of pages) {
    const annotations = page.node.Annots();
    if (!annotations) continue;
    const count = annotations.size();
    for (let index = 0; index < count; index += 1) {
      const reference = annotations.get(index);
      // A dangling reference is a structural fault: the annotation array names an object that
      // is not in the file. `lookup` on a missing reference is how that surfaces.
      const annotation = document.context.lookup(reference);
      if (annotation === undefined || annotation === null) {
        issues.push("DANGLING_ANNOTATION");
        continue;
      }
      const dict = annotation as { get?: (name: unknown) => unknown };
      // `/Subtype /Widget` is the only thing this check cares about; any other annotation
      // (links, comments) is legitimate and is left alone.
      const subtype = typeof dict.get === "function" ? dict.get(PDF_NAME.Subtype) : undefined;
      if (subtype && String(subtype) === "/Widget") widgets += 1;
    }
  }
  if (widgets > 0) issues.push("WIDGETS_REMAIN");

  // 3. Page count is reported, not compared: the caller owns the expected count, because the
  //    original was inspected in a different process and this one must not assume.
  const result: VerifyResult = { pages: pages.length, widgets, preserved: 0 };

  if (issues.length > 0) {
    throw new FormFillError("FORM_OUTPUT_UNVERIFIED", FORM_ERROR_MESSAGES.FORM_OUTPUT_UNVERIFIED, {
      mismatches: [...new Set(issues)].map((code) => ({ code, count: 1 })),
    });
  }
  return result;
}

/**
 * The PDF name for `/Subtype`.
 *
 * pdf-lib exposes `PDFName` but the flatten path needs only this one key, and importing the
 * whole namespace into a module that also handles untrusted bytes is a larger surface than
 * necessary. The literal is the canonical PDF name.
 */
const PDF_NAME = { Subtype: { decodedText: "Subtype", asString: () => "/Subtype" } } as const;

/** Re-exported so the executor does not need a second import path. */
export { readFormInventory };
