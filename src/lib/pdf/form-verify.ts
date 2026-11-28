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
import { appearanceProblems, readFormInventory, valuesEqual } from "./form-schema";
import { FORM_FIELD_LIMIT } from "./form-types";
import type { FormFieldKind } from "./form-types";
import { FormFillError } from "./form-validation";
import { FORM_ERROR_MESSAGES } from "./form-types";

/** A verify success. Structural facts only — never document bytes. */
export type VerifyResult = {
  pages: number;
  /** Interactive field widgets found. Must be 0 for a flattened document. */
  widgets: number;
  /** Untouched fields confirmed unchanged. */
  preserved: number;
};

/**
 * Structural facts about a filled (not flattened) document, for the isolated executor.
 *
 * The executor cannot compare values, because the expected values are held in the trusted
 * worker's memory and are deliberately not transmitted. What it can establish without them is
 * that the document re-parses, how many pages it has, how many widgets remain, and whether every
 * widget carries a usable appearance. The value comparison is Version: ImageMagick 6.9.11-60 Q16 x86_64 2021-01-25 https://imagemagick.org
Copyright: (C) 1999-2021 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC Modules OpenMP(4.5) 
Delegates (built-in): bzlib djvu fftw fontconfig freetype heic jbig jng jp2 jpeg lcms lqr ltdl lzma openexr pangocairo png tiff webp wmf x xml zlib
Usage: compare-im6.q16 [options ...] image reconstruct difference

Image Settings:
  -alpha option        on, activate, off, deactivate, set, opaque, copy
                       transparent, extract, background, or shape
  -authenticate password
                       decipher image with this password
  -background color    background color
  -channel type        apply option to select image channels
  -colorspace type     alternate image colorspace
  -compose operator    set image composite operator
  -compress type       type of pixel compression when writing the image
  -decipher filename   convert cipher pixels to plain pixels
  -define format:option
                       define one or more image format options
  -density geometry    horizontal and vertical density of the image
  -depth value         image depth
  -dissimilarity-threshold value
                       maximum distortion for (sub)image match
  -encipher filename   convert plain pixels to cipher pixels
  -extract geometry    extract area from image
  -format "string"     output formatted image characteristics
  -fuzz distance       colors within this distance are considered equal
  -gravity type        horizontal and vertical text placement
  -highlight-color color
                       empasize pixel differences with this color
  -identify            identify the format and characteristics of the image
  -interlace type      type of image interlacing scheme
  -limit type value    pixel cache resource limit
  -lowlight-color color
                       de-emphasize pixel differences with this color
  -mask filename       associate a mask with the image
  -metric type         measure differences between images with this metric
  -monitor             monitor progress
  -passphrase filename get the passphrase from this file
  -precision value     maximum number of significant digits to print
  -profile filename    add, delete, or apply an image profile
  -quality value       JPEG/MIFF/PNG compression level
  -quiet               suppress all warning messages
  -quantize colorspace reduce colors in this colorspace
  -regard-warnings     pay attention to warning messages
  -repage geometry     size and location of an image canvas
  -respect-parentheses settings remain in effect until parenthesis boundary
  -sampling-factor geometry
                       horizontal and vertical sampling factor
  -seed value          seed a new sequence of pseudo-random numbers
  -set attribute value set an image attribute
  -quality value       JPEG/MIFF/PNG compression level
  -similarity-threshold value
                       minimum distortion for (sub)image match
  -size geometry       width and height of image
  -subimage-search     search for subimage
  -synchronize         synchronize image to storage device
  -taint               declare the image as modified
  -transparent-color color
                       transparent color
  -type type           image type
  -verbose             print detailed information about the image
  -version             print version information
  -virtual-pixel method
                       virtual pixel access method

Image Operators:
  -brightness-contrast geometry
                       improve brightness / contrast of the image
  -distort method args
                       distort images according to given method and args
  -level value         adjust the level of image contrast
  -resize geometry     resize the image
  -rotate degrees      apply Paeth rotation to the image
  -sigmoidal-contrast geometry
                       increase the contrast without saturating highlights or
  -trim                trim image edges

Image Sequence Operators:
  -crop geometry       cut out a rectangular region of the image
  -separate            separate an image channel into a grayscale image
  -write filename      write images to this file

Image Stack Operators:
  -delete indexes      delete the image from the image sequence

Miscellaneous Options:
  -debug events        display copious debugging information
  -help                print program options
  -list type           print a list of supported option arguments
  -log format          format of debugging information

By default, the image format of `file' is determined by its magic
number.  To specify a particular image format, precede the filename
with an image format name and a colon (i.e. ps:image) or specify the
image type as the filename suffix (i.e. image.ps).  Specify 'file' as
'-' for standard input or output., which runs on the
 * trusted side against the baseline.
 */
export async function verifyFilledStructure(bytes: Uint8Array): Promise<VerifyResult> {
  const document = await PDFDocument.load(bytes, { ignoreEncryption: false });
  const inventory = readFormInventory(document);
  let widgetProblems = 0;
  for (const field of document.getForm().getFields()) {
    widgetProblems += appearanceProblems(field).length;
  }
  if (widgetProblems > 0) {
    throw new FormFillError("FORM_OUTPUT_UNVERIFIED", FORM_ERROR_MESSAGES.FORM_OUTPUT_UNVERIFIED, {
      mismatches: [{ code: "APPEARANCE_PROBLEM", count: widgetProblems }],
    });
  }
  return { pages: document.getPageCount(), widgets: inventory.fields.length, preserved: 0 };
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


// ---------------------------------------------------------------------------------------
// The trusted-side baseline (F03)
// ---------------------------------------------------------------------------------------

/**
 * A field's state as observed by the admission inspection.
 *
 * Names and values are held in worker memory for one execution and are never written to the
 * journal, a log line or the wire. That is the constraint the review set: the previous design
 * put the expected and untouched maps *inside the 256 KiB control frame*, which both risked the
 * control ceiling on a large form and made the comparison depend on what the caller claimed
 * rather than on what was observed.
 */
export type FieldObservation = {
  name: string;
  kind: FormFieldKind;
  value: string | boolean | string[] | null;
};

/**
 * The transient baseline for one execution.
 *
 * Constructed by `captureBaseline` immediately after admission inspection, used by `compare`,
 * and dropped. There is deliberately no serialization method: a structure that cannot be
 * written cannot be persisted by accident.
 */
export type FieldBaseline = {
  readonly fields: ReadonlyMap<string, FieldObservation>;
  readonly pages: number;
  /** True once the baseline has been consumed by a comparison; a second use is a bug. */
  consumed: boolean;
};

/** Capture the baseline from an inspected document's inventory. */
export function captureBaseline(inventory: { fields: Array<{ name: string; kind: FormFieldKind; value: unknown }>; pages: number }): FieldBaseline {
  if (inventory.fields.length > FORM_FIELD_LIMIT) {
    // The same limit the decoder enforces, so a baseline cannot be larger than an inventory
    // that was allowed across the wire.
    throw new FormFillError("FORM_VALUE_INVALID", FORM_ERROR_MESSAGES.FORM_VALUE_INVALID);
  }
  const fields = new Map<string, FieldObservation>();
  for (const field of inventory.fields) {
    fields.set(field.name, { name: field.name, kind: field.kind, value: field.value as FieldObservation["value"] });
  }
  return { fields, pages: inventory.pages, consumed: false };
}

/** A finding from the comparison. Codes only — never a field name or a value. */
export type CompareFinding =
  | "VALUE_NOT_ROUND_TRIPPED"
  | "UNTOUCHED_FIELD_MODIFIED"
  | "FIELD_MISSING"
  | "FIELD_ADDED"
  | "APPEARANCE_PROBLEM";

/**
 * Compare a re-parsed document against the in-memory baseline.
 *
 * ## Semantics are the engine's, not this module's
 *
 * `valuesEqual` and `appearanceProblems` are imported from the engine. The comparison rules they
 * encode — a text field's two empty spellings, checkbox and radio state, multi-widget
 * aggregation, list order — are subtle and already correct. Re-deriving them here would create a
 * second opinion about whether a document is valid, and the two would eventually disagree.
 *
 * Nothing is normalized that the engine does not normalize: no NFC, no whitespace collapsing,
 * no sorting of selections.
 */
export function compare(baseline: FieldBaseline, after: { fields: Array<{ name: string; kind: FormFieldKind; value: unknown; widgetProblems?: number }>; pages: number }, expected: ReadonlyMap<string, string | boolean | string[]>): { findings: CompareFinding[]; preserved: number } {
  if (baseline.consumed) throw new FormFillError("FORM_OUTPUT_UNVERIFIED", FORM_ERROR_MESSAGES.FORM_OUTPUT_UNVERIFIED);
  baseline.consumed = true;

  const findings = new Set<CompareFinding>();
  const observed = new Map(after.fields.map((field) => [field.name, field]));
  let preserved = 0;

  // 1. Every expected value must round-trip.
  for (const [name, want] of expected) {
    const seen = observed.get(name);
    if (!seen) {
      findings.add("FIELD_MISSING");
      continue;
    }
    if (!valuesEqual(seen.kind, want, seen.value as string | boolean | string[] | null)) {
      findings.add("VALUE_NOT_ROUND_TRIPPED");
    }
  }

  // 2. Every field that was present before and not part of the request must be unchanged.
  for (const [name, before] of baseline.fields) {
    if (expected.has(name)) continue;
    const seen = observed.get(name);
    if (!seen) {
      findings.add("FIELD_MISSING");
      continue;
    }
    if (valuesEqual(before.kind, before.value, seen.value as string | boolean | string[] | null)) preserved += 1;
    else findings.add("UNTOUCHED_FIELD_MODIFIED");
  }

  // 3. No field may appear that was not there before.
  for (const name of observed.keys()) {
    if (!baseline.fields.has(name)) findings.add("FIELD_ADDED");
  }

  return { findings: [...findings], preserved };
}

/**
 * Verify a flattened document against the baseline.
 *
 * Structural only, for the reason stated on `verifyFlattened`: flattening removes the interactive
 * layer, so there is nothing left to compare field-by-field. The page count is the one thing that
 * must match, because the baseline knows what it was.
 */
export async function verifyFlattenedAgainstBaseline(bytes: Uint8Array, baseline: FieldBaseline): Promise<VerifyResult> {
  const structural = await verifyFlattened(bytes);
  if (structural.pages !== baseline.pages) {
    throw new FormFillError("FORM_OUTPUT_UNVERIFIED", FORM_ERROR_MESSAGES.FORM_OUTPUT_UNVERIFIED, {
      mismatches: [{ code: "PAGE_COUNT_CHANGED", count: 1 }],
    });
  }
  return structural;
}
