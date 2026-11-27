/**
 * `fill-forms` — browser-safe AcroForm schema contract.
 *
 * This module only depends on `pdf-lib`, so the very same inventory, validation
 * and verification code runs:
 *   - in the browser, to render the form-filling interface, and
 *   - in the worker, as the authoritative check before any byte is written.
 *
 * Scope (deliberately narrow, see docs/stage2-fill-forms.md):
 *   - existing AcroForm *terminal* fields only: text, checkbox, radio group,
 *     dropdown, option list;
 *   - field identity is the fully qualified name; duplicated fully qualified
 *     names are rejected because a JSON name→value map cannot address them
 *     unambiguously;
 *   - unsupported widgets (push buttons, signatures, XFA, rich text, combed,
 *     password) are reported, never guessed at.
 */
import { PDFDocument, PDFName, PDFDict, type PDFField } from "pdf-lib";
import { FORM_FIELD_LIMIT, FORM_OPTION_LIMIT, type FormFieldDescriptor, type FormFieldKind, type FormFillValue, type FormInventory, type UnsupportedFieldDescriptor } from "@/lib/pdf/form-types";
import { FormFillError } from "@/lib/pdf/form-validation";
import { FORM_ERROR_MESSAGES } from "@/lib/pdf/form-types";

export type {
  FormFieldKind,
  FormFieldDescriptor,
  UnsupportedFieldDescriptor,
  FormInventory,
  FormFillValue,
  FormFillErrorCode,
  RawFieldMap,
} from "@/lib/pdf/form-types";

/** Hard bounds so a hostile document cannot exhaust the worker or browser tab. */
export { FORM_FIELDS_JSON_LIMIT, FORM_FIELD_LIMIT, FORM_FIELD_NAME_LIMIT, FORM_OPTION_LIMIT, FORM_VALUE_CHAR_LIMIT, FORM_VALUE_LIMIT } from "@/lib/pdf/form-types";
export { FormFillError, parseFieldsPayload, assertFieldsPayloadSize, validateFillValues, valueSnapshot } from "@/lib/pdf/form-validation";

function widgetPages(document: PDFDocument, field: PDFField): number[] {
  const widgets = field.acroField.getWidgets();
  const pages = document.getPages();
  const byRef = new Map(pages.map((page, index) => [page.ref.toString(), index + 1]));
  const result = new Set<number>();
  for (const widget of widgets) {
    const direct = widget.P();
    if (direct) { const page = byRef.get(direct.toString()); if (page) result.add(page); }
  }
  if (result.size) return [...result].sort((a, b) => a - b);
  // Structure-only fallback: match widget references against each page's /Annots.
  for (const [index, page] of pages.entries()) {
    const annots = page.node.Annots();
    if (!annots) continue;
    const references = new Set<string>();
    for (let position = 0; position < annots.size(); position += 1) {
      const entry = annots.get(position);
      if (entry) references.add(entry.toString());
    }
    for (const widget of widgets) {
      const ref = (widget as unknown as { ref?: { toString(): string } }).ref;
      if (ref && references.has(ref.toString())) result.add(index + 1);
    }
  }
  return [...result].sort((a, b) => a - b);
}

function classify(field: PDFField): FormFieldKind | { unsupported: string } {
  const kind = field.constructor.name;
  if (kind === "PDFTextField") {
    const text = field as unknown as { isPassword: () => boolean; isRichFormatted: () => boolean; isCombed: () => boolean };
    if (text.isPassword()) return { unsupported: "Password text fields are not fillable." };
    if (text.isRichFormatted()) return { unsupported: "Rich text fields are not supported." };
    if (text.isCombed()) return { unsupported: "Combed text fields are not supported." };
    return "text";
  }
  if (kind === "PDFCheckBox") return "checkbox";
  if (kind === "PDFRadioGroup") return "radio";
  if (kind === "PDFDropdown") return "dropdown";
  if (kind === "PDFOptionList") return "optionlist";
  if (kind === "PDFSignature") return { unsupported: "Signature fields are not fillable." };
  if (kind === "PDFButton") return { unsupported: "Push buttons do not carry a value." };
  return { unsupported: `Field type ${kind.replace(/^PDF/u, "")} is not supported.` };
}

function fieldOptions(field: PDFField, kind: FormFieldKind): string[] | undefined {
  if (kind !== "radio" && kind !== "dropdown" && kind !== "optionlist") return undefined;
  try { return (field as unknown as { getOptions(): string[] }).getOptions().slice(0, FORM_OPTION_LIMIT); }
  catch { return []; }
}

function currentValue(field: PDFField, kind: FormFieldKind): string | boolean | string[] | null {
  try {
    if (kind === "text") return (field as unknown as { getText(): string | undefined }).getText() ?? null;
    if (kind === "checkbox") return (field as unknown as { isChecked(): boolean }).isChecked();
    if (kind === "radio") return (field as unknown as { getSelected(): string | undefined }).getSelected() ?? null;
    const selected = (field as unknown as { getSelected(): string[] }).getSelected().slice(0, FORM_OPTION_LIMIT);
    // pdf-lib reports a dropdown as a one-element list even when it is not a
    // multi-select; only an option list exposes a real array.
    return kind === "dropdown" ? selected[0] ?? null : selected;
  } catch {
    return null;
  }
}

export function formFieldKind(field: PDFField) { return classify(field); }
export function formFieldValue(field: PDFField) { const kind = classify(field); return typeof kind === "string" ? currentValue(field, kind) : null; }

/**
 * Read the AcroForm inventory of an already-loaded, unencrypted document.
 * Nothing is written; repeated calls on the same document return equal data.
 */
export function readFormInventory(document: PDFDocument): FormInventory {
  const form = document.getForm();
  const hasXfa = form.hasXFA();
  let needAppearances = false;
  try {
    const acro = (form as unknown as { acroForm: { dict: PDFDict } }).acroForm.dict;
    needAppearances = String(acro.lookup(PDFName.of("NeedAppearances")) ?? "") === "true";
  } catch { needAppearances = false; }

  const allFields = form.getFields();
  if (allFields.length > FORM_FIELD_LIMIT) throw new FormFillError("FORM_UNSUPPORTED", `The form has more than ${FORM_FIELD_LIMIT} fields, which exceeds the supported limit.`);

  const fields: FormFieldDescriptor[] = [];
  const unsupported: UnsupportedFieldDescriptor[] = [];
  const counts = new Map<string, number>();
  for (const field of allFields) {
    const name = field.getName();
    counts.set(name, (counts.get(name) ?? 0) + 1);
    const kind = classify(field);
    if (typeof kind !== "string") { unsupported.push({ name, reason: kind.unsupported }); continue; }
    const pages = widgetPages(document, field);
    if (!pages.length) { unsupported.push({ name, reason: "The field has no widget on a page." }); continue; }
    const options = fieldOptions(field, kind);
    const descriptor: FormFieldDescriptor = {
      name, kind, page: pages[0],
      required: (() => { try { return field.isRequired(); } catch { return false; } })(),
      readOnly: (() => { try { return field.isReadOnly(); } catch { return true; } })(),
      value: currentValue(field, kind),
      ...(options ? { options } : {}),
    };
    if (kind === "text") {
      const text = field as unknown as { getMaxLength(): number | undefined; isMultiline(): boolean };
      const maxLength = text.getMaxLength();
      if (maxLength !== undefined) descriptor.maxLength = maxLength;
      descriptor.multiline = text.isMultiline();
    }
    fields.push(descriptor);
  }
  const duplicates = [...counts.entries()].filter(([, count]) => count > 1).map(([name]) => name);
  return { fields, unsupported, pages: document.getPageCount(), hasXfa, needAppearances, duplicates };
}

/**
 * Reject documents whose form cannot be modified safely.
 * Called before any write; `signed` is detected structurally by the engine.
 */
export function assertFillableDocument(inventory: FormInventory, flags: { signed: boolean; encrypted: boolean }) {
  if (flags.encrypted) throw new FormFillError("FORM_RESTRICTED", "Encrypted PDFs cannot be filled by this tool.");
  if (flags.signed) throw new FormFillError("FORM_RESTRICTED", "Signed or certified PDFs cannot be modified safely.");
  if (inventory.hasXfa) throw new FormFillError("FORM_UNSUPPORTED", "XFA forms are not supported; only AcroForm fields can be filled.");
  if (inventory.duplicates.length) throw new FormFillError("FORM_UNSUPPORTED", `Duplicated field names cannot be addressed unambiguously: ${inventory.duplicates.slice(0, 5).join(", ")}.`);
  if (!inventory.fields.length) throw new FormFillError("FORM_NOT_FOUND", "This PDF does not contain supported AcroForm fields.");
}

/** Apply validated values to a loaded document. Nothing is serialised here. */
export function applyFillValues(document: PDFDocument, values: Map<string, FormFillValue>) {
  const form = document.getForm();
  const applied: Array<{ name: string; kind: FormFieldKind; previous: string | boolean | string[] | null; next: FormFillValue }> = [];
  for (const [name, value] of values) {
    const field = form.getField(name);
    const kind = classify(field);
    if (typeof kind !== "string") throw new FormFillError("FORM_UNSUPPORTED", `Field "${name}" changed type while filling.`);
    const previous = currentValue(field, kind);
    try {
      if (kind === "text") (field as unknown as { setText(value: string): void }).setText(value as string);
      else if (kind === "checkbox") {
        if (value === true) (field as unknown as { check(): void }).check();
        else (field as unknown as { uncheck(): void }).uncheck();
      }
      else if (kind === "dropdown") (field as unknown as { select(value: string): void }).select(value as string);
      else if (kind === "radio") (field as unknown as { select(value: string): void }).select(value as string);
      else (field as unknown as { select(value: string[]): void }).select(value as string[]);
    } catch (error) {
      if (error instanceof FormFillError) throw error;
      // pdf-lib's own message can echo the offending value (e.g. an encoding
      // error quoting the text), and this message is persisted on the job row.
      // Only the field and the exception type are kept.
      const kind = error instanceof Error ? error.name : "Error";
      throw new FormFillError("FORM_FILL_FAILED", `Field "${name}" could not be filled (${kind}).`, { field: name });
    }
    applied.push({ name, kind, previous, next: value });
  }
  return applied;
}

type AppearanceIssue =
  | "WIDGET_NO_APPEARANCE"
  | "WIDGET_NO_NORMAL_APPEARANCE"
  | "APPEARANCE_NO_ON_STATE"
  | "WIDGET_NO_APPEARANCE_STATE"
  | "APPEARANCE_STATE_WITHOUT_STREAM";

export function appearanceProblems(field: PDFField): AppearanceIssue[] {
  const problems: AppearanceIssue[] = [];
  for (const widget of field.acroField.getWidgets()) {
    const api = widget.AP();
    if (!api) { problems.push("WIDGET_NO_APPEARANCE"); continue; }
    const normal = api.lookup(PDFName.of("N"));
    if (!normal) { problems.push("WIDGET_NO_NORMAL_APPEARANCE"); continue; }
    if (normal instanceof PDFDict) {
      const states = [...normal.keys()].filter((key) => String(key) !== "/Off");
      if (!states.length) { problems.push("APPEARANCE_NO_ON_STATE"); continue; }
      const state = widget.getAppearanceState()?.toString();
      if (!state) { problems.push("WIDGET_NO_APPEARANCE_STATE"); continue; }
      const entry = normal.get(PDFName.of(state.replace(/^\//u, "")));
      if (!entry) problems.push("APPEARANCE_STATE_WITHOUT_STREAM");
    }
  }
  return problems;
}

/**
 * Canonical value comparison for verification (FF-09).
 *
 * A text field has two empty spellings in a saved PDF: `/V ()` (which pdf-lib
 * reads as `""`) and no `/V` at all (which it reads as `undefined`). The field is
 * empty either way, so both normalise to `""`. Before this, a request that
 * cleared a field compared `""` against `null` and was rejected as
 * `FORM_OUTPUT_UNVERIFIED` — a *correct* write reported as a failure.
 *
 * Boolean and list values are compared exactly.
 */
function canonicalValue(kind: FormFieldKind, value: string | boolean | string[] | null): string | boolean | string[] | null {
  if (kind !== "text") return value;
  return value ?? "";
}

export function valuesEqual(kind: FormFieldKind, expected: string | boolean | string[] | null, actual: string | boolean | string[] | null): boolean {
  const left = canonicalValue(kind, expected);
  const right = canonicalValue(kind, actual);
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right)) return false;
    return left.length === right.length && left.every((item, index) => item === right[index]);
  }
  return left === right;
}

export type VerifiedForm = { inventory: FormInventory; pages: number; preserved: number };

/**
 * Independently re-open the produced bytes and verify:
 *   1. every requested value round-trips,
 *   2. every widget of a touched field still carries a usable normal appearance
 *      and (for state maps) a state that resolves to a stream,
 *   3. every field that was *not* part of the request keeps its previous value.
 *
 * A failure is reported as `FORM_OUTPUT_UNVERIFIED`, which the engine treats as
 * a validation failure — the output is never committed.
 */
export async function verifyFilledForm(bytes: Uint8Array, expected: Map<string, FormFillValue>, options: { untouched?: Map<string, string | boolean | string[] | null>; verifyAppearances?: boolean } = {}) {
  let document: PDFDocument;
  try { document = await PDFDocument.load(bytes, { ignoreEncryption: false }); }
  catch { throw new FormFillError("FORM_OUTPUT_UNVERIFIED", FORM_ERROR_MESSAGES.FORM_OUTPUT_UNVERIFIED); }
  const inventory = readFormInventory(document);
  const form = document.getForm();
  // Verification failures are persisted on the job and served by the status
  // API, so they carry counts of stable codes only — no field name, no value,
  // no submitted boolean (FF-08).
  const mismatches = new Map<string, number>();
  const note = (code: string) => mismatches.set(code, (mismatches.get(code) ?? 0) + 1);
  for (const [name, value] of expected) {
    const field = form.getFieldMaybe(name);
    if (!field) { note("FIELD_DISAPPEARED"); continue; }
    const kind = classify(field);
    const actual = typeof kind === "string" ? currentValue(field, kind) : null;
    if (typeof kind !== "string" || !valuesEqual(kind, value, actual)) note("VALUE_NOT_ROUND_TRIPPED");
    if (options.verifyAppearances !== false) for (const problem of appearanceProblems(field)) note(problem);
  }
  let preserved = 0;
  for (const [name, previous] of options.untouched ?? []) {
    if (expected.has(name)) continue;
    const field = form.getFieldMaybe(name);
    if (!field) { note("UNTOUCHED_FIELD_DISAPPEARED"); continue; }
    const kind = classify(field);
    const actual = typeof kind === "string" ? currentValue(field, kind) : null;
    if (typeof kind !== "string" || !valuesEqual(kind, previous, actual)) note("UNTOUCHED_FIELD_MODIFIED");
    else preserved += 1;
  }
  if (mismatches.size) {
    throw new FormFillError("FORM_OUTPUT_UNVERIFIED", FORM_ERROR_MESSAGES.FORM_OUTPUT_UNVERIFIED, {
      mismatches: [...mismatches].map(([code, count]) => ({ code, count })),
    });
  }
  return { inventory, pages: document.getPageCount(), preserved };
}
