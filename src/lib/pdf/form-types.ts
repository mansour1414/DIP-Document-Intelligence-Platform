/**
 * `fill-forms` — the shared, dependency-free data contract.
 *
 * Declarations only: this module is erased at build time, so browser code can
 * import the descriptor types without pulling `pdf-lib` into the client bundle.
 * The runtime implementation (inventory, validation, verification) stays in
 * `form-schema.ts`, which re-exports these types.
 */

export type FormFieldKind = "text" | "checkbox" | "radio" | "dropdown" | "optionlist";

export type FormFieldDescriptor = {
  name: string;
  kind: FormFieldKind;
  page: number;
  required: boolean;
  readOnly: boolean;
  options?: string[];
  value: string | boolean | string[] | null;
  maxLength?: number;
  multiline?: boolean;
};

export type UnsupportedFieldDescriptor = { name: string; reason: string };

export type FormInventory = {
  fields: FormFieldDescriptor[];
  unsupported: UnsupportedFieldDescriptor[];
  pages: number;
  hasXfa: boolean;
  needAppearances: boolean;
  duplicates: string[];
};

export type FormFillValue = string | boolean | string[];

export type RawFieldMap = Record<string, FormFillValue>;

export type FormFillErrorCode =
  | "FORM_NOT_FOUND"
  | "FORM_UNSUPPORTED"
  | "FORM_RESTRICTED"
  | "FORM_VALUE_INVALID"
  | "FORM_FILL_FAILED"
  | "FORM_OUTPUT_UNVERIFIED";

/**
 * Content-free messages, allowlisted by code (FF-08).
 *
 * These strings are persisted on `job.error.message`, replayed by the status API
 * and copied into logs. They therefore describe a *rule*, never data: no
 * submitted value, no boolean, and no field name — a field name can itself be
 * sensitive (`patient.diagnosis`, `employee.salary`).
 *
 * Detail for debugging travels separately in `FormFillError.details`, which is
 * structured (codes and counts) and never persisted by the pipeline.
 */
export const FORM_ERROR_MESSAGES: Readonly<Record<FormFillErrorCode, string>> = {
  FORM_NOT_FOUND: "This PDF does not contain supported AcroForm fields.",
  FORM_UNSUPPORTED: "This document uses a form feature that is not supported.",
  FORM_RESTRICTED: "This document is encrypted, signed or certified and cannot be modified.",
  FORM_VALUE_INVALID: "One or more submitted form values are not valid for this form.",
  FORM_FILL_FAILED: "The form values could not be written to this document.",
  FORM_OUTPUT_UNVERIFIED: "The filled output could not be verified and was not returned.",
};

/** Reasons a submitted value is rejected; each remains content-free. */
export const FORM_VALUE_ISSUES = [
  "UNKNOWN_FIELD",
  "UNSUPPORTED_FIELD",
  "READ_ONLY_FIELD",
  "TYPE_MISMATCH",
  "LENGTH_EXCEEDED",
  "LINE_BREAK_IN_SINGLE_LINE",
  "CONTROL_CHARACTER",
  "OPTION_NOT_OFFERED",
  "DUPLICATE_SELECTION",
  "NAME_INVALID",
  "NAME_RESERVED",
  "VALUE_TOO_LONG",
  "TOO_MANY_VALUES",
  "NO_VALUES",
  "UNRENDERABLE_SCRIPT",
] as const;
export type FormValueIssue = (typeof FORM_VALUE_ISSUES)[number];

/** Bounds shared by the browser form, the API boundary and the worker. */
export const FORM_FIELD_LIMIT = 400;
export const FORM_VALUE_LIMIT = 200;
export const FORM_VALUE_CHAR_LIMIT = 4_000;
export const FORM_OPTION_LIMIT = 200;
export const FORM_FIELD_NAME_LIMIT = 200;
export const FORM_FIELDS_JSON_LIMIT = 64 * 1024;
