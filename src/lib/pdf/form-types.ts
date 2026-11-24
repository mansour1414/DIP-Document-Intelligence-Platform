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

/** Bounds shared by the browser form, the API boundary and the worker. */
export const FORM_FIELD_LIMIT = 400;
export const FORM_VALUE_LIMIT = 200;
export const FORM_VALUE_CHAR_LIMIT = 4_000;
export const FORM_OPTION_LIMIT = 200;
export const FORM_FIELD_NAME_LIMIT = 200;
export const FORM_FIELDS_JSON_LIMIT = 64 * 1024;
