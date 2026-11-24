/**
 * `fill-forms` — the pure validation contract (no `pdf-lib`, no DOM, no Node).
 *
 * Everything in this module is a function of plain data: error codes, payload
 * shape checking, value validation against an already-read inventory, and the
 * payload-size guard. It is imported by
 *   - the API route (before a job is queued),
 *   - the orchestrator (before uploads are read),
 *   - the document worker (again, authoritatively), and
 *   - the browser form (to validate as the user types).
 *
 * Sharing one implementation is what makes the client-side experience and the
 * server-side rejection agree on *why* a value is refused. The PDF-touching
 * half lives in `form-schema.ts`.
 */
import {
  FORM_FIELD_NAME_LIMIT,
  FORM_FIELDS_JSON_LIMIT,
  FORM_OPTION_LIMIT,
  FORM_VALUE_CHAR_LIMIT,
  FORM_VALUE_LIMIT,
  type FormFillErrorCode,
  type FormFillValue,
  type FormInventory,
  type RawFieldMap,
} from "@/lib/pdf/form-types";

/** C0/C1 control characters that must never reach a PDF string. */
const textControls = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u;

export class FormFillError extends Error {
  constructor(public readonly code: FormFillErrorCode, message: string, public readonly details?: Record<string, unknown>) {
    super(message);
    this.name = "FormFillError";
  }
}

/**
 * Validate a caller-supplied `{ name: value }` map against the inventory.
 * All problems are collected; nothing is written unless every entry is valid.
 */
export function validateFillValues(inventory: FormInventory, values: Record<string, unknown>) {
  const entries = Object.entries(values);
  if (!entries.length) throw new FormFillError("FORM_VALUE_INVALID", "At least one field value is required.");
  if (entries.length > FORM_VALUE_LIMIT) throw new FormFillError("FORM_VALUE_INVALID", `No more than ${FORM_VALUE_LIMIT} fields may be filled in one request.`);
  const byName = new Map(inventory.fields.map((field) => [field.name, field]));
  const unsupported = new Map(inventory.unsupported.map((field) => [field.name, field.reason]));
  const issues: string[] = [];
  const normalized = new Map<string, FormFillValue>();
  for (const [name, raw] of entries) {
    if (!name.trim()) { issues.push("Field names must not be blank."); continue; }
    if (name.length > FORM_FIELD_NAME_LIMIT) { issues.push(`Field name "${name.slice(0, 40)}…" exceeds the ${FORM_FIELD_NAME_LIMIT} character limit.`); continue; }
    const field = byName.get(name);
    if (!field) {
      const reason = unsupported.get(name);
      issues.push(reason ? `Field "${name}" cannot be filled: ${reason}` : `Field "${name}" does not exist in this form.`);
      continue;
    }
    if (field.readOnly) { issues.push(`Field "${name}" is read-only.`); continue; }
    if (field.kind === "text") {
      if (typeof raw !== "string") { issues.push(`Field "${name}" expects a string value.`); continue; }
      if ([...raw].length > (field.maxLength ?? FORM_VALUE_CHAR_LIMIT)) { issues.push(`Field "${name}" exceeds its ${field.maxLength ?? FORM_VALUE_CHAR_LIMIT} character limit.`); continue; }
      if (!field.multiline && /[\r\n]/u.test(raw)) { issues.push(`Field "${name}" is single-line and cannot contain line breaks.`); continue; }
      if (textControls.test(raw)) { issues.push(`Field "${name}" contains an unsupported control character.`); continue; }
      // NOTE: issue messages name the field and the rule, never the submitted
      // value — they are returned to the caller, persisted as the job error and
      // copied into logs.
      normalized.set(name, raw); continue;
    }
    if (field.kind === "checkbox") {
      if (typeof raw !== "boolean") { issues.push(`Field "${name}" expects a boolean value.`); continue; }
      normalized.set(name, raw); continue;
    }
    if (field.kind === "radio" || field.kind === "dropdown") {
      if (typeof raw !== "string") { issues.push(`Field "${name}" expects one option string.`); continue; }
      if (!(field.options ?? []).includes(raw)) { issues.push(`Field "${name}" does not offer the selected option.`); continue; }
      normalized.set(name, raw); continue;
    }
    if (!Array.isArray(raw) || raw.some((item) => typeof item !== "string")) { issues.push(`Field "${name}" expects an array of option strings.`); continue; }
    if (new Set(raw).size !== raw.length) { issues.push(`Field "${name}" contains duplicate selections.`); continue; }
    if ((raw as string[]).some((item) => !(field.options ?? []).includes(item))) { issues.push(`Field "${name}" does not offer one of the selected options.`); continue; }
    normalized.set(name, raw as string[]);
  }
  if (issues.length) throw new FormFillError("FORM_VALUE_INVALID", issues.join(" "), { issues });
  return normalized;
}

/** Snapshot of every supported field value, used to prove untouched fields survive. */
export function valueSnapshot(inventory: FormInventory) {
  return new Map(inventory.fields.map((field) => [field.name, field.value]));
}

/**
 * Shape validation of the transport payload, independent of any PDF.
 *
 * Runs in the API/orchestrator boundary *before* a job is queued and again in
 * the worker, so a malformed payload can never reach the engine. Semantic
 * validation against the actual form inventory happens later in
 * `validateFillValues`.
 */
export function parseFieldsPayload(value: unknown): RawFieldMap {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new FormFillError("FORM_VALUE_INVALID", "Form fields must be a JSON object of field name to value.");
  const entries = Object.entries(value as Record<string, unknown>);
  if (!entries.length) throw new FormFillError("FORM_VALUE_INVALID", "At least one field value is required.");
  if (entries.length > FORM_VALUE_LIMIT) throw new FormFillError("FORM_VALUE_INVALID", `No more than ${FORM_VALUE_LIMIT} fields may be filled in one request.`);
  const parsed: RawFieldMap = {};
  for (const [name, raw] of entries) {
    if (!name.trim() || name.length > FORM_FIELD_NAME_LIMIT) throw new FormFillError("FORM_VALUE_INVALID", "Field names must be between 1 and 200 characters.");
    if (name === "__proto__" || name === "constructor" || name === "prototype") throw new FormFillError("FORM_VALUE_INVALID", "Field names must not use reserved object keys.");
    if (typeof raw === "boolean") { parsed[name] = raw; continue; }
    if (typeof raw === "string") {
      if ([...raw].length > FORM_VALUE_CHAR_LIMIT) throw new FormFillError("FORM_VALUE_INVALID", `Field "${name}" exceeds the ${FORM_VALUE_CHAR_LIMIT} character limit.`);
      parsed[name] = raw; continue;
    }
    if (Array.isArray(raw) && raw.every((item) => typeof item === "string")) {
      if (raw.length > FORM_OPTION_LIMIT) throw new FormFillError("FORM_VALUE_INVALID", `Field "${name}" selects more than ${FORM_OPTION_LIMIT} options.`);
      if (raw.some((item) => [...item].length > FORM_VALUE_CHAR_LIMIT)) throw new FormFillError("FORM_VALUE_INVALID", `Field "${name}" contains an option that is too long.`);
      parsed[name] = [...raw] as string[]; continue;
    }
    throw new FormFillError("FORM_VALUE_INVALID", `Field "${name}" must be a string, a boolean, or an array of strings.`);
  }
  return parsed;
}

/** Reject a payload whose serialised form exceeds the transport limit. */
export function assertFieldsPayloadSize(serialized: string) {
  if (serialized.length > FORM_FIELDS_JSON_LIMIT) throw new FormFillError("FORM_VALUE_INVALID", `The form field payload exceeds ${Math.round(FORM_FIELDS_JSON_LIMIT / 1024)} KB.`);
}
