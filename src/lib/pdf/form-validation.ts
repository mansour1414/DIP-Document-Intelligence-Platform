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
  FORM_ERROR_MESSAGES,
  FORM_FIELD_NAME_LIMIT,
  FORM_FIELDS_JSON_LIMIT,
  FORM_OPTION_LIMIT,
  FORM_VALUE_CHAR_LIMIT,
  FORM_VALUE_LIMIT,
  type FormFillErrorCode,
  type FormFillValue,
  type FormInventory,
  type FormValueIssue,
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
 *
 * All problems are collected; nothing is written unless every entry is valid.
 *
 * FF-08: issues carry a stable `FormValueIssue` code and the field's *index* in
 * the request — never the name and never the value. A field name is data too
 * (`patient.diagnosis`), and these issues reach the persisted job error and the
 * status API. The index is enough to point a client at the offending control.
 */
export function validateFillValues(inventory: FormInventory, values: Record<string, unknown>) {
  const entries = Object.entries(values);
  if (!entries.length) throw valueRejection([{ issue: "NO_VALUES" }]);
  if (entries.length > FORM_VALUE_LIMIT) throw valueRejection([{ issue: "TOO_MANY_VALUES", limit: FORM_VALUE_LIMIT }]);
  const byName = new Map(inventory.fields.map((field) => [field.name, field]));
  const unsupported = new Set(inventory.unsupported.map((field) => field.name));
  const issues: Array<{ issue: FormValueIssue; index: number; limit?: number }> = [];
  const normalized = new Map<string, FormFillValue>();
  entries.forEach(([name, raw], index) => {
    if (!name.trim() || name.length > FORM_FIELD_NAME_LIMIT) { issues.push({ issue: "NAME_INVALID", index }); return; }
    const field = byName.get(name);
    if (!field) {
      issues.push({ issue: unsupported.has(name) ? "UNSUPPORTED_FIELD" : "UNKNOWN_FIELD", index });
      return;
    }
    if (field.readOnly) { issues.push({ issue: "READ_ONLY_FIELD", index }); return; }
    if (field.kind === "text") {
      if (typeof raw !== "string") { issues.push({ issue: "TYPE_MISMATCH", index }); return; }
      if ([...raw].length > (field.maxLength ?? FORM_VALUE_CHAR_LIMIT)) { issues.push({ issue: "LENGTH_EXCEEDED", index, limit: field.maxLength ?? FORM_VALUE_CHAR_LIMIT }); return; }
      if (!field.multiline && /[\r\n]/u.test(raw)) { issues.push({ issue: "LINE_BREAK_IN_SINGLE_LINE", index }); return; }
      if (textControls.test(raw)) { issues.push({ issue: "CONTROL_CHARACTER", index }); return; }
      normalized.set(name, raw); return;
    }
    if (field.kind === "checkbox") {
      if (typeof raw !== "boolean") { issues.push({ issue: "TYPE_MISMATCH", index }); return; }
      normalized.set(name, raw); return;
    }
    if (field.kind === "radio" || field.kind === "dropdown") {
      if (typeof raw !== "string") { issues.push({ issue: "TYPE_MISMATCH", index }); return; }
      if (!(field.options ?? []).includes(raw)) { issues.push({ issue: "OPTION_NOT_OFFERED", index }); return; }
      normalized.set(name, raw); return;
    }
    if (!Array.isArray(raw) || raw.some((item) => typeof item !== "string")) { issues.push({ issue: "TYPE_MISMATCH", index }); return; }
    if (new Set(raw).size !== raw.length) { issues.push({ issue: "DUPLICATE_SELECTION", index }); return; }
    if ((raw as string[]).some((item) => !(field.options ?? []).includes(item))) { issues.push({ issue: "OPTION_NOT_OFFERED", index }); return; }
    normalized.set(name, raw as string[]);
  });
  if (issues.length) throw valueRejection(issues);
  return normalized;
}

/** Build the one error type used for every rejected-value outcome. */
function valueRejection(issues: Array<{ issue: FormValueIssue; index?: number; limit?: number }>) {
  // The field *index* identifies the offending control to a caller that sent the
  // map; the name does not travel, because a name is data (`patient.diagnosis`)
  // and this object is what a route or a log line may serialize.
  return new FormFillError("FORM_VALUE_INVALID", FORM_ERROR_MESSAGES.FORM_VALUE_INVALID, {
    issues: issues.map(({ issue, index, limit }) => ({ issue, ...(index === undefined ? {} : { index }), ...(limit === undefined ? {} : { limit }) })),
  });
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
 *
 * Every failure is `FORM_VALUE_INVALID` with a content-free message (FF-08);
 * structured detail lives in `details`.
 */
export function parseFieldsPayload(value: unknown): RawFieldMap {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw valueRejection([{ issue: "NAME_INVALID" }]);
  // `Object.entries` would silently keep only the last duplicate key, so a
  // duplicate is detected on the raw JSON text before it can be lost. (FF-10)
  const entries = Object.entries(value as Record<string, unknown>);
  if (!entries.length) throw valueRejection([{ issue: "NO_VALUES" }]);
  if (entries.length > FORM_VALUE_LIMIT) throw valueRejection([{ issue: "TOO_MANY_VALUES", limit: FORM_VALUE_LIMIT }]);
  const parsed: RawFieldMap = {};
  const issues: Array<{ issue: FormValueIssue; index: number; limit?: number }> = [];
  entries.forEach(([name, raw], index) => {
    if (!name.trim() || name.length > FORM_FIELD_NAME_LIMIT) { issues.push({ issue: "NAME_INVALID", index }); return; }
    if (name === "__proto__" || name === "constructor" || name === "prototype") { issues.push({ issue: "NAME_RESERVED", index }); return; }
    if (typeof raw === "boolean") { parsed[name] = raw; return; }
    if (typeof raw === "string") {
      if ([...raw].length > FORM_VALUE_CHAR_LIMIT) { issues.push({ issue: "VALUE_TOO_LONG", index, limit: FORM_VALUE_CHAR_LIMIT }); return; }
      parsed[name] = raw; return;
    }
    if (Array.isArray(raw) && raw.every((item) => typeof item === "string")) {
      if (raw.length > FORM_OPTION_LIMIT) { issues.push({ issue: "TOO_MANY_VALUES", index, limit: FORM_OPTION_LIMIT }); return; }
      if (raw.some((item) => [...item].length > FORM_VALUE_CHAR_LIMIT)) { issues.push({ issue: "VALUE_TOO_LONG", index, limit: FORM_VALUE_CHAR_LIMIT }); return; }
      parsed[name] = [...raw] as string[]; return;
    }
    issues.push({ issue: "TYPE_MISMATCH", index });
  });
  if (issues.length) throw valueRejection(issues);
  return parsed;
}

/**
 * Parse a `fields` multipart part.
 *
 * Two properties the review found missing (FF-10):
 *   - the 64 KiB limit is measured in **UTF-8 bytes**, not UTF-16 code units
 *     (35,121 Arabic characters are 70,121 bytes and used to pass);
 *   - **duplicate object keys are rejected**, because `JSON.parse` keeps only the
 *     last one and would silently accept an ambiguous request.
 */
export function parseFieldsPart(part: unknown): RawFieldMap {
  if (typeof part !== "string" || part.length === 0) throw valueRejection([{ issue: "NO_VALUES" }]);
  assertFieldsPayloadSize(part);
  assertNoDuplicateJsonKeys(part);
  let parsed: unknown;
  try { parsed = JSON.parse(part) as unknown; }
  catch { throw valueRejection([{ issue: "NAME_INVALID" }]); }
  return parseFieldsPayload(parsed);
}

/**
 * Reject a `fields` object whose JSON text repeats a key.
 *
 * `JSON.parse` keeps only the last duplicate, so an ambiguous request would be
 * accepted and silently reinterpreted. This walks the document with a minimal
 * recursive-descent parser (structure only, no coercion) and throws on a
 * repeated key *within the same object*. The same key in different objects is
 * legitimate — only siblings are compared.
 *
 * The scan is bounded by the payload size, which is checked first, and by
 * `MAX_JSON_DEPTH`, so it cannot be used as a stack-exhaustion vector.
 */
export function assertNoDuplicateJsonKeys(source: string) {
  const MAX_JSON_DEPTH = 64;
  let index = 0;
  const fail = (): never => { throw valueRejection([{ issue: "NAME_INVALID" }]); };

  const skipWhitespace = () => {
    while (index < source.length) {
      const character = source[index];
      if (character === " " || character === "\t" || character === "\n" || character === "\r") index += 1;
      else break;
    }
  };

  // Returns the decoded string; advancing past the closing quote.
  const readString = (): string => {
    if (source[index] !== '"') fail();
    index += 1;
    let value = "";
    while (index < source.length) {
      const character = source[index];
      if (character === '"') { index += 1; return value; }
      if (character === "\\") {
        const escape = source[index + 1];
        index += 2;
        if (escape === "u") {
          const hex = source.slice(index, index + 4);
          if (!/^[0-9a-fA-F]{4}$/u.test(hex)) fail();
          value += String.fromCharCode(Number.parseInt(hex, 16));
          index += 4;
        } else {
          const mapped: Record<string, string> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
          if (!(escape in mapped)) fail();
          value += mapped[escape];
        }
        continue;
      }
      if (character < " ") fail();
      value += character;
      index += 1;
    }
    return fail();
  };

  const skipValue = (depth: number): void => {
    if (depth > MAX_JSON_DEPTH) fail();
    skipWhitespace();
    const character = source[index];
    if (character === '"') { readString(); return; }
    if (character === "{") {
      index += 1;
      const keys = new Set<string>();
      skipWhitespace();
      if (source[index] === "}") { index += 1; return; }
      for (;;) {
        skipWhitespace();
        const key = readString();
        if (keys.has(key)) fail();
        keys.add(key);
        skipWhitespace();
        if (source[index] !== ":") fail();
        index += 1;
        skipValue(depth + 1);
        skipWhitespace();
        if (source[index] === ",") { index += 1; continue; }
        if (source[index] === "}") { index += 1; return; }
        fail();
      }
    }
    if (character === "[") {
      index += 1;
      skipWhitespace();
      if (source[index] === "]") { index += 1; return; }
      for (;;) {
        skipValue(depth + 1);
        skipWhitespace();
        if (source[index] === ",") { index += 1; continue; }
        if (source[index] === "]") { index += 1; return; }
        fail();
      }
    }
    const literal = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/u.exec(source.slice(index, index + 64));
    if (!literal) fail();
    index += literal?.[0].length ?? 0;
  };

  skipValue(0);
  skipWhitespace();
  if (index !== source.length) fail();
}

/**
 * Reject a payload whose serialised form exceeds the transport limit.
 *
 * Measured with `TextEncoder` (UTF-8), not `.length` (UTF-16 code units): Arabic
 * text is 2 bytes per code unit, so a string-length check understates the real
 * payload by half and lets oversized requests through. (FF-10)
 */
export function assertFieldsPayloadSize(serialized: string) {
  if (new TextEncoder().encode(serialized).byteLength > FORM_FIELDS_JSON_LIMIT) throw valueRejection([{ issue: "VALUE_TOO_LONG", limit: FORM_FIELDS_JSON_LIMIT }]);
}

/** UTF-8 byte length of a payload, exposed so callers can bound before parsing. */
export function fieldsPayloadBytes(serialized: string) { return new TextEncoder().encode(serialized).byteLength; }
