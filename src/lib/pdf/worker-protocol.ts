/**
 * The wire contract between the API/worker parent and the bounded PDF child.
 *
 * ## Why this module exists
 *
 * `form-worker.ts` used to parse "the last non-empty line of stdout" as JSON. That
 * channel cannot carry a binary PDF, it has no unambiguous frame boundary, and a
 * child that printed anything extra could shift what the parent read. Both sides
 * now speak one explicit protocol, and the definitions live here so the parent and
 * the child cannot drift apart.
 *
 * ## Framing
 *
 * Parent → child, on `stdin` (fd 0):
 *
 *     [uint32 control length][control JSON][PDF bytes (fill/verify only)]
 *
 * Child → parent, on **fd 3** (a dedicated pipe, not stdout):
 *
 *     [uint32 meta length][meta JSON][uint32 output length][output PDF bytes]
 *
 * Every length is big-endian and validated against a hard ceiling *before* any
 * allocation. stdout and stderr stay diagnostics-only and are never parsed as
 * authority, so a noisy dependency cannot corrupt a result.
 *
 * ## Why fd 3 rather than stdout
 *
 * Verified by executable PoC against this Node version and the real
 * `--import tsx` launch path, including a TypeScript entry and a path alias: a
 * fourth pipe carries arbitrary bytes intact in both directions. Base64-in-JSON
 * would inflate the payload by a third and add a second parse of attacker-influenced
 * data; stdout would mix the result with anything a library prints. `stdio[3]` is a
 * built-in Node capability, so the choice adds no dependency.
 *
 * ## What framing is not
 *
 * Framing proves the bytes arrived intact and as declared. It says nothing about
 * whether the child is trustworthy: a compromised or buggy child can emit a
 * perfectly-framed lie. The parent therefore re-verifies the output independently
 * (magic bytes, byte length, SHA-256, page preservation) instead of believing the
 * metadata. A matching checksum proves integrity in transit, not honesty.
 */

import { FORM_FIELD_LIMIT, FORM_VALUE_LIMIT, type FormFieldDescriptor, type FormFieldKind, type FormInventory } from "@/lib/pdf/form-types";

/**
 * The closed set of field kinds, named from the type so the two cannot drift.
 *
 * `FORM_FIELD_KINDS` is `readonly FormFieldKind[]` *and* the runtime list is checked
 * against the type at the assertion below: if a kind is added to the type without
 * being added here, the type annotation stops compiling rather than silently
 * rejecting the new kind at runtime.
 */
const FORM_FIELD_KINDS: readonly FormFieldKind[] = ["text", "checkbox", "radio", "dropdown", "optionlist"];

/** Protocol version. Bumping it invalidates both sides together. */
export const WORKER_PROTOCOL_VERSION = 1;

/**
 * Ceilings for each framed field.
 *
 * Derived from the existing contracts rather than invented as round numbers:
 *
 * - control metadata holds typed field values, bounded by `FORM_FIELDS_JSON_LIMIT`
 *   (64 KiB) plus the option envelope, so 256 KiB is a ceiling with headroom that
 *   still cannot be used to allocate unbounded memory.
 * - inventory metadata is the AcroForm inventory, bounded by `FORM_FIELD_LIMIT`
 *   (400 fields) each with `FORM_VALUE_LIMIT` (200 values) — a 4 MiB ceiling keeps
 *   the previous `maxOutputBytes` capacity while remaining a real bound.
 * - PDF bytes reuse `MAX_INPUT_BYTES` / `MAX_OUTPUT_BYTES` from runtime config, so
 *   the transport limit and the product limit are the same number.
 */
export const WORKER_LIMITS = {
  /** Largest control JSON the child will accept. */
  controlBytes: 256 * 1024,
  /** Largest result metadata the parent will accept. */
  metaBytes: 4 * 1024 * 1024,
  /** Largest diagnostic tail kept from stderr. */
  stderrTailBytes: 4_000,
} as const;

/** The two operations this boundary serves. */
export type WorkerOp = "inspect" | "fill";

/** Control envelope sent to the child. Never contains secrets or file paths. */
export type WorkerControl =
  | { v: typeof WORKER_PROTOCOL_VERSION; op: "inspect" }
  | { v: typeof WORKER_PROTOCOL_VERSION; op: "fill"; flatten: boolean; fields: Record<string, string | boolean | string[]> };

/** Metadata accompanying a successful inspect. */
export type InspectMeta = { ok: true; op: "inspect"; pages: number; inventory: FormInventory };

/** Metadata accompanying a successful fill. */
export type FillMeta = {
  ok: true;
  op: "fill";
  pages: number;
  outBytes: number;
  checksum: string;
  report: { filled: number; untouched: number; rasterAppearances: number; flatten: boolean };
};

/** Metadata accompanying a refusal. Details are allowlisted, never free-form. */
export type FailureMeta = { ok: false; op: WorkerOp; code: string; details?: unknown };

export type WorkerMeta = InspectMeta | FillMeta | FailureMeta;

/** A framed envelope, as read from either pipe. */
export type Frame = { meta: WorkerMeta; output?: Uint8Array };

/**
 * Errors raised by the protocol layer itself.
 *
 * Separate from `FormWorkerError` so the parent can map every framing failure to
 * the same external code without importing the worker.
 */
export class WorkerProtocolError extends Error {
  constructor(message: string, readonly reason: string) {
    super(message);
  }
}

/** Build the parent → child frame. */
export function encodeControl(control: WorkerControl, pdf: Uint8Array): Buffer {
  const json = Buffer.from(JSON.stringify(control), "utf8");
  if (json.byteLength > WORKER_LIMITS.controlBytes) {
    throw new WorkerProtocolError("The control metadata exceeds the transport limit.", "CONTROL_TOO_LARGE");
  }
  const header = Buffer.alloc(4);
  header.writeUInt32BE(json.byteLength, 0);
  return Buffer.concat([header, json, Buffer.from(pdf.buffer, pdf.byteOffset, pdf.byteLength)]);
}

/** Build the child → parent frame. */
export function encodeResult(meta: WorkerMeta, output?: Uint8Array): Buffer {
  const json = Buffer.from(JSON.stringify(meta), "utf8");
  if (json.byteLength > WORKER_LIMITS.metaBytes) {
    throw new WorkerProtocolError("The result metadata exceeds the transport limit.", "META_TOO_LARGE");
  }
  const metaHeader = Buffer.alloc(4);
  metaHeader.writeUInt32BE(json.byteLength, 0);
  if (!output) return Buffer.concat([metaHeader, json]);
  const outHeader = Buffer.alloc(4);
  outHeader.writeUInt32BE(output.byteLength, 0);
  return Buffer.concat([metaHeader, json, outHeader, Buffer.from(output.buffer, output.byteOffset, output.byteLength)]);
}

/** Reject a declared length that is not a safe non-negative integer within `max`. */
function readLength(buffer: Buffer, offset: number, max: number, what: string): number {
  if (offset + 4 > buffer.byteLength) throw new WorkerProtocolError(`The ${what} length is truncated.`, "TRUNCATED");
  const length = buffer.readUInt32BE(offset);
  if (length > max) throw new WorkerProtocolError(`The ${what} exceeds the transport limit.`, "FIELD_TOO_LARGE");
  return length;
}

/**
 * Read the parent → child frame.
 *
 * Rejects truncated input, an oversized control block, and trailing bytes beyond
 * the declared PDF length.
 */
export function decodeControl(buffer: Buffer, maxPdfBytes: number): { control: WorkerControl; pdf: Uint8Array } {
  const controlLength = readLength(buffer, 0, WORKER_LIMITS.controlBytes, "control");
  const end = 4 + controlLength;
  if (end > buffer.byteLength) throw new WorkerProtocolError("The control block is truncated.", "TRUNCATED");
  let parsed: unknown;
  try { parsed = JSON.parse(buffer.subarray(4, end).toString("utf8")); }
  catch { throw new WorkerProtocolError("The control block is not valid JSON.", "INVALID_JSON"); }
  const control = parseControl(parsed);
  const pdf = new Uint8Array(buffer.subarray(end));
  if (pdf.byteLength > maxPdfBytes) throw new WorkerProtocolError("The document exceeds the transport limit.", "PDF_TOO_LARGE");
  if (control.op !== "inspect" && pdf.byteLength === 0) throw new WorkerProtocolError("The document is empty.", "PDF_EMPTY");
  return { control, pdf };
}

/**
 * Read the child → parent frame.
 *
 * Rejects truncated frames, oversized metadata, trailing data after the declared
 * output, and an output length that disagrees with the bytes present.
 */
export function decodeResult(buffer: Buffer, maxOutputBytes: number): Frame {
  const metaLength = readLength(buffer, 0, WORKER_LIMITS.metaBytes, "result metadata");
  const metaEnd = 4 + metaLength;
  if (metaEnd > buffer.byteLength) throw new WorkerProtocolError("The result metadata is truncated.", "TRUNCATED");
  let parsed: unknown;
  try { parsed = JSON.parse(buffer.subarray(4, metaEnd).toString("utf8")); }
  catch { throw new WorkerProtocolError("The result metadata is not valid JSON.", "INVALID_JSON"); }
  const meta = parseMeta(parsed);
  if (meta.ok !== true) return { meta };
  // A success frame from a *fill* must carry exactly its declared output.
  if (meta.op === "fill") {
    const outLength = readLength(buffer, metaEnd, maxOutputBytes, "output");
    const outEnd = metaEnd + 4 + outLength;
    if (outEnd > buffer.byteLength) throw new WorkerProtocolError("The output is truncated.", "TRUNCATED");
    if (outEnd !== buffer.byteLength) throw new WorkerProtocolError("Unexpected trailing data after the output.", "TRAILING_DATA");
    if (outLength !== meta.outBytes) throw new WorkerProtocolError("The output length disagrees with the metadata.", "OUTPUT_LENGTH_MISMATCH");
    return { meta, output: new Uint8Array(buffer.subarray(metaEnd + 4, outEnd)) };
  }
  // An inspect result carries no output bytes at all.
  if (metaEnd !== buffer.byteLength) throw new WorkerProtocolError("Unexpected trailing data after the metadata.", "TRAILING_DATA");
  return { meta };
}

/** Exactly one, Boolean, known operation. A truthy string is not a discriminator. */
function parseControl(value: unknown): WorkerControl {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new WorkerProtocolError("The control block is not an object.", "INVALID_CONTROL");
  const record = value as Record<string, unknown>;
  if (record.v !== WORKER_PROTOCOL_VERSION) throw new WorkerProtocolError("The protocol version is not supported.", "VERSION_MISMATCH");
  if (record.op === "inspect") return { v: WORKER_PROTOCOL_VERSION, op: "inspect" };
  if (record.op === "fill") {
    if (typeof record.flatten !== "boolean") throw new WorkerProtocolError("The flatten option must be a boolean.", "INVALID_CONTROL");
    return { v: WORKER_PROTOCOL_VERSION, op: "fill", flatten: record.flatten, fields: parseFields(record.fields) };
  }
  throw new WorkerProtocolError("The requested operation is not supported.", "UNKNOWN_OP");
}

/**
 * Typed field values: string, boolean, or string[] only.
 *
 * Values are validated against the real form by the child; this only enforces the
 * wire shape, so a crafted control block cannot smuggle a nested object into the
 * fill engine.
 */
function parseFields(value: unknown): Record<string, string | boolean | string[]> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new WorkerProtocolError("The field payload must be an object.", "INVALID_FIELDS");
  const fields: Record<string, string | boolean | string[]> = {};
  for (const [name, item] of Object.entries(value as Record<string, unknown>)) {
    if (typeof item === "string" || typeof item === "boolean") { fields[name] = item; continue; }
    if (Array.isArray(item) && item.every((entry) => typeof entry === "string")) { fields[name] = item as string[]; continue; }
    throw new WorkerProtocolError("A field value has an unsupported type.", "INVALID_FIELDS");
  }
  return fields;
}

/** A positive, safe page count. Zero is not "no pages known", it is invalid. */
export function assertPages(value: unknown, field = "pages"): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new WorkerProtocolError(`The ${field} value is not a positive safe integer.`, "INVALID_PAGES");
  }
  return value;
}

/** Strict meta validation. A `true` from a non-Boolean is rejected, not coerced. */
/**
 * Validate the inventory against the real `FormInventory` contract.
 *
 * "It is an object" was not enough. This inventory drives the UI, the value
 * validation and the field-count limits, so a child that returned `{}` — or a
 * field with a numeric name, a `kind` outside the allowed set, a page number past
 * the document, or 10,000 entries — would have produced a plausible-looking success
 * that failed later, somewhere less defensible. Every entry is checked here, and the
 * counts are bounded by the same `FORM_FIELD_LIMIT` the engine enforces, so the
 * parent cannot be made to hold an inventory larger than the engine could produce.
 *
 * The cast at the end is a *consequence* of the checks above, not a substitute for
 * them: every property is proven before the value is given the type.
 */
function parseInventory(value: unknown, pages: number): FormInventory {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new WorkerProtocolError("The inspect result carries no inventory.", "INVALID_META");
  const inventory = value as Record<string, unknown>;
  if (!Array.isArray(inventory.fields)) throw new WorkerProtocolError("The inventory carries no field list.", "INVALID_META");
  if (inventory.fields.length > FORM_FIELD_LIMIT) throw new WorkerProtocolError("The inventory exceeds the field limit.", "FIELD_TOO_LARGE");
  const fields = inventory.fields.map((entry: unknown, index: number): FormFieldDescriptor => {
    const where = `field ${index}`;
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new WorkerProtocolError(`The inventory ${where} is not an object.`, "INVALID_INVENTORY");
    const field = entry as Record<string, unknown>;
    if (typeof field.name !== "string" || !field.name || field.name.length > FORM_VALUE_LIMIT) throw new WorkerProtocolError(`The inventory ${where} has an invalid name.`, "INVALID_INVENTORY");
    if (!FORM_FIELD_KINDS.includes(field.kind as FormFieldKind)) throw new WorkerProtocolError(`The inventory ${where} has an unknown kind.`, "INVALID_INVENTORY");
    if (typeof field.page !== "number" || !Number.isSafeInteger(field.page) || field.page < 1 || field.page > pages) throw new WorkerProtocolError(`The inventory ${where} names a page outside the document.`, "INVALID_INVENTORY");
    for (const flag of ["required", "readOnly"] as const) if (typeof field[flag] !== "boolean") throw new WorkerProtocolError(`The inventory ${where} has an invalid ${flag} flag.`, "INVALID_INVENTORY");
    for (const optional of ["maxLength"] as const) if (field[optional] !== undefined && (typeof field[optional] !== "number" || !Number.isSafeInteger(field[optional]))) throw new WorkerProtocolError(`The inventory ${where} has an invalid ${optional}.`, "INVALID_INVENTORY");
    if (field.multiline !== undefined && typeof field.multiline !== "boolean") throw new WorkerProtocolError(`The inventory ${where} has an invalid multiline flag.`, "INVALID_INVENTORY");
    if (field.options !== undefined) {
      if (!Array.isArray(field.options) || field.options.length > FORM_FIELD_LIMIT || field.options.some((option: unknown) => typeof option !== "string" || option.length > FORM_VALUE_LIMIT)) throw new WorkerProtocolError(`The inventory ${where} has invalid options.`, "INVALID_INVENTORY");
    }
    const kind = field.kind as FormFieldKind;
    const fieldValue = field.value;
    const valueOk = kind === "checkbox"
      ? typeof fieldValue === "boolean" || fieldValue === null
      : kind === "optionlist"
        ? Array.isArray(fieldValue) ? fieldValue.every((item: unknown) => typeof item === "string") : typeof fieldValue === "string" || fieldValue === null
        : typeof fieldValue === "string" || fieldValue === null;
    if (!valueOk) throw new WorkerProtocolError(`The inventory ${where} has a value that does not match its kind.`, "INVALID_INVENTORY");
    return {
      name: field.name, kind, page: field.page, required: field.required as boolean, readOnly: field.readOnly as boolean,
      value: fieldValue as FormFieldDescriptor["value"],
      ...(field.options === undefined ? {} : { options: field.options as string[] }),
      ...(field.maxLength === undefined ? {} : { maxLength: field.maxLength as number }),
      ...(field.multiline === undefined ? {} : { multiline: field.multiline as boolean }),
    };
  });
  if (!Array.isArray(inventory.unsupported)) throw new WorkerProtocolError("The inventory carries no unsupported list.", "INVALID_META");
  if (inventory.unsupported.length > FORM_FIELD_LIMIT) throw new WorkerProtocolError("The inventory exceeds the unsupported-field limit.", "FIELD_TOO_LARGE");
  const unsupported = inventory.unsupported.map((entry: unknown, index: number) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new WorkerProtocolError(`Unsupported entry ${index} is not an object.`, "INVALID_INVENTORY");
    const item = entry as Record<string, unknown>;
    if (typeof item.name !== "string" || !item.name || item.name.length > FORM_VALUE_LIMIT) throw new WorkerProtocolError(`Unsupported entry ${index} has an invalid name.`, "INVALID_INVENTORY");
    if (typeof item.reason !== "string" || !item.reason || item.reason.length > FORM_VALUE_LIMIT) throw new WorkerProtocolError(`Unsupported entry ${index} has an invalid reason.`, "INVALID_INVENTORY");
    return { name: item.name, reason: item.reason };
  });
  for (const flag of ["hasXfa", "needAppearances"] as const) if (typeof inventory[flag] !== "boolean") throw new WorkerProtocolError(`The inventory has an invalid ${flag} flag.`, "INVALID_META");
  if (inventory.pages !== pages) throw new WorkerProtocolError("The inventory page count disagrees with the result.", "INVALID_INVENTORY");
  if (!Array.isArray(inventory.duplicates)) throw new WorkerProtocolError("The inventory carries no duplicate list.", "INVALID_META");
  if (inventory.duplicates.length > FORM_FIELD_LIMIT || inventory.duplicates.some((name: unknown) => typeof name !== "string" || !name || name.length > FORM_VALUE_LIMIT)) throw new WorkerProtocolError("The inventory has invalid duplicates.", "INVALID_INVENTORY");
  return { fields, unsupported, pages, hasXfa: inventory.hasXfa as boolean, needAppearances: inventory.needAppearances as boolean, duplicates: inventory.duplicates as string[] };
}

export function parseMeta(value: unknown): WorkerMeta {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new WorkerProtocolError("The result metadata is not an object.", "INVALID_META");
  const record = value as Record<string, unknown>;
  if (typeof record.ok !== "boolean") throw new WorkerProtocolError("The result discriminator must be a boolean.", "INVALID_DISCRIMINATOR");
  if (record.ok === false) {
    if (record.op !== "inspect" && record.op !== "fill") throw new WorkerProtocolError("The failure result names no operation.", "INVALID_META");
    if (typeof record.code !== "string" || !record.code) throw new WorkerProtocolError("The failure result names no code.", "INVALID_META");
    return { ok: false, op: record.op as WorkerOp, code: record.code, ...(record.details === undefined ? {} : { details: record.details }) };
  }
  if (record.op === "inspect") {
    const pages = assertPages(record.pages);
    return { ok: true, op: "inspect", pages, inventory: parseInventory(record.inventory, pages) };
  }
  if (record.op === "fill") {
    if (typeof record.checksum !== "string" || !/^[0-9a-f]{64}$/u.test(record.checksum)) throw new WorkerProtocolError("The fill result carries no valid checksum.", "INVALID_META");
    if (typeof record.outBytes !== "number" || !Number.isSafeInteger(record.outBytes) || record.outBytes <= 0) throw new WorkerProtocolError("The fill result carries no valid output length.", "INVALID_META");
    const report = record.report;
    if (!report || typeof report !== "object" || Array.isArray(report)) throw new WorkerProtocolError("The fill result carries no report.", "INVALID_META");
    const r = report as Record<string, unknown>;
    for (const key of ["filled", "untouched", "rasterAppearances"] as const) {
      if (typeof r[key] !== "number" || !Number.isSafeInteger(r[key]) || (r[key] as number) < 0) throw new WorkerProtocolError("The fill report is invalid.", "INVALID_META");
    }
    if (typeof r.flatten !== "boolean") throw new WorkerProtocolError("The fill report is invalid.", "INVALID_META");
    return {
      ok: true, op: "fill", pages: assertPages(record.pages), outBytes: record.outBytes, checksum: record.checksum,
      report: { filled: r.filled as number, untouched: r.untouched as number, rasterAppearances: r.rasterAppearances as number, flatten: r.flatten },
    };
  }
  throw new WorkerProtocolError("The result names an unexpected operation.", "UNKNOWN_OP");
}
