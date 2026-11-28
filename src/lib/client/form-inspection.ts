/**
 * Client contract for `POST /api/fill-forms/inspect`.
 *
 * Filling a form is a two-step interaction that the one-shot job contract does
 * not cover: the browser has to learn the field list before it can render
 * inputs. This module owns that read-only call — the workspace never builds a
 * request itself — and normalises the response so a malformed payload degrades
 * into a clear error instead of an undefined-rendering crash.
 *
 * Inspection is *advisory for rendering only*. The worker re-reads the inventory
 * from the uploaded bytes and validates every submitted value against it, so
 * nothing here can widen what the server accepts.
 */
import type { FormInventory } from "@/lib/pdf/form-types";
import type { FetchLike } from "@/lib/client/server-tool-job";

export class FormInspectionError extends Error {
  readonly code: string;
  readonly status?: number;

  constructor(code: string, message: string, status?: number) {
    super(message);
    this.name = "FormInspectionError";
    this.code = code;
    this.status = status;
  }
}

const asRecord = (value: unknown): Record<string, unknown> | undefined =>
  value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;

/** Read an inventory response defensively; unknown shapes are rejected, not defaulted. */
export function readInventoryResponse(payload: unknown): FormInventory {
  const record = asRecord(payload);
  const inventory = asRecord(record?.inventory);
  if (!inventory) throw new FormInspectionError("INSPECTION_FAILED", "The form could not be inspected.");
  const fields = Array.isArray(inventory.fields) ? inventory.fields : null;
  const unsupported = Array.isArray(inventory.unsupported) ? inventory.unsupported : [];
  const duplicates = Array.isArray(inventory.duplicates) ? inventory.duplicates.filter((name): name is string => typeof name === "string") : [];
  if (!fields) throw new FormInspectionError("INSPECTION_FAILED", "The form inventory was malformed.");
  const kinds = new Set(["text", "checkbox", "radio", "dropdown", "optionlist"]);
  const parsed = fields.flatMap((entry) => {
    const field = asRecord(entry);
    if (!field || typeof field.name !== "string" || typeof field.kind !== "string" || !kinds.has(field.kind)) return [];
    return [{
      name: field.name,
      kind: field.kind as FormInventory["fields"][number]["kind"],
      page: typeof field.page === "number" ? field.page : 1,
      required: field.required === true,
      readOnly: field.readOnly === true,
      ...(Array.isArray(field.options) ? { options: field.options.filter((option): option is string => typeof option === "string") } : {}),
      value: (typeof field.value === "string" || typeof field.value === "boolean" || Array.isArray(field.value) ? field.value : null) as FormInventory["fields"][number]["value"],
      ...(typeof field.maxLength === "number" ? { maxLength: field.maxLength } : {}),
      ...(typeof field.multiline === "boolean" ? { multiline: field.multiline } : {}),
    }];
  });
  return {
    fields: parsed,
    unsupported: unsupported.flatMap((entry) => {
      const item = asRecord(entry);
      return item && typeof item.name === "string" && typeof item.reason === "string" ? [{ name: item.name, reason: item.reason }] : [];
    }),
    pages: typeof inventory.pages === "number" ? inventory.pages : 1,
    hasXfa: inventory.hasXfa === true,
    needAppearances: inventory.needAppearances === true,
    duplicates,
  };
}

export type InspectInput = { file: Blob & { name?: string }; fetchImpl?: FetchLike; signal?: AbortSignal };

/** Read the AcroForm inventory of a PDF without creating a job or storing bytes. */
export async function inspectFillForm(input: InspectInput): Promise<FormInventory> {
  const fetchImpl = input.fetchImpl ?? fetch;
  const form = new FormData();
  form.append("file", input.file, input.file.name ?? "form.pdf");
  const response = await fetchImpl("/api/fill-forms/inspect", {
    method: "POST",
    body: form,
    cache: "no-store",
    ...(input.signal ? { signal: input.signal } : {}),
  });
  let payload: unknown = undefined;
  try { payload = await response.json(); } catch { payload = undefined; }
  const record = asRecord(payload);
  if (response.status === 401) throw new FormInspectionError("AUTH_REQUIRED", "Sign in to fill a form.", 401);
  if (!response.ok) {
    throw new FormInspectionError(
      typeof record?.code === "string" ? record.code : "INSPECTION_FAILED",
      typeof record?.message === "string" ? record.message : "The form could not be inspected.",
      response.status,
    );
  }
  return readInventoryResponse(payload);
}
