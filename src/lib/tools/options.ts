export type ToolOptionValue = string | number | boolean;
export type ToolOptions = Record<string, ToolOptionValue>;

type OptionProperty = {
  type: "string" | "number" | "integer" | "boolean";
  enum?: readonly ToolOptionValue[];
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  default?: ToolOptionValue;
};

export type ToolOptionContract = {
  version: "1";
  required?: readonly string[];
  properties: Readonly<Record<string, OptionProperty>>;
  validate?: (options: ToolOptions) => string | undefined;
};

const empty = (): ToolOptionContract => ({ version: "1", properties: {} });
const pageRange = { type: "string", minLength: 1, maxLength: 2_000, pattern: "^[0-9,\\s-]+$" } as const;
const quality = { type: "number", minimum: 0.45, maximum: 0.95 } as const;
const locale = { type: "string", enum: ["en", "ar"] } as const;

export const toolOptionContracts: Readonly<Record<string, ToolOptionContract>> = {
  "merge-pdf": empty(),
  "split-pdf": { version: "1", properties: { pages: pageRange } },
  "compress-pdf": { version: "1", properties: { quality } },
  "organize-pdf": { version: "1", required: ["pages"], properties: { pages: pageRange } },
  "rotate-pdf": { version: "1", properties: { rotation: { type: "integer", enum: [90, 180, 270], default: 90 } } },
  "delete-pages": { version: "1", required: ["pages"], properties: { pages: pageRange } },
  "extract-pages": { version: "1", required: ["pages"], properties: { pages: pageRange } },
  "jpg-to-pdf": empty(),
  "pdf-to-jpg": { version: "1", properties: { quality } },
  "watermark-pdf": { version: "1", required: ["watermark"], properties: { watermark: { type: "string", minLength: 1, maxLength: 80 } } },
  "crop-pdf": {
    version: "1",
    properties: {
      topPercent: { type: "number", minimum: 0, maximum: 45, default: 0 },
      rightPercent: { type: "number", minimum: 0, maximum: 45, default: 0 },
      bottomPercent: { type: "number", minimum: 0, maximum: 45, default: 0 },
      leftPercent: { type: "number", minimum: 0, maximum: 45, default: 0 },
    },
    validate: (options) => {
      const values = ["topPercent", "rightPercent", "bottomPercent", "leftPercent"].map((key) => Number(options[key] ?? 0));
      if (values.every((value) => value === 0)) return "At least one crop edge must be greater than zero.";
      if (values[1] + values[3] >= 95 || values[0] + values[2] >= 95) return "Crop edges must leave at least five percent of the page visible.";
    },
  },
  "page-numbers": {
    version: "1",
    properties: {
      position: { type: "string", enum: ["top-left", "top-center", "top-right", "bottom-left", "bottom-center", "bottom-right"], default: "bottom-center" },
      format: { type: "string", minLength: 1, maxLength: 80, default: "{page}" },
      startNumber: { type: "integer", minimum: 1, maximum: 1_000_000, default: 1 },
      fontSize: { type: "number", minimum: 8, maximum: 36, default: 12 },
      margin: { type: "number", minimum: 0, maximum: 72, default: 24 },
    },
    validate: (options) => String(options.format ?? "{page}").includes("{page}") ? undefined : "Page number format must include {page}.",
  },
  "header-footer": {
    version: "1",
    properties: {
      headerText: { type: "string", maxLength: 200 },
      footerText: { type: "string", maxLength: 200 },
      alignment: { type: "string", enum: ["left", "center", "right"], default: "center" },
      fontSize: { type: "number", minimum: 8, maximum: 36, default: 12 },
      margin: { type: "number", minimum: 0, maximum: 72, default: 24 },
    },
    validate: (options) => String(options.headerText ?? "").trim() || String(options.footerText ?? "").trim() ? undefined : "Header text or footer text is required.",
  },
  "resize-pages": {
    version: "1",
    properties: {
      pageSize: { type: "string", enum: ["a3", "a4", "letter", "legal"], default: "a4" },
      orientation: { type: "string", enum: ["preserve", "portrait", "landscape"], default: "preserve" },
      fit: { type: "string", enum: ["contain", "stretch"], default: "contain" },
    },
  },
  "alternate-mix": {
    version: "1",
    properties: {
      startWith: { type: "string", enum: ["first", "second"], default: "first" },
      reverseSecond: { type: "boolean", default: false },
    },
  },
  "flip-pages": {
    version: "1",
    properties: {
      axis: { type: "string", enum: ["horizontal", "vertical"], default: "horizontal" },
      pages: pageRange,
    },
  },
  "split-pdf-by-size": {
    version: "1",
    properties: { targetSizeMb: { type: "number", minimum: 1, maximum: 100, default: 10 } },
  },
  "split-pdf-by-bookmarks": empty(),
  "split-pdf-by-text": {
    version: "1",
    required: ["matchText"],
    properties: {
      matchText: { type: "string", minLength: 1, maxLength: 200 },
      caseSensitive: { type: "boolean", default: false },
    },
  },
  "n-up-pdf": {
    version: "1",
    properties: {
      layout: { type: "integer", enum: [2, 4, 6, 9], default: 2 },
      orientation: { type: "string", enum: ["portrait", "landscape"], default: "portrait" },
      pageSize: { type: "string", enum: ["a4", "letter"], default: "a4" },
      margin: { type: "number", minimum: 0, maximum: 36, default: 18 },
      order: { type: "string", enum: ["row", "column"], default: "row" },
    },
  },
  "remove-annotations": {
    version: "1",
    properties: { policy: { type: "string", enum: ["comments", "comments-and-links"], default: "comments" } },
  },
  "word-to-pdf": empty(),
  "pdf-to-word": empty(),
  "excel-to-pdf": empty(),
  "powerpoint-to-pdf": empty(),
  "ocr-pdf": { version: "1", properties: { language: { type: "string", enum: ["eng", "ara", "ara+eng"], default: "ara+eng" } } },
  "summarize-pdf": { version: "1", properties: { locale, documentId: { type: "string", pattern: "^[0-9a-fA-F-]{36}$" } } },
  "chat-with-pdf": { version: "1", properties: { locale, question: { type: "string", maxLength: 4_000 }, documentId: { type: "string", pattern: "^[0-9a-fA-F-]{36}$" } } },
  "extract-data": { version: "1", properties: { locale, documentId: { type: "string", pattern: "^[0-9a-fA-F-]{36}$" } } },
};

export class ToolOptionsValidationError extends Error {
  readonly code = "TOOL_OPTIONS_INVALID";
  constructor(public readonly issues: readonly string[]) { super(issues.join(" ")); }
}

function issueFor(key: string, value: unknown, property: OptionProperty) {
  if (property.type === "string" && typeof value !== "string") return `${key} must be a string.`;
  if (property.type === "boolean" && typeof value !== "boolean") return `${key} must be a boolean.`;
  if (property.type === "number" && (typeof value !== "number" || !Number.isFinite(value))) return `${key} must be a finite number.`;
  if (property.type === "integer" && !Number.isSafeInteger(value)) return `${key} must be an integer.`;
  if (property.enum && !property.enum.includes(value as ToolOptionValue)) return `${key} has an unsupported value.`;
  if (typeof value === "number" && property.minimum !== undefined && value < property.minimum) return `${key} is below its minimum.`;
  if (typeof value === "number" && property.maximum !== undefined && value > property.maximum) return `${key} exceeds its maximum.`;
  if (typeof value === "string" && property.minLength !== undefined && value.trim().length < property.minLength) return `${key} is required.`;
  if (typeof value === "string" && property.maxLength !== undefined && value.length > property.maxLength) return `${key} is too long.`;
  if (typeof value === "string" && property.pattern && !new RegExp(property.pattern).test(value)) return `${key} has an invalid format.`;
}

export function optionJsonSchema(contract: ToolOptionContract) {
  return { type: "object", additionalProperties: false, required: [...(contract.required ?? [])], properties: Object.fromEntries(Object.entries(contract.properties).map(([key, value]) => [key, { ...value }])), "x-schema-version": contract.version };
}

export function validateToolOptions(toolId: string, value: unknown): ToolOptions {
  const contract = toolOptionContracts[toolId];
  if (!contract) throw new ToolOptionsValidationError([`No option contract is registered for ${toolId}.`]);
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new ToolOptionsValidationError(["Options must be an object."]);
  const input = value as Record<string, unknown>; const issues: string[] = [];
  for (const key of Object.keys(input)) if (!contract.properties[key]) issues.push(`Unknown option ${key}.`);
  for (const key of contract.required ?? []) if (!(key in input)) issues.push(`${key} is required.`);
  const normalized: ToolOptions = {};
  for (const [key, property] of Object.entries(contract.properties)) {
    const raw = input[key] ?? property.default;
    if (raw === undefined) continue;
    const issue = issueFor(key, raw, property); if (issue) issues.push(issue); else normalized[key] = raw as ToolOptionValue;
  }
  if (!issues.length) { const custom = contract.validate?.(normalized); if (custom) issues.push(custom); }
  if (issues.length) throw new ToolOptionsValidationError(issues);
  return normalized;
}
