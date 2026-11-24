/**
 * `fill-forms` — read-only inspection: restriction probes and form inventory.
 *
 * This module is the *whole* import graph of `POST /api/fill-forms/inspect`, and
 * that is the point (FF-01). It depends on `pdf-lib` and nothing else native:
 *
 *   - no native raster addon,
 *   - no font-asset path resolution,
 *   - no `node:module` / `node:path` / `createRequire`.
 *
 * The previous layout imported the fill engine — which reaches the rasteriser
 * through `form-appearance.ts` — into an app route. In a production build that
 * module-scope `dirname(require.resolve("@fontsource/..."))` is evaluated during
 * page-data collection, where Turbopack has replaced `require.resolve` with a
 * *numeric module id*; `dirname(7)` throws and `/api/fill-forms/inspect` fails
 * to build. Fonts are now resolved lazily, at render time, inside the worker
 * only, and this file has no renderer in its graph at all.
 *
 * The probes below are unchanged in behaviour and are re-exported by
 * `form-fill.ts`, so the worker and the route still share one implementation.
 */
import { PDFArray, PDFDict, PDFDocument, PDFName, PDFRef } from "pdf-lib";
import { getReadyQueueConnection } from "@/lib/queue";
import type { PDFObject } from "pdf-lib";
import { readFormInventory, type FormInventory } from "@/lib/pdf/form-schema";
import { FormFillError } from "@/lib/pdf/form-validation";
import { FORM_ERROR_MESSAGES } from "@/lib/pdf/form-types";

/**
 * Restriction probes.
 *
 * Two layers, on purpose:
 *
 *   1. **Structural** (authoritative). The document's own object graph is walked
 *      — catalog → `/AcroForm`, `/Perms`, every field's `/FT` — so XFA packets,
 *      signature fields and certification signatures are found even when they
 *      live inside a compressed object stream (`/ObjStm`), which no raw-byte
 *      scan can see. `pdf-lib` cannot enumerate these for us: `getForm()`
 *      *deletes* a `/XFA` entry and only logs a warning, so anything that must
 *      survive detection is read from the graph before that happens.
 *
 *   2. **Byte** (defence in depth). A literal scan for `/ByteRange`, `/Encrypt`,
 *      `/XFA` and friends still runs, because a damaged-but-parseable file may
 *      keep the marker outside the objects we can reach, and because an unsigned
 *      revision of a previously signed file keeps its old `/ByteRange`.
 *
 * A document is rejected when *either* layer fires.
 */
export type Restrictions = { encrypted: boolean; signed: boolean; xfa: boolean };

export function scanBytes(bytes: Uint8Array) {
  const text = new TextDecoder("latin1").decode(bytes);
  return {
    encrypted: /\/Encrypt\s+\d+\s+\d+\s+R/u.test(text) || /\/Encrypt\s*<</u.test(text),
    xfa: /\/XFA\b/u.test(text),
    signed: /\/ByteRange\s*\[/u.test(text) || /\/FT\s*\/Sig\b/u.test(text) || /\/DocMDP\b/u.test(text),
  };
}

/**
 * Structural budgets (FF-02, architect round 2).
 *
 * The walk below is recursive over `/Fields → /Kids`, and both the depth and the
 * number of nodes are attacker-controlled. Each bound is explicit, and
 * *exhausting* a bound is a rejection, never an "assume safe".
 *
 * The budgets are checked **before** a child is queued, not after it is popped:
 * a single `/Kids` array with a million entries would otherwise allocate a
 * million-element pending stack before the first bound was consulted.
 */
export const STRUCTURE_BUDGETS = {
  maxDepth: 64,
  maxNodes: 5_000,
  maxRefHops: 32,
  /** Total indirect-reference resolutions across the whole walk. */
  maxTotalHops: 50_000,
  /** Entries accepted from a single `/Kids` or `/Fields` array before refusal. */
  maxChildrenPerNode: 5_000,
} as const;

/** The only field types the PDF form model defines. Anything else is malformed. */
const KNOWN_FIELD_TYPES = new Set(["/Tx", "/Btn", "/Ch", "/Sig"]);

export class StructureFailure extends Error {
  constructor(readonly reason: string) { super(reason); }
}

type ScanContext = {
  document: PDFDocument;
  hops: number;
  nodes: number;
  /**
   * References already **resolved**, mapped to how many times they were reached.
   *
   * Revisiting a reference is not by itself an error: a legitimate PDF may share
   * a field subtree, and a `/Kids` cycle is a malformed graph that pdf-lib would
   * otherwise follow until the stack overflows. The difference must be decided
   * *here*, structurally, rather than by catching a `RangeError` later.
   */
  /** How many times each reference was resolved; used to report shared subtrees. */
  resolved: Map<string, number>;
};

/**
 * Resolve one object-graph entry.
 *
 * Returns `undefined` only when the entry is genuinely **absent**. A present but
 * unresolvable entry (a dangling indirect reference, a chain longer than the
 * budget, or a reference cycle) throws: that is precisely the case the review
 * showed was being treated as "no restriction".
 */
function resolveEntry(context: ScanContext, owner: PDFDict, key: PDFName): PDFObject | undefined {
  if (!owner.has(key)) return undefined;
  let value: PDFObject | undefined = owner.get(key);
  const seen = new Set<string>();
  while (value instanceof PDFRef) {
    context.hops += 1;
    if (context.hops > STRUCTURE_BUDGETS.maxTotalHops) throw new StructureFailure("REFERENCE_BUDGET_EXCEEDED");
    const refKey = value.toString();
    if (seen.has(refKey)) throw new StructureFailure("REFERENCE_CYCLE");
    seen.add(refKey);
    if (seen.size > STRUCTURE_BUDGETS.maxRefHops) throw new StructureFailure("REFERENCE_CHAIN_TOO_LONG");
    const next = context.document.context.lookup(value);
    if (next === undefined) throw new StructureFailure("UNRESOLVED_REFERENCE");
    value = next as PDFObject | undefined;
  }
  if (value === undefined) throw new StructureFailure("UNRESOLVED_REFERENCE");
  return value;
}

const typeName = (value: PDFObject | undefined) => String((value as { toString?: () => string } | undefined)?.toString?.() ?? "");

/**
 * `/FT` must be a *name* from the field-type vocabulary.
 *
 * The previous walk accepted whatever `/FT` string it found and only compared it
 * to `/Sig`. A malformed `/FT` (a dictionary, a number, an empty string, an
 * unknown name) therefore produced a document that looked "clean" while pdf-lib
 * would go on to interpret it some other way. An unreadable type is not
 * "not a signature" — it is a document whose structure cannot be established.
 */
function assertFieldType(value: PDFObject | undefined): string | undefined {
  if (value === undefined) return undefined;
  const name = typeName(value);
  if (!KNOWN_FIELD_TYPES.has(name)) throw new StructureFailure("FT_MALFORMED");
  return name;
}

/**
 * `/SigFlags` must be a number, and only the two defined bits are meaningful.
 *
 * A non-numeric `/SigFlags` used to coerce to `NaN`, and `NaN & 1 === 0`, so a
 * malformed value silently read as "no signatures". It is now a rejection.
 */
function assertSigFlags(value: PDFObject | undefined): number {
  if (value === undefined) return 0;
  const raw = typeName(value);
  if (!/^\d{1,6}$/u.test(raw)) throw new StructureFailure("SIGFLAGS_MALFORMED");
  return Number(raw);
}

/**
 * Walk the parsed object graph.
 *
 * Corrections after the architect review:
 *
 *   1. A previously **visited** reference used to be skipped silently. Skipping is
 *      correct for a shared subtree, but *wrong* for a cycle, and the two were
 *      indistinguishable. A reference that reappears on the current descent path
 *      is now `FIELD_GRAPH_CYCLE`; one that reappears elsewhere is a shared node
 *      and is skipped after being counted.
 *   2. `/FT`, `/SigFlags`, `/Perms`, `/Fields` and `/Kids` are type-checked rather
 *      than coerced. A malformed `/FT` or `/SigFlags` used to read as "no
 *      signature".
 *   3. Budgets are enforced *before* children are queued, and each `/Kids` array
 *      is capped, so no attacker-controlled array sizes the pending stack.
 *   4. A malformed graph is rejected here, before any later pdf-lib call walks the
 *      same `/Fields` tree and overflows the native stack.
 */
async function scanStructure(bytes: Uint8Array): Promise<{ xfa: boolean; signed: boolean }> {
  let document: PDFDocument;
  try { document = await PDFDocument.load(bytes, { ignoreEncryption: false, updateMetadata: false }); }
  catch (error) {
    // A file the parser rejects outright is *unsupported*, not restricted: there
    // is no object graph to be unsure about.
    throw new StructureFailure(/encrypted/iu.test(error instanceof Error ? error.message : "") ? "DOCUMENT_ENCRYPTED" : "DOCUMENT_UNREADABLE");
  }
  return scanStructureInDocument(document);
}

/**
 * Run the structural walk against a document that is **already loaded**.
 *
 * The bounded child parses once and then calls this, so the restriction decision
 * and the inventory describe the same object graph instead of two separately
 * timed parses of the same bytes.
 */
export function scanStructureInDocument(document: PDFDocument): { xfa: boolean; signed: boolean } {
  const context: ScanContext = { document, hops: 0, nodes: 0, resolved: new Map() };
  let catalog: PDFDict;
  try { catalog = document.catalog; }
  catch { throw new StructureFailure("CATALOG_UNREADABLE"); }

  // `/Perms` is how a certified document records its policy. It exists
  // independently of any signature-dictionary text, and an *unresolvable*
  // `/Perms` must not read as "not certified".
  let certified = false;
  const perms = resolveEntry(context, catalog, PDFName.of("Perms"));
  if (perms !== undefined) {
    if (!(perms instanceof PDFDict)) throw new StructureFailure("PERMS_NOT_A_DICTIONARY");
    for (const key of perms.keys()) {
      if (resolveEntry(context, perms, key) === undefined) throw new StructureFailure("PERMS_ENTRY_UNRESOLVED");
      certified = true;
    }
  }

  const acro = resolveEntry(context, catalog, PDFName.of("AcroForm"));
  if (acro === undefined) return { xfa: false, signed: certified };
  if (!(acro instanceof PDFDict)) throw new StructureFailure("ACROFORM_NOT_A_DICTIONARY");
  if (acro.has(PDFName.of("XFA"))) return { xfa: true, signed: true };

  const flagsSigned = (() => {
    const flags = assertSigFlags(resolveEntry(context, acro, PDFName.of("SigFlags")));
    // Bit 1 = SignaturesExist, bit 2 = AppendOnly. Both mean signatures are
    // present somewhere the walk may not reach.
    return (flags & 1) === 1 || (flags & 2) === 2;
  })();

  const fields = resolveEntry(context, acro, PDFName.of("Fields"));
  if (fields === undefined) return { xfa: false, signed: certified || flagsSigned };
  if (!(fields instanceof PDFArray)) throw new StructureFailure("FIELDS_NOT_AN_ARRAY");
  if (fields.size() > STRUCTURE_BUDGETS.maxChildrenPerNode) throw new StructureFailure("FIELDS_ARRAY_TOO_LARGE");

  let signed = certified || flagsSigned;
  // `path` is the chain of references from the root to this node. Carrying it on
  // the pending entry is what lets an explicit (non-recursive) stack distinguish
  // a cycle from a legitimately shared subtree: a repeat *within* one path is a
  // cycle, a repeat across sibling paths is not.
  type Pending = { ref: PDFObject; depth: number; inherited: string | undefined; path: ReadonlySet<string> };
  const stack: Pending[] = [];
  const queueChildren = (entries: PDFObject[], depth: number, inherited: string | undefined, path: ReadonlySet<string>) => {
    // Budget first, allocation second.
    if (context.nodes + stack.length + entries.length > STRUCTURE_BUDGETS.maxNodes) throw new StructureFailure("FIELD_BUDGET_EXCEEDED");
    for (const entry of entries) stack.push({ ref: entry, depth, inherited, path });
  };
  queueChildren(fields.asArray(), 0, undefined, new Set());

  while (stack.length) {
    const pending = stack.pop() as Pending;
    context.nodes += 1;
    if (context.nodes > STRUCTURE_BUDGETS.maxNodes) throw new StructureFailure("FIELD_BUDGET_EXCEEDED");
    if (pending.depth > STRUCTURE_BUDGETS.maxDepth) throw new StructureFailure("FIELD_DEPTH_EXCEEDED");

    // Follow a chain of indirect references, refusing any that loops back onto
    // itself. `chain` is local: a shared node reached from a sibling is not a
    // cycle, only a repeat *within one resolution* is.
    let node = pending.ref;
    const chain: string[] = [];
    while (node instanceof PDFRef) {
      const key = node.toString();
      // A reference that repeats inside one resolution cannot terminate at all.
      if (chain.includes(key)) throw new StructureFailure("REFERENCE_CYCLE");
      // A reference that reappears on the path from the root is a `/Kids` cycle.
      if (pending.path.has(key)) throw new StructureFailure("FIELD_GRAPH_CYCLE");
      chain.push(key);
      if (chain.length > STRUCTURE_BUDGETS.maxRefHops) throw new StructureFailure("REFERENCE_CHAIN_TOO_LONG");
      context.hops += 1;
      if (context.hops > STRUCTURE_BUDGETS.maxTotalHops) throw new StructureFailure("REFERENCE_BUDGET_EXCEEDED");
      const next = context.document.context.lookup(node);
      if (next === undefined) throw new StructureFailure("UNRESOLVED_FIELD_REFERENCE");
      context.resolved.set(key, (context.resolved.get(key) ?? 0) + 1);
      node = next as PDFObject;
    }
    if (!(node instanceof PDFDict)) throw new StructureFailure("FIELD_NOT_A_DICTIONARY");

    const inheritedType = assertFieldType(resolveEntry(context, node, PDFName.of("FT"))) ?? pending.inherited;
    if (inheritedType === "/Sig") signed = true;

    const kids = resolveEntry(context, node, PDFName.of("Kids"));
    if (kids === undefined) continue;
    if (!(kids instanceof PDFArray)) throw new StructureFailure("KIDS_NOT_AN_ARRAY");
    if (kids.size() > STRUCTURE_BUDGETS.maxChildrenPerNode) throw new StructureFailure("KIDS_ARRAY_TOO_LARGE");
    // Extend the path with everything traversed to reach this node, so a child
    // that points back at any ancestor is detected immediately.
    const childPath = chain.length ? new Set([...pending.path, ...chain]) : pending.path;
    queueChildren(kids.asArray(), pending.depth + 1, inheritedType, childPath);
  }
  return { xfa: false, signed };
}

/**
 * Read every restriction signal that applies to these bytes.
 *
 * A structural failure is surfaced as `FORM_RESTRICTED` — never downgraded to
 * "no restriction found" (FF-02). The byte layer remains as defence in depth: a
 * damaged-but-parseable file may keep `/ByteRange` outside the reachable graph,
 * and an unsigned revision of a previously signed file keeps its old marker.
 */
export async function probeRestrictions(bytes: Uint8Array): Promise<Restrictions> {
  const bytesView = scanBytes(bytes);
  let structural: { xfa: boolean; signed: boolean };
  try { structural = await scanStructure(bytes); }
  catch (error) {
    const reason = error instanceof StructureFailure ? error.reason : "STRUCTURE_UNREADABLE";
    // Unparseable bytes are a format problem, not a restriction; everything the
    // walk *did* understand but could not complete is fail-closed (FF-02).
    if (reason === "DOCUMENT_UNREADABLE") throw new FormFillError("FORM_UNSUPPORTED", FORM_ERROR_MESSAGES.FORM_UNSUPPORTED, { structure: reason });
    if (reason === "DOCUMENT_ENCRYPTED") throw new FormFillError("FORM_RESTRICTED", FORM_ERROR_MESSAGES.FORM_RESTRICTED, { structure: reason });
    throw new FormFillError("FORM_RESTRICTED", FORM_ERROR_MESSAGES.FORM_RESTRICTED, { structure: reason });
  }
  return {
    encrypted: bytesView.encrypted,
    xfa: bytesView.xfa || structural.xfa,
    signed: bytesView.signed || structural.signed,
  };
}


export function assertFillableRestrictions(restrictions: Restrictions) {
  if (restrictions.encrypted) throw new FormFillError("FORM_RESTRICTED", FORM_ERROR_MESSAGES.FORM_RESTRICTED, { restriction: "ENCRYPTED" });
  if (restrictions.xfa) throw new FormFillError("FORM_UNSUPPORTED", FORM_ERROR_MESSAGES.FORM_UNSUPPORTED, { restriction: "XFA" });
  if (restrictions.signed) throw new FormFillError("FORM_RESTRICTED", FORM_ERROR_MESSAGES.FORM_RESTRICTED, { restriction: "SIGNED" });
}

/** True when the bytes carry an `/Encrypt` marker. Exported for the bounded child. */
export function scanEncryptionMarkers(bytes: Uint8Array) {
  return scanBytes(bytes).encrypted;
}

/**
 * Cheap checks that must pass *before* any parser sees the bytes (FF-04).
 *
 * `PDFDocument.load` is the expensive, attacker-facing step: it inflates object
 * streams, follows the xref chain and can be made to work hard by a small file.
 * The review found the inspect route buffering a multipart body and parsing
 * before the size limit and before malware screening, with no parser budgets at
 * all. This function is deliberately cheap — a signature check, a trailer
 * marker, and a page-object estimate — so a hostile upload is rejected at a cost
 * of a single linear scan.
 *
 * It is a *pre*-filter, not a replacement for the malware gate: screening still
 * runs before inspection (see the route), and the structural probes afterwards.
 */
export function assertCheapPdfShape(bytes: Uint8Array) {
  if (bytes.byteLength < 64) throw new FormFillError("FORM_UNSUPPORTED", FORM_ERROR_MESSAGES.FORM_UNSUPPORTED, { shape: "TOO_SHORT" });
  // `%PDF-` must appear in the header; readers tolerate leading junk, so the
  // first KiB is scanned rather than only byte 0.
  const head = new TextDecoder("latin1").decode(bytes.subarray(0, Math.min(bytes.byteLength, 1024)));
  if (!head.includes("%PDF-")) throw new FormFillError("FORM_UNSUPPORTED", FORM_ERROR_MESSAGES.FORM_UNSUPPORTED, { shape: "NO_PDF_HEADER" });
  const tail = new TextDecoder("latin1").decode(bytes.subarray(Math.max(0, bytes.byteLength - 4096)));
  if (!tail.includes("%%EOF") && !head.includes("%%EOF")) throw new FormFillError("FORM_UNSUPPORTED", FORM_ERROR_MESSAGES.FORM_UNSUPPORTED, { shape: "NO_PDF_TRAILER" });
  // A decompression-bomb guard that does not decompress anything: count
  // `/Type /Page` markers. Object streams hide them, so this is an upper bound
  // only — the authoritative page count comes from the bounded parse below.
  const text = new TextDecoder("latin1").decode(bytes);
  const pageMarkers = (text.match(/\/Type\s*\/Page\b/gu) ?? []).length;
  const maxPages = 2_000 * 4;
  if (pageMarkers > maxPages) throw new FormFillError("FORM_UNSUPPORTED", FORM_ERROR_MESSAGES.FORM_UNSUPPORTED, { shape: "PAGE_MARKERS_EXCEEDED", pageMarkers });
}

/**
 * Parse with an explicit wall-clock budget and page cap (FF-04).
 *
 * Node cannot interrupt `pdf-lib` mid-parse without a worker thread, and adding
 * one is an architectural change that needs owner approval. What this can do —
 * and now does — is bound everything *around* the parse: the byte size, the
 * shape, the page count immediately after load, and the CPU time the caller is
 * willing to spend. Exceeding the budget after a successful load rejects the
 * document rather than serving a partial inventory.
 */
export async function loadBounded(bytes: Uint8Array, budgetMs: number) {
  const started = Date.now();
  const document = await loadUnencryptedForInspection(bytes);
  const elapsed = Date.now() - started;
  if (elapsed > budgetMs) throw new FormFillError("FORM_UNSUPPORTED", FORM_ERROR_MESSAGES.FORM_UNSUPPORTED, { budget: "PARSE_TIME_EXCEEDED", elapsed });
  return document;
}

async function loadUnencryptedForInspection(bytes: Uint8Array) {
  try { return await PDFDocument.load(bytes, { ignoreEncryption: false }); }
  catch (error) {
    if (/encrypted/iu.test(error instanceof Error ? error.message : "")) throw new FormFillError("FORM_RESTRICTED", FORM_ERROR_MESSAGES.FORM_RESTRICTED);
    throw new FormFillError("FORM_UNSUPPORTED", FORM_ERROR_MESSAGES.FORM_UNSUPPORTED);
  }
}

/**
 * Per-tenant inspection admission (FF-04).
 *
 * Two independent budgets, both enforced *before* a byte of the body is read:
 *
 *   - **rate**: requests per minute per tenant, so one caller cannot monopolise
 *     the parser pool;
 *   - **concurrency**: simultaneously open inspections per tenant, so N slow
 *     documents from one tenant cannot starve every other tenant.
 *
 * The concurrency budget is a counter with a short TTL rather than a mutex: the
 * TTL is the crash recovery. If a worker dies mid-inspection the counter expires
 * instead of wedging the tenant permanently.
 *
 * Both keys are scoped by tenant id only. Job ids are not available before the
 * body is parsed, and a per-request key would not bound anything.
 */
const INSPECT_RATE_PER_MINUTE = 30;
const INSPECT_CONCURRENCY = 4;
const INSPECT_LEASE_SECONDS = 120;

export type InspectAdmission = { release: () => Promise<void> };

export async function admitFormInspection(tenantId: string): Promise<InspectAdmission> {
  const redis = await getReadyQueueConnection();
  const rateKey = `dip:fill-forms-inspect-rate:v1:${tenantId}`;
  const count = await redis.incr(rateKey);
  if (count === 1) await redis.expire(rateKey, 60);
  if (count > INSPECT_RATE_PER_MINUTE) throw new FormFillError("FORM_UNSUPPORTED", FORM_ERROR_MESSAGES.FORM_UNSUPPORTED, { admission: "RATE_LIMITED" });
  const concurrencyKey = `dip:fill-forms-inspect-open:v1:${tenantId}`;
  const open = await redis.incr(concurrencyKey);
  if (open === 1) await redis.expire(concurrencyKey, INSPECT_LEASE_SECONDS);
  if (open > INSPECT_CONCURRENCY) {
    await redis.decr(concurrencyKey);
    throw new FormFillError("FORM_UNSUPPORTED", FORM_ERROR_MESSAGES.FORM_UNSUPPORTED, { admission: "CONCURRENCY_LIMITED" });
  }
  let released = false;
  return {
    async release() {
      // Idempotent: the route releases in a `finally`, and a double decrement
      // would silently raise the tenant's ceiling.
      if (released) return;
      released = true;
      const remaining = await redis.decr(concurrencyKey).catch(() => 0);
      if (remaining <= 0) await redis.del(concurrencyKey).catch(() => undefined);
    },
  };
}

/** Read-only inventory. Never mutates the document and never writes bytes. */
export async function inspectFormPdf(bytes: Uint8Array, options: { budgetMs?: number; maxPages?: number } = {}): Promise<FormInventory> {
  if (scanBytes(bytes).encrypted) throw new FormFillError("FORM_RESTRICTED", FORM_ERROR_MESSAGES.FORM_RESTRICTED, { restriction: "ENCRYPTED" });
  const restrictions = await probeRestrictions(bytes);
  assertFillableRestrictions(restrictions);
  const document = await loadBounded(bytes, options.budgetMs ?? 20_000);
  if (options.maxPages !== undefined && document.getPageCount() > options.maxPages) throw new FormFillError("FORM_UNSUPPORTED", FORM_ERROR_MESSAGES.FORM_UNSUPPORTED, { pages: document.getPageCount() });
  try { return readFormInventory(document); }
  catch (error) {
    // `pdf-lib` walks `/Fields` recursively without a depth bound, so a cyclic
    // `/Kids` graph overflows the stack inside `getForm()` even though our own
    // walk terminated cleanly. An inventory we could not build is a document we
    // cannot describe, and a document we cannot describe must not be filled:
    // report it as unsupported rather than letting a raw `RangeError` escape as
    // an unclassified 500 (FF-02).
    if (error instanceof FormFillError) throw error;
    if (error instanceof RangeError) throw new FormFillError("FORM_UNSUPPORTED", FORM_ERROR_MESSAGES.FORM_UNSUPPORTED, { structure: "FIELD_GRAPH_TOO_DEEP" });
    throw new FormFillError("FORM_UNSUPPORTED", FORM_ERROR_MESSAGES.FORM_UNSUPPORTED, { structure: "INVENTORY_UNREADABLE" });
  }
}

/** Test seam: run the structural walk directly so its budgets can be asserted. */
export async function scanStructureForTest(bytes: Uint8Array) { return scanStructure(bytes); }
