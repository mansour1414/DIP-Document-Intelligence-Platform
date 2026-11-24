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
type Restrictions = { encrypted: boolean; signed: boolean; xfa: boolean };

export function scanBytes(bytes: Uint8Array) {
  const text = new TextDecoder("latin1").decode(bytes);
  return {
    encrypted: /\/Encrypt\s+\d+\s+\d+\s+R/u.test(text) || /\/Encrypt\s*<</u.test(text),
    xfa: /\/XFA\b/u.test(text),
    signed: /\/ByteRange\s*\[/u.test(text) || /\/FT\s*\/Sig\b/u.test(text) || /\/DocMDP\b/u.test(text),
  };
}

/**
 * Structural budgets (FF-02).
 *
 * The walk below is recursive over `/Fields → /Kids`, and both the depth and the
 * number of nodes are attacker-controlled. Each bound is therefore explicit, and
 * *exhausting* a bound is a rejection, never an "assume safe".
 */
const STRUCTURE_MAX_DEPTH = 64;
const STRUCTURE_MAX_NODES = 5_000;
const STRUCTURE_MAX_REF_HOPS = 32;

class StructureFailure extends Error {
  constructor(readonly reason: string) { super(reason); }
}

type ScanContext = {
  document: PDFDocument;
  hops: number;
  nodes: number;
  visited: Set<string>;
};

/**
 * Resolve one object-graph entry.
 *
 * Returns `undefined` only when the entry is genuinely **absent**. A present but
 * unresolvable entry (a dangling indirect reference, an indirect chain longer
 * than the budget, or a cycle) throws: that is precisely the case the review
 * showed was being treated as "no restriction" (FF-02).
 */
function resolveEntry(context: ScanContext, owner: PDFDict, key: PDFName): PDFObject | undefined {
  if (!owner.has(key)) return undefined;
  let value: PDFObject | undefined = owner.get(key);
  const seen = new Set<string>();
  while (value instanceof PDFRef) {
    context.hops += 1;
    if (context.hops > STRUCTURE_MAX_REF_HOPS * STRUCTURE_MAX_NODES) throw new StructureFailure("REFERENCE_BUDGET_EXCEEDED");
    const refKey = value.toString();
    if (seen.has(refKey)) throw new StructureFailure("REFERENCE_CYCLE");
    seen.add(refKey);
    if (seen.size > STRUCTURE_MAX_REF_HOPS) throw new StructureFailure("REFERENCE_CHAIN_TOO_LONG");
    const next = context.document.context.lookup(value);
    if (next === undefined) throw new StructureFailure("UNRESOLVED_REFERENCE");
    value = next as PDFObject | undefined;
  }
  if (value === undefined) throw new StructureFailure("UNRESOLVED_REFERENCE");
  return value;
}

const typeName = (value: PDFObject | undefined) => String((value as { toString?: () => string } | undefined)?.toString?.() ?? "");

/**
 * Walk the parsed object graph.
 *
 * Two things the previous top-level-only scan got wrong (FF-02):
 *
 *   1. A signature field can live **under `/Kids`**, one or more levels below
 *      `/AcroForm /Fields`. Only the top-level array was inspected, so a nested
 *      `/Sig` field was silently accepted and then written into.
 *   2. `/FT` is **inheritable** in the PDF object model. A field with no `/FT` of
 *      its own takes its ancestor's type, so reading only the own entry misses
 *      nested signatures in a second way.
 *
 * The walk therefore carries the inherited `/FT` down, follows indirect
 * references, and treats *every* anomaly — dangling reference, `/Perms` that is
 * not a dictionary, `/Kids` that is not an array, a cycle, a budget overrun — as
 * `FORM_RESTRICTED`. That direction is deliberate: a document whose structure
 * cannot be fully established must never be modified, because a false positive
 * only refuses a fill that was never provably safe, while a false negative
 * writes into a signed document.
 */
async function scanStructure(bytes: Uint8Array): Promise<{ xfa: boolean; signed: boolean }> {
  let document: PDFDocument;
  try { document = await PDFDocument.load(bytes, { ignoreEncryption: false, updateMetadata: false }); }
  catch (error) {
    // A file the parser rejects outright is *unsupported*, not restricted: there
    // is no object graph to be unsure about. (This stays FORM_UNSUPPORTED so a
    // four-byte "PDF" is not reported as a signed document.)
    throw new StructureFailure(/encrypted/iu.test(error instanceof Error ? error.message : "") ? "DOCUMENT_ENCRYPTED" : "DOCUMENT_UNREADABLE");
  }
  const context: ScanContext = { document, hops: 0, nodes: 0, visited: new Set() };
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
    // Any well-formed entry under /Perms is a usage-rights or certification
    // signature; both make the document unsafe to rewrite.
    for (const key of perms.keys()) {
      if (resolveEntry(context, perms, key) === undefined) throw new StructureFailure("PERMS_ENTRY_UNRESOLVED");
      certified = true;
    }
  }

  const acro = resolveEntry(context, catalog, PDFName.of("AcroForm"));
  if (acro === undefined) return { xfa: false, signed: certified };
  if (!(acro instanceof PDFDict)) throw new StructureFailure("ACROFORM_NOT_A_DICTIONARY");
  if (acro.has(PDFName.of("XFA"))) return { xfa: true, signed: true };

  // SigFlags bit 1 ("SignaturesExist") and bit 2 ("AppendOnly") both mean the
  // producer knows signatures are present — possibly in a field this walk did
  // not reach.
  const sigFlagsEntry = resolveEntry(context, acro, PDFName.of("SigFlags"));
  const sigFlags = Number(typeName(sigFlagsEntry) || "0");
  const flagsSigned = (sigFlags & 1) === 1 || (sigFlags & 2) === 2;

  const fields = resolveEntry(context, acro, PDFName.of("Fields"));
  if (fields === undefined) return { xfa: false, signed: certified || flagsSigned };
  if (!(fields instanceof PDFArray)) throw new StructureFailure("FIELDS_NOT_AN_ARRAY");

  let signed = certified || flagsSigned;
  type Pending = { ref: PDFObject; depth: number; inherited: string | undefined };
  const stack: Pending[] = fields.asArray().map((entry) => ({ ref: entry, depth: 0, inherited: undefined }));
  while (stack.length) {
    const pending = stack.pop() as Pending;
    context.nodes += 1;
    if (context.nodes > STRUCTURE_MAX_NODES) throw new StructureFailure("FIELD_BUDGET_EXCEEDED");
    if (pending.depth > STRUCTURE_MAX_DEPTH) throw new StructureFailure("FIELD_DEPTH_EXCEEDED");

    let node = pending.ref;
    // Follow an indirect reference, remembering it so a `/Kids` cycle terminates
    // instead of repeating forever.
    while (node instanceof PDFRef) {
      const key = node.toString();
      if (context.visited.has(key)) break;
      context.visited.add(key);
      context.hops += 1;
      if (context.hops > STRUCTURE_MAX_REF_HOPS * STRUCTURE_MAX_NODES) throw new StructureFailure("REFERENCE_BUDGET_EXCEEDED");
      const next = context.document.context.lookup(node);
      if (next === undefined) throw new StructureFailure("UNRESOLVED_FIELD_REFERENCE");
      node = next as PDFObject;
    }
    if (node instanceof PDFRef) continue; // already visited: a shared or cyclic subtree
    if (!(node instanceof PDFDict)) throw new StructureFailure("FIELD_NOT_A_DICTIONARY");

    // `/FT` is inherited: absent means "same type as my parent".
    const ownType = resolveEntry(context, node, PDFName.of("FT"));
    const inheritedType = ownType === undefined ? pending.inherited : typeName(ownType);
    if (inheritedType === "/Sig") signed = true;

    const kids = resolveEntry(context, node, PDFName.of("Kids"));
    if (kids === undefined) continue;
    if (!(kids instanceof PDFArray)) throw new StructureFailure("KIDS_NOT_AN_ARRAY");
    for (const kid of kids.asArray()) stack.push({ ref: kid, depth: pending.depth + 1, inherited: inheritedType });
    if (signed && stack.length > STRUCTURE_MAX_NODES) throw new StructureFailure("FIELD_BUDGET_EXCEEDED");
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
