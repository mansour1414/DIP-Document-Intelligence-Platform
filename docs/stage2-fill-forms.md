# Stage 2 — Fill PDF Forms (`fill-forms`)

Bounded vertical slice: **filling existing AcroForm fields**. Out of scope and
left in the backlog: form creation, AI field detection, true redaction, digital
signatures.

Authorisation: the owner's Stage 2 prompt (`DIP — Stage 2: Fill PDF Forms
Implementation`) is the approval for this slice. This branch is proposed, not
merged, deployed or released — no gate is approved here.

## What is implemented

| Layer | Artefact | State |
| --- | --- | --- |
| Engine | `src/lib/pdf/form-fill.ts` (`inspectFormPdf`, `fillFormPdf`) | Complete |
| Contract (shared) | `src/lib/pdf/form-types.ts`, `form-validation.ts`, `form-schema.ts` | Complete |
| Appearance fallback | `src/lib/pdf/form-appearance.ts` | Complete |
| Registry | `src/config/index.ts`, `src/lib/tools/{registry,options}.ts` | Complete |
| Job pipeline | `src/lib/jobs/{orchestrator,document-pipeline}.ts` | Complete |
| API | `POST /api/jobs/fill-forms` (async), `POST /api/fill-forms/inspect` (read-only) | Complete |
| UI | `src/components/tools/fill-forms-workspace.tsx` (en + ar) | Complete |
| Public API | `/v1/jobs` with a `fields` multipart part | Complete (same `createToolJob`; the payload is bounded, shape-validated and folded into the idempotency request hash) |
| Persisted Workflows | rejected with `WORKFLOW_TYPED_INPUT_UNSUPPORTED` | **Pending integration** |
| Agent plans | tool excluded (`agentExcludedTools`) | **Pending integration** |

The distinction in the last two rows is deliberate: a persisted workflow node
carries flat options only, and an Agent plan is generated from a natural-language
request. Neither can express a typed per-field map *safely* yet, so both refuse
the tool with an explicit code instead of accepting a JSON blob that would be
unvalidated at the boundary where it is authored. Supporting them requires
extending those contracts (typed node inputs / a field-resolution step) — a
separate change, not a silent widening of this one.

## Accepted input

* One PDF, `application/pdf`, ≤ 100 MB, ≤ 200 pages, ≤ 400 AcroForm fields.
* Field kinds: text (single/multi-line, not rich/combed/password), checkbox,
  radio group, dropdown, option list.
* ≤ 200 field values per request, ≤ 4 000 characters per value, ≤ 64 KB of
  serialised payload, ≤ 200 characters per field name.
* Values: `string`, `boolean`, or `string[]` — validated with
  `parseFieldsPayload()` at the API boundary and again in the worker, then
  semantically with `validateFillValues()` against the document's own inventory.

## Rejected documents (fail closed, before any write)

| Condition | Code |
| --- | --- |
| Encrypted (`/Encrypt`) | `FORM_RESTRICTED` |
| Signed / certified (`/ByteRange`, `/FT /Sig`, `/DocMDP`) | `FORM_RESTRICTED` |
| XFA hybrid form (byte probe — see note) | `FORM_UNSUPPORTED` |
| Duplicated fully-qualified field names | `FORM_UNSUPPORTED` |
| No supported AcroForm fields | `FORM_NOT_FOUND` |
| Unsupported kind (push button, signature, rich text, combed, password) | `FORM_UNSUPPORTED` |
| Value violates the field contract | `FORM_VALUE_INVALID` |
| Output fails re-open verification | `FORM_OUTPUT_UNVERIFIED` |

### How restrictions are detected (two layers, neither sufficient alone)

**1. Structural probe (authoritative).** The parsed object graph is walked
*before* the form API is touched: `catalog → /AcroForm`, `catalog → /Perms →
/DocMDP`, `/AcroForm /XFA`, `/AcroForm /SigFlags` bits 1–2, and every top-level
field's `/FT`. Because this reads decompressed objects, it sees markers inside
`/ObjStm` compressed object streams that **no raw-byte scan can reach**.
`test/fill-forms.runtime.test.ts` proves this with compacted fixtures where the
marker is asserted to be *invisible* to a byte scan and still rejected.

**2. Byte probe (defence in depth).** A literal scan for `/ByteRange`,
`/Encrypt`, `/XFA`, `/FT /Sig`, `/DocMDP` still runs, because a
damaged-but-parseable file can keep a marker outside the reachable graph, and an
unsigned revision of a previously signed file keeps its old `/ByteRange`.

A document is rejected when **either** layer fires. The reverse (both silent) is
not reachable by design: `SigFlags` set means the producer knows signatures
exist, so it fails closed.

**Why the graph must be read first.** `PDFDocument.getForm()` *deletes* the
`/XFA` entry and only logs a warning ("Removing XFA form data as pdf-lib does
not support reading or writing XFA"). Anything that must survive detection has
to be read from the graph before that call, and `save()` calls it too (via
`updateFieldAppearances`), which is why the compacted fixtures save with
`updateFieldAppearances: false`.

**A bug this found.** An earlier version of the structural probe used
`lookup(key, PDFDict)`, which *throws* when the entry is absent; the surrounding
`catch` then reported "graph unreadable" for every ordinary document and
silently disabled the whole layer. It is now `lookup(key)` plus an `instanceof`
check, and the compressed-XFA test is what catches a regression.

## Sensitive form values

Field values are customer data. They are handled as follows, and each point is
tested:

* **Never logged.** The pipeline logs counts (`filled_fields`,
  `untouched_fields`, `raster_appearances`, `flatten`) and the engine label —
  never names or values. Proven by a test that captures every `console.*` call
  while a real fill runs, with Latin and Arabic secrets, and asserts neither
  appears.
* **Never in a persisted error.** `job.error.message` is written to the database
  and echoed through the status API, so verification failures describe shape and
  size only (`string(32 chars)`, `list(2 items)`, `boolean(true)`), and
  pdf-lib's own exception text — which can quote the offending value — is
  replaced with the exception *type*. Proven by
  "verification and fill failures never echo the submitted value into a
  persisted message".
* **Never in metrics.** `recordMetric` labels are `tool_id`, `engine`,
  `engine_version`, `status`; field data is not among them.
* **Never in audit metadata.** The only audit writers in the codebase are
  `src/lib/business/audit.ts` and `src/lib/agent/audit.ts`, both for
  organization/API-key events; the job pipeline writes none, and this slice adds
  no audit call that could carry a value.
* **Retention is inherited, not extended.** `fill-forms` stores exactly one
  output through the existing `file` table and object-storage adapter, so the
  plan-based retention sweep applies unchanged. No new table, column or bucket.
* **Tenant isolation is inherited.** Inputs are read through
  `isAuthorizedFileStorageAccess` inside the job's tenant scope, outputs are
  written through `screenAndStoreWorkerOutputs`, and status/download go through
  `findJobForUser` / `findOutputFileForUser`. The slice adds no path around any
  of them.

## Verification after writing

`fillFormPdf()` re-opens its own output and checks, independently of the code
that wrote it:

1. every requested value round-trips (`getText`/`isChecked`/`getSelected`),
2. every widget of a touched field has a `/AP /N` stream, and state maps have a
   state that resolves to a stream,
3. every field that was **not** in the request still holds its previous value.

A failure throws `FORM_OUTPUT_UNVERIFIED` and the pipeline never stores the
bytes. The `/NeedAppearances` flag is deleted on the output, because leaving it
set invites a reader to regenerate (and discard) the appearances that were just
verified.

## Arabic / RTL evaluation (reported honestly)

Measured against the approved stack, not assumed:

* **Vector path.** pdf-lib's appearance generator encodes WinAnsi only. An
  Arabic value throws `WinAnsi cannot encode "أ" (0x0623)`. There is no shaping
  engine in the approved dependency set (no fontkit, no HarfBuzz), so **vector
  Arabic text with correct shaping is not achievable in this slice**.
* **Raster path (implemented).** Values that WinAnsi cannot encode are painted
  into a PNG with `@napi-rs/canvas` and the vendored
  `@fontsource/noto-sans-arabic` faces, then installed as the widget's
  `/AP /N`. The canvas performs Arabic shaping and bidi (`direction = "rtl"`,
  right alignment), so the glyphs are correct. Measured: a 300×22 pt Arabic
  widget becomes a 9 116-byte PNG in ~54 ms; the whole 1-page bilingual fixture
  in this suite saves in well under a second.
* **Trade-off, stated plainly.** The value is preserved as a real form-field
  value (name, type, value, state), but the glyphs *inside that widget* are
  pixels: they cannot be re-selected with a text tool, and the fallback font is a
  single weight with no per-field font metrics. Every other widget and the rest
  of the document keeps vector text.
* **Other scripts are refused**, not painted as tofu: only Latin, Latin-1/Latin
  Extended, Arabic (and its presentation blocks), their punctuation, and bidi
  controls are rasterisable. CJK/Cyrillic/Devanagari values raise
  `FORM_UNSUPPORTED` with the field name. Glyph coverage was measured
  (U+2014, U+2013, U+201C-201D, U+2022, U+2026, U+00A0 render at real advance
  widths; CJK/Cyrillic/Devanagari fall back to a 1 em notdef box).
* **Unsupported, recorded as backlog:** true Arabic text shaping in the vector
  appearance stream requires an embedded Unicode font plus a shaping engine.

## Production build (Next/Turbopack)

`npm run build` is a mandatory CI gate, so the new modules were verified against
it. Two bundling failures were found and fixed — both would have broken the gate
while every unit test still passed:

1. **Native addon in a route chunk.** A static `import { createCanvas } from
   "@napi-rs/canvas"` reached an app route through
   `/api/fill-forms/inspect`, and Turbopack failed with "non-ecmascript
   placeable asset". The rasteriser is now loaded lazily through a *runtime*
   require whose specifier is not a string literal, so the addon never enters
   the bundle; it is resolved from `node_modules` by the worker at run time.
   Types stay type-only.
2. **`.woff` files as build inputs.** `require.resolve()` of a `.woff`
   specifier made the bundler treat the font as a build asset ("Unknown module
   type"). Fonts are now located from
   `require.resolve("@fontsource/noto-sans-arabic/package.json")` plus a path
   join, which stays inside JavaScript.

Verified with `npx next build` (Next.js 16.3.4 / Turbopack): with the
environment's Google-Fonts fetch stubbed out (this sandbox is offline, and
`src/app/layout.tsx` needs `fonts.googleapis.com`), the build reports
**`✓ Compiled successfully`** with **0** Turbopack errors. The baseline commit
fails the same offline fetch, so that is an environment limitation, not a
regression; no change to `layout.tsx` is included in this branch.

## Integration contracts

* `fields` is a **dedicated job parameter**, never a flat option and never a
  re-parsed JSON string: `toolsWithDedicatedJobParameters` in
  `src/lib/tools/options.ts`. The option contract for the tool is exactly
  `{ flatten: boolean (default false) }`, schema version `1`; the registry
  advertises `fieldsParameter: "fields"`.
* Idempotency: the client fingerprint includes the field map, so editing a value
  is a new operation and only an unchanged re-submit reuses the key.
* Access control, output screening, malware scanning, audit logging, metrics and
  credit accounting are inherited unchanged from the existing job pipeline; this
  slice adds no parallel path. Logs record counts and the engine, never values.
* The browser never imports `pdf-lib` or `@napi-rs/canvas`: it imports the pure
  `form-validation.ts` contract and the read-only
  `/api/fill-forms/inspect` route, which creates no job and stores nothing.

## Evidence

* Environment: Node 22.22.3, `node --import ./scripts/node-platform-compat.mjs
  --import tsx --test`, sandbox without `prisma generate` (see below).
* `test/fill-forms.runtime.test.ts` — 17 cases, 17 pass. Real engine, real
  documents, outputs reopened independently.
* `test/fill-forms.pipeline.test.ts` — 4 cases, **4 skipped** in this
  environment (no generated Prisma client; CI runs them).
* `test/fill-forms.contract.test.ts` — 8 cases, 8 pass (registry, options,
  workflow/Agent rejection, API surface, worker wiring, browser safety,
  transport contract).
* Combined focused run: **29 tests — 25 pass, 0 fail, 4 skipped.**
* Whole local `test/*.test.ts` suite: 370 tests — 322 pass, 13 fail, 35 skipped.
  The same 13 files fail on the untouched base commit (verified by stashing),
  all for environment reasons (missing generated Prisma client, no
  Postgres/Redis/Groq/clamd). No new failure, and 4 skips are the pipeline
  cases above.
* No `2026-11-23` evidence ledger, no `DIP-CR-006` document and no
  `test/fixtures/processing/` corpus exist in this repository. This report
  therefore cites no ledger rows and every fixture is generated in-code rather
  than referenced from a missing source.
* `prisma generate` cannot run in this sandbox (`binaries.prisma.sh` is
  unreachable), so `tsc`/tests that need the generated client report as skipped
  or are filtered by path. This is a pre-existing environment limitation, not a
  result of this change.
