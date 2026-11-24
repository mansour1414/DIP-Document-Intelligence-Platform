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

Counts below are stated **for the commit that carries this document** and are
the only current figures. Earlier figures from the first Stage 2 push are kept in
their own subsection and labelled as historical (FF-11).

* Environment: Node 22.22.3, `node --import ./scripts/node-platform-compat.mjs
  --import tsx --test`, sandbox without `prisma generate` (see below).
* `test/fill-forms.runtime.test.ts` — **26 cases, 26 pass**. Real engine, real
  documents, outputs reopened independently.
* `test/fill-forms.contract.test.ts` — **16 cases, 16 pass** (registry, options,
  workflow/Agent rejection, API surface, worker wiring, browser safety,
  transport contract, plus one structural case per remediation finding).
* `test/fill-forms.pipeline.test.ts` — **4 cases, 4 skipped** in this
  environment. CI runs them: `npx prisma generate` precedes `npm test` in
  `ci.yml`, and `DIP_REQUIRE_PIPELINE=1` turns a skip into a failure there.
* Combined focused run: **46 tests — 42 pass, 0 fail, 4 skipped.**
* Whole local `test/*.test.ts` suite: **489 tests — 431 pass, 15 fail, 43
  skipped.** The same 15 files fail on the untouched base commit (473 / 415 / 15
  / 43), all for environment reasons (missing generated Prisma client, no
  Postgres/Redis/Groq/clamd). The delta is +16 tests and +16 passes with an
  identical failure set.

### Historical results (superseded — do not cite as current)

The first Stage 2 push reported **29 focused tests — 25 pass, 4 skipped**
(17 runtime, 8 contract, 4 pipeline) and **370 whole-suite tests — 322 pass, 13
fail, 35 skipped**. The independent review ran **30** focused cases (17 runtime,
9 contract, 4 pipeline, 0 skipped) against that head and found them all passing.

Those numbers no longer describe the repository. They are recorded only so that
the earlier report and the review can be read against what was actually measured
at the time, per DIP-CR-006 test sequencing.

* `prisma generate` cannot run in this sandbox (`binaries.prisma.sh` is
  unreachable), so `tsc`/tests that need the generated client report as skipped
  or are filtered by path. This is a pre-existing environment limitation, not a
  result of this change.

## Remediation round (independent review, FF-01 … FF-12)

An independent review of the first Stage 2 head returned **NO-GO** with
5 HIGH / 5 MEDIUM / 2 LOW findings. The table below states, per finding, what
changed and how far it is verified. A finding is only "verified" when a
regression test reproduces the reviewed defect and the fix is exercised by it.

| Finding | Change | Status |
| --- | --- | --- |
| FF-01 | Inspection moved to `src/lib/pdf/form-inspection.ts`, which imports `pdf-lib` only. The inspect route no longer reaches the rasteriser; font resolution in `form-appearance.ts` is lazy and validates the resolved specifier. | **FIXED AND VERIFIED** — production build completes (compile, page-data collection, 111/111 static pages, finalization) and the built route answers `401 AUTH_REQUIRED` under `next start`. |
| FF-02 | Bounded recursive `/Kids` walk with inherited `/FT`, indirect-reference following, cycle/depth/node/hop budgets. Any structural anomaly is `FORM_RESTRICTED`; only unparseable bytes remain `FORM_UNSUPPORTED`. | **FIXED AND VERIFIED** — nested signature, inherited `/FT`, dangling and non-dict `/Perms`, non-array `/Fields`, and a `/Kids` cycle all rejected; a library stack overflow is converted to a coded refusal. |
| FF-03 | Values encrypt to Redis under a tenant+job-bound AAD reference (`form-payload.ts`), non-destructive read for retries, purged on success, final failure, cancel, expiry and enqueue failure; TTL backstop = `abandonedGraceMs()`. `Job.params` carries `fieldsRef` only. | **PARTIALLY FIXED — reassessed in round 2 below.** The payload, AAD binding and purge sites are unit-verified; round 2 found the *lifecycle* and *expiry race* defects listed in that section, and fixed them. Key derivation and TTL remain blocked on owner authorization. |
| FF-04 | `Content-Length` pre-check before `formData()`, cheap signature/trailer/page-marker checks, screening before parse, bounded parse budget, per-tenant rate and concurrency admission. | **SUPERSEDED BY ROUND 2** — the header-only bound was bypassable (chunked, false header), and in-process parsing could not be interrupted. Round 2 replaces both with a counting stream and a hard-bounded child process; see priority 2 and 3 below. |
| FF-05 | Flattened widget references are removed from every page `/Annots`; the output is re-read and all remaining annotations must resolve, with zero surviving widgets and unrelated annotations preserved. | **FIXED AND VERIFIED** — the reviewed 15-widget/two-page fixture now flattens to 0 unresolved, 0 widgets, 1 preserved link. Verified with pdf-lib; **pypdf and Poppler are unavailable here**. |
| FF-06 | Restriction preflight in `createToolJob` after `requireCleanUpload`, before billing, storage and enqueue. | **IMPLEMENTED BUT UNVERIFIED** — position is asserted against the real source; no live billing/DB to prove absence of a charge or row. |
| FF-07 | Arabic line breaks preserved; overflow and illegible geometry rejected with no partial output; Arabic option-list selections rejected rather than comma-joined; Latin option lists keep pdf-lib's correct provider. | **PARTIALLY FIXED — root cause found in round 2.** The gate only ran on the raster (non-WinAnsi) path, so long Latin values were accepted and clipped silently. Round 2 measures every value; see priority 6 below. Border reproduction remains open. |
| FF-08 | Allowed content-free messages plus stable issue codes; no field names or booleans in errors, details or verification mismatches. | **FIXED AND VERIFIED** — text, Arabic, checkbox and unexpected-library-exception paths assert the allowlist and assert that neither value nor field name is serialised. |
| FF-09 | Empty text compares canonically (`undefined` and `""` both mean empty). | **FIXED AND VERIFIED** — clearing to `""` round-trips. |
| FF-10 | 64 KiB measured in UTF-8 bytes; duplicate JSON keys rejected before `JSON.parse`; exactly one `fields` part; both the Web API and the Public API apply all three. | **FIXED AND VERIFIED** — 70,121-byte payload rejected, duplicate keys rejected (including escape-decoded collisions), repeated parts rejected. |
| FF-11 | `loadPipeline` skips only on a genuine missing Prisma client and rethrows anything else; CI sets `DIP_REQUIRE_PIPELINE=1`; counts reconciled in this section. | **FIXED AND VERIFIED** — counts above are measured on the final commit; CI enforcement cannot be exercised here. |
| FF-12 | Trailing blank line removed from `form-schema.ts`. | **FIXED AND VERIFIED** — `git diff --check` is clean for the commit. |

### Limitations that remain

* **Real-service verification is absent.** RLS, Redis, S3 and ClamAV are not
  available in this environment, so those paths are exercised against behavioural
  fakes and the exact gap is recorded per finding.
* **Independent readers are limited to pdf-lib.** pypdf and Poppler are not
  installed here, so the flatten evidence is a structural re-read with pdf-lib
  plus annotation-graph assertions, not a second engine.
* **The PDF boundary is process containment, not a kernel sandbox.** The child
  runs as the same OS user with the same filesystem visibility; it has a minimal
  environment, a heap cap and a hard deadline, but it is not a container.
* **Rasterised Arabic is pixels.** Values keep Unicode `/V` and the widget stays
  interactive, but the glyphs inside that widget are not selectable text.
* **Raster border/background.** An Arabic raster appearance paints its own white
  background and does not reproduce the widget's original border.

---

## Remediation round 2 (architect review of `32285ca`)

A second review returned **NO-GO** with seven priorities. Table below: what
changed, and what is actually proven. Claims are limited to what the evidence in
this repository supports.

| # | Priority | Change | Status |
| --- | --- | --- | --- |
| 1A | Expiry purge race | `applyExpiryPlan` now issues `updateManyAndReturn` and returns the rows it transitioned; the sweep purges payloads from that result set, never from `plan.expireIds`. Dry-run remains non-mutating. No new DB privilege (column `UPDATE` + `SELECT` only) and no migration. | **FIXED AND VERIFIED (behavioural)** — two-planned/one-claimed regression, unique-ownership and "purge follows the write" cases in `test/retention.expiry-race.test.ts` (11/11). Postgres port updated to `UPDATE … RETURNING`. |
| 1B | Queue lifecycle | Terminal decision extracted to `src/lib/jobs/payload-lifecycle.ts`; the worker passes its verdict to the pipeline, so a first-attempt `UnrecoverableError` purges immediately. RETRYING write is now a guarded `updateMany` that cannot revive CANCELLED/EXPIRED/SUCCEEDED. | **FIXED AND VERIFIED (behavioural)** — 14 cases covering success-after-commit, retry success, unrecoverable-first, exhaustion, stalled, crash-after-commit, duplicate delivery, cancel-vs-claim, enqueue failure, expiration and Redis-cleanup failure. |
| 1C | HKDF + bounded TTL | **Not implemented — proposal only** (`docs/payload-key-proposal.md`). Changes the operational guarantee, so it needs owner authorization. | **BLOCKED ON OWNER AUTHORIZATION.** Today's behaviour is unchanged and described honestly. |
| 2 | Isolated PDF boundary | `src/lib/pdf/form-worker.ts` spawns `form-worker-child.ts` per document: minimal `env` (PATH + NODE_ENV only), `--max-old-space-size`, hard deadline → SIGKILL, bounded stdout, bounded input, concurrency cap, guaranteed kill. The child does shape checks → one parse → structural walk → inventory, so the route and the boundary no longer parse twice. | **FIXED AND VERIFIED (behavioural)** — happy path, coded rejection, oversize refusal, deadline kill (4 ms), concurrency refusal; a 400 k-node page-tree bomb rejected in ~850 ms with host RSS flat; heap-bomb child dies SIGABRT with OOM detected at 64 MB and 128 MB; spinning child killed at 1 510 ms. |
| 3 | Request-byte enforcement | `src/lib/http/bounded-body.ts` re-wraps the request body in a counting stream; missing (chunked), false and duplicate-part bodies are all cut off before buffering. Applied to the inspect route, `POST /api/jobs/[tool]` and the Public API. Admission replaced by an atomic single-`EVAL` lease set with unique ids, expiry recovery, per-tenant **and** global ceilings and configurable defaults. | **FIXED AND VERIFIED (behavioural)** — 8 byte-bound cases (all three bypass shapes), 8 lease cases including outage fail-open. Redis is not live here, so atomicity is Redis's documented `EVAL` guarantee, not measured. |
| 4 | Typed structural validation | `assertFieldType` / `assertSigFlags` / budget-before-queueing in the walk; `StructureFailure` carries a typed reason. | **FIXED AND VERIFIED** — 10-case pdf-lib probe: cycle, malformed `/FT`, malformed `/SigFlags`, oversized `/Kids`, unresolved reference all rejected with distinct reasons; shared subtrees and 10-level nesting accepted. |
| 5 | Preflight before billing | Ordering was already correct (screening → preflight → billing → storage → job). The remaining hole was an orphan **charge**: a failure after authorization left a consumed credit and a `job.created` event with no job. `enforceJobCreation` now returns an idempotent release handle used by the creation-failure path. | **FIXED AND VERIFIED (structural + behavioural)** — ordering and release invariants in `fill-forms.contract.test.ts`; the ledger reversal itself is not exercised against a live database. |
| 6 | FF-07 fidelity | **Root cause found and fixed:** Latin values that WinAnsi could encode bypassed the legibility gate entirely (pdf-lib's `defaultUpdateAppearances` clips silently), so the exact reported defect was the one case never measured. Every text value is now measured before any appearance is written; Latin stays vector text, Arabic still rasterises; the shrink loop's floor is expressed in points, not device pixels; geometry rejections carry their own issue codes. | **FIXED AND VERIFIED** — 9 behavioural cases: rotation preserved at 0/90/180/270, option semantics, interactive-vs-flattened agreement, Latin overflow rejection, Latin-stays-vector, Arabic and mixed direction, point-based floors, blank values. Border reproduction remains open (see limitations). |
| 7 | Content-free errors | `src/lib/jobs/error-boundary.ts`: `Job.error`/`JobStep.error` carry `{ code }` only, from a closed vocabulary; anything else collapses to `PROCESSING_FAILED`. The pipeline's `error.message` writes are gone. | **FIXED AND VERIFIED** — 13-case synthetic canary: native, Redis, filesystem, parser and non-Error throws all fail to leak, plus a source check that the pipeline uses the boundary. |

### Approval still required

1. **Payload key and lifetime (priority 1C)** — see `docs/payload-key-proposal.md`.
   Not applied. Two independent decisions: purpose-derived keys, and a bounded
   TTL ceiling.
2. **Expiry purge side effect (priority 1A)** — the sweep deletes the Redis
   payload of jobs it actually expired. This does not change *which* jobs expire
   or *when*, but it is a new side effect inside an approved retention operation.
3. **Admission and boundary defaults (priorities 2 and 3)** — the numbers below
   are proposed operational defaults, all environment-configurable, and none is
   an approved product quota.

### Operator configuration (all optional)

| Variable | Default | Bounds | Meaning |
| --- | --- | --- | --- |
| `FORM_WORKER_TIMEOUT_MS` | 20 000 | 1 000 – 120 000 | Hard deadline before SIGKILL |
| `FORM_WORKER_MAX_HEAP_MB` | 256 | 64 – 2 048 | `--max-old-space-size` for the child |
| `FORM_WORKER_CONCURRENCY` | 2 | 1 – 16 | Simultaneous child processes |
| `FORM_INSPECT_CONCURRENCY` | 2 | 1 – 16 | Per-tenant open inspections |
| `FORM_INSPECT_GLOBAL_CONCURRENCY` | 8 | 1 – 64 | Open inspections per process |
| `FORM_INSPECT_RATE_PER_MINUTE` | 30 | 1 – 600 | Per-tenant inspections per minute |

### Verification for this round

* Focused suites: `fill-forms.*` + `retention.*` + `jobs.error-boundary` +
  `http.bounded-body` + `inspection-lease` = 171 tests, **167 pass, 0 fail**
  (4 skips are the Prisma-gated pipeline tests).
* Full suite `npm test`: **545 tests, 487 pass, 15 fail, 43 skipped.** The 15
  failing files are identical to the commit this branch was cut from, and are
  environment failures (no Prisma client, no Redis, no Postgres, no ClamAV).
* `npx tsc --noEmit`: 447 errors, **identical to baseline** (all Prisma-absence).
* `npx eslint src/ workers/ test/`: 0 errors.
* `npx prisma generate`: **still blocked** (TLS to the binary host). FF-01
  therefore remains *pending clean-build verification* and no later claim rests
  on a stubbed build.

---

## Remediation round 3 (architect review of `dfe658b`)

Review returned **NO-GO** with six priorities plus a CI failure. This round was
deliberately bounded: no new abstractions, no scope growth, and two of the
architect's findings turned out to be defects in the round-2 work itself.

### CI classification

The failing run (`45409389856`) reported 4 pass / 7 fail. **Only one defect was
real, and it was mine:** `src/lib/jobs/document-pipeline.ts:122`,
`TS2322` on `data: { params: rest }`. It broke Type Check, Build, Browser and
Full Release B, which all run the type checker.

| Job | Classified as | Evidence |
| --- | --- | --- |
| Type Check | **PR defect (fixed)** | `TS2322` annotation on `document-pipeline.ts:122` |
| Build / Browser / Full Release B | **cascade of the same** | same annotation; these jobs typecheck first |
| Test, Integration / Processing | **not established** | logs unavailable — see the gap below |
| CR-002 Groq evaluation | **independent** | HTTP 413 from the provider; no provider, model, secret or acceptance gate was touched |

**Evidence gap, stated plainly:** the job logs could not be downloaded —
`gh run view --log-failed` and the per-job logs API both redirect to
`blob.core.windows.net`, which this environment cannot reach. My only CI evidence
is the check-run annotations, which carry the `TS2322` and nothing about the
workflow/`audit_logs` failures the architect saw in Integration/Processing. I
therefore **do not claim** that those are pre-existing. The files involved
(`test/workflow.*`, `test/phase9*.rls.integration.mjs`) are untouched by this
branch, which makes a PR-caused regression unlikely but not proven, and nothing
here should be read as such.

### P1 — the multipart regression (a total outage on three endpoints)

Undocumented in the round-2 report: `withBodyLimit` substituted `request.body`
via `Object.defineProperty` and then the route called `request.formData()` on the
**original** request. `formData()` reads the body state the request was
constructed with, which the substitute had already drained:

```
TypeError: Body is unusable: Body has already been read
```

That is Inspect, Web submission and the Public API — all of them, not an edge
case. My tests missed it because they called `.body.getReader()` on the stream I
had just substituted, exercising the substitute and never the consumer.

The replacement builds a **new `Request`** over a pull-based bounded stream, so
`formData()` parses the bounded stream like any other body. Measured behaviour:

| Requirement | Result |
| --- | --- |
| Valid multipart succeeds via `formData()` | pass (`test/http.bounded-body.test.ts`) |
| Oversized rejected while consuming bytes | pass |
| Missing / false `Content-Length` cannot bypass | pass (both cases) |
| Backpressure | pull-based; one chunk per consumer read, no eager drain |
| Upload deadline | enforced **inside the stream** after measuring that an `AbortSignal` does *not* interrupt `formData()` (a slow body kept reading past the abort) |
| Admission before the upload is consumed | pass — the lease is acquired before a single byte is read |
| Duplicate / invalid parts | repeated `options`/`fields`/`secrets` parts rejected; `files` remains multi-valued by design |
| 64 KiB fields payload preserved | `multipartBudget` adds framing overhead to the file budget, never subtracts from the fields allowance |

### P2 — admission now fails closed

The round-2 code failed open on a Redis error. The justification was that the
parser pool bounds itself; that is wrong, because the in-process cap is only
reached **after** admission, so failing open removes both ceilings exactly when a
tenant could exploit it. It now raises `AdmissionUnavailableError` and the route
answers 503 without reading the body. Lease lifetime was also wrong: 120 s is
shorter than the 120 s upload deadline alone, so it is now 420 s (upload +
screening + parse) and a test asserts the relationship.

**Not proven:** that Redis executed the Lua. There is no Redis here, so the
semantics are exercised against an in-memory implementation of the same commands.
Atomicity of `EVAL` is Redis's documented guarantee, not something this repository
demonstrates.

### P3 — boundary gaps closed, and what is *not* closed

Closed: submission preflight now goes through `processPdfBounded` instead of
parsing in-process; `validateUpload`'s page-counting parse now runs *after*
screening; the child's reply is validated against `isFormFillErrorCode` rather
than trusted; IPC output is bounded by **bytes** (`chunk.byteLength`, not
`stdout.length`); a killed child keeps its pool slot until the kernel reaps it.

**Two of the architect's points are confirmed, not closed:**

1. **A V8 heap cap is not an RSS cap.** Measured: a child with
   `--max-old-space-size=64` still reads and writes arbitrary files.
2. **A stripped environment is not a sandbox.** Measured: the child read
   `/tmp/dip-secret-probe.txt` successfully. Network egress was blocked here by
   the *sandbox*, not by the boundary.
3. `node --permission` **does** deny filesystem access (`ERR_ACCESS_DENIED`) and
   would be the right OS-level control — but it breaks the `tsx` loader the child
   depends on, so it cannot be enabled without changing the child's module
   strategy.

**Release blocker (unchanged in kind, restated precisely):** the child is
contained in a *process*, not in a security boundary. It runs as the same OS user
with the same filesystem and (absent a network policy) the same egress. Closing
this needs a deployment control — a dedicated container/namespace with a read-only
root, no egress policy and a memory cgroup — which is infrastructure, so it stays
open and is **not claimed as closed**.

Also open: **the standalone build does not emit the child.** `output: "standalone"`
inlines this module into a server chunk, so a sibling `form-worker-child.js` does
not exist there. `childEntry()` now searches several roots and honours
`FORM_WORKER_ENTRY`, and `next.config.ts` declares the entry through
`outputFileTracingIncludes`, but **no standalone image was built and exercised in
this environment**. That is a release blocker, not a closed gate.

### P4 — the counter frame (a real bug in round 2)

In BullMQ 6.3.4, `attemptsMade` is incremented **inside** `Job.moveToFailed`
(`job.js:510`) and the worker emits `failed` afterwards (`worker.js:651`). The
retry decision is taken earlier still, from the pre-increment value
(`job.js:446`). Round 2 applied the processor-entry form (`attemptsMade + 1`) in
the `failed` handler — adding one to an already-incremented counter. Reproduced:

```
attempt 2 of 3: entry=1  bullmqRetries=true  failedEventCounter=2
   truth: queueWillRetry=true   my "terminal"=true   <-- MISMATCH
```

On attempt 2 of 3 the payload was purged **while a retry was still scheduled**.
The two frames are now separate exports — `classifyFailedEvent` takes the
post-increment counter, `classifyAtProcessorEntry` the pre-increment one — and the
tests walk a real three-attempt run asserting that the
worker, the pipeline and the queue always agree.

Also fixed: the `classifyTerminal` hook was declared and consumed but never
passed by the worker — dead wiring, removed. The duplicate-success early return
now retries the purge instead of skipping it, since a crash between commit and
purge would otherwise leave the payload to the TTL. Public API cancellation was
an unguarded `tx.job.update`; it is now status-guarded, so a cancel racing a claim
cannot overwrite a RUNNING or SUCCEEDED job and then purge a live attempt's inputs.

### P5 — the charge could be released after the job committed

Round 2's compensation ran in a single `catch`, so it also fired when the failure
came **after** the job row committed. Reproduced:

```
enqueue-throws   committed=1 releases=1 -> BUG: job committed but charge released
ambiguous        committed=1 releases=1 -> BUG: job committed but charge released
```

Cleanup now branches on whether a job committed. Before: release the charge and
delete the inputs. After: keep both, log `job.enqueue_failed_after_commit`, and
leave the row QUEUED so the expiry sweep reconciles a job that never ran. An
ambiguous acknowledgement is exactly the case where "the exception proves the
queue rejected it" is false.

### P6 — preserved fixes

The expiry purge still follows the transitioned rows only. **Not verified here:**
that the retention role can run `UPDATE … RETURNING params` against a real
database. The migration grants `SELECT` on `jobs` and
`UPDATE (status, error_code, completed_at, updated_at)`, which is exactly what the
statement needs and requires no widening — but the assertion is a new integration
test that **skips** without a database, so it is unproven. (The SET list does not
touch `params`; only the `RETURNING` reads it, which `SELECT` covers.)

The error boundary was reviewed for regressions and **did** have one: the closed
vocabulary collapsed ~24 operational codes that previously reached users and
runbooks (`FONT_UNAVAILABLE`, `SECRET_REFERENCE_EXPIRED`, `PDF_INVALID`, …). Those
are restored, with a test that fails if any is dropped again.

HKDF/TTL remains proposed only. `RETENTION_APPLY` remains disabled.

### Round-3 verification

| Gate | Result |
| --- | --- |
| `npm test` | **574 tests, 515 pass, 15 fail, 44 skipped** |
| Failing files | the **same 15** as the branch base; all environment (no Prisma client, Redis, Postgres, ClamAV) |
| `tsc --noEmit` | **447 = baseline exactly**, zero net new errors |
| `eslint src/ workers/ test/` | 0 errors, 0 warnings |
| `prisma generate` | still blocked (TLS); the `TS2322` fix is verified against a faithful mock of Prisma's JSON input types, not the generated client |
| CI logs | **unavailable** (storage host unreachable); annotations only |
