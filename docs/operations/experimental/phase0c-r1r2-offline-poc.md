# DIP Phase 0C — R1/R2 Minimal Isolated Offline Proof of Concept

**Status:** EXPERIMENTAL — ISOLATED — OFFLINE ONLY. Not production integration. Not a Change Request approval.
**Date:** 2026-11-17
**Base:** `main` @ `e9fc069189fd54534b065a87d10fd9352b75d993`
**Statuses (verbatim):** `CI: NOT CHECKED. Security Gate: OPEN. Licensing Gate: OPEN. Stage 7: NOT ACCEPTED. R1/R2: OPEN.`

## 1. Scope and non-goals

This PoC evaluates, **offline only**:

- **R1** — PDF-embedded ZIP64 detection and inspection (explicitly referenced attachments).
- **R2** — Bounded, streaming inspection of compressed nested ZIP archives.

Explicit non-goals: no production wiring, no modification of `src/`, `workers/`, `package.json`,
dependencies, or workflows; no live ClamAV execution; no `workflow_dispatch`; no deployment; no GHCR
publishing; no Change Request approval; no gate closure; no merge. A live isolated experiment is a
**future, separately authorized** step (Section 10).

Deliverables (all inside authorized paths):

| Path | Role |
| --- | --- |
| `scripts/experiments/phase0c_r1r2_fixtures.py` | Deterministic offline fixture builders (EICAR halves, benign controls, byte-exact ZIP32/ZIP64, small PDFs with attachment trees). Stdlib only. |
| `scripts/experiments/phase0c_r1r2_poc.py` | Bounded inspection prototype: single cumulative resource budget, streaming ZIP reader, narrow PDF attachment parser, coverage ledger, offline scanner adapters, case suite, JSON report. Stdlib only. |
| `test/phase0c-r1r2-offline-artifacts.py` | Python `unittest` regression suite (run explicitly; not part of `npm test`). |
| `test/phase0c-r1r2-offline.test.mjs` | Node `node:test` runner (picked up by `npm test`) that executes the PoC offline and asserts governance/safety invariants; skips honestly if `python3` is unavailable. |

## 2. MASTER BASELINE review (pre-implementation)

Reviewed before implementation:

- **Approved pre-storage boundary** (`docs/production-readiness.md`): malware scanning happens
  **after** validation and **before** durable storage/job creation. The actual ingest sequence in
  `src/lib/jobs/orchestrator.ts` is `validateUpload` → `requireCleanUpload` → `storage.put`
  (then DB job creation and enqueue). A **post-storage worker scan does NOT satisfy** this boundary
  and is never used as evidence here.
- **Tool limits** (`docs/phase-1-capability-audit.md`): qpdf does not interpret content-stream
  semantics; its `--json=1 --json-key=objects --decode-level=none` usage (production: signature
  detection only, `src/lib/pdf/qpdf.ts:38`) enumerates object metadata and is **not** exhaustive PDF
  stream inspection. PDF.js exposes a bounded subset of decoded image XObjects and is **not** an
  exhaustive arbitrary-stream inspector. Neither is invoked or relied upon in this PoC.
- **Phase 0B residual risks** (`docs/operations/experimental/clamav-phase0b-remediation-design.md`):
  R1 (PDF-embedded ZIP64) and R2 (compressed nested archives) are `RESIDUAL_RISK_OPEN`; raw clamd
  CLEAN, observational controls, and residual-risk probes never count as security PASS.
- **Phase 0A verified failures**: `D_eicar_zip64` — ZIP64 silent bypass returning `stream: OK` on
  ClamAV 1.5.4; `E1_yes_small_zip32_maxfilesize` — silent truncation at max file size.
- **Existing components reused conceptually (not imported into production):** Python stdlib
  `zipfile`/`zlib` behaviour model (note: `zipfile`/`read()` truncate at *declared* size — this PoC
  deliberately does NOT rely on that), the isolated ZIP/OOXML preflight
  (`docs/operations/experimental/clamav-phase0b-zip-preflight.mts`, zero-decompression scope), and
  the EICAR-based test corpus conventions of the Phase 0A/0B evidence scripts.
- **Licensing** (`docs/license-registry.md`): no new dependencies introduced; ClamAV stays a
  separate private GPL-2.0-only INSTREAM scanner; qpdf Apache-2.0 controlled subprocess; Ghostscript
  prohibited. The OCR-specific licensing closure (2026-09-10) is not a global R1/R2 gate.

## 3. Mandatory architecture corrections — implementation mapping

| # | Correction | How this PoC honours it |
| --- | --- | --- |
| 1 | Preserve the approved pre-storage boundary | `security_boundary` block in every report restates `validateUpload -> requireCleanUpload -> storage.put`; `post_storage_worker_scan_satisfies_pre_storage: false`; no code touches the boundary. |
| 2 | Post-storage worker scan ≠ pre-storage requirement | Stated verbatim in report and here; no worker path is used or implied. |
| 3 | No claim that qpdf --json / PDF.js give exhaustive stream inspection | `tool_capabilities` records both as `NOT_VERIFIED` with explicit reasons; the PoC's PDF parser is declared narrow and gap-tagged; arbitrary streams are ledger-skipped with reasons. |
| 4 | ONE end-to-end resource budget (extraction + scanning + timeouts + memory + disk) | `ResourceBudget` is a single shared object threaded through PDF parsing, attachment extraction, nested recursion, and scanner feed. Scanner `feed()` calls charge the **same** wall-clock/CPU/memory/temp-disk ceilings. |
| 5 | Encrypted-PDF and post-unlock output scanning are explicit requirements | `SEC-REQ-02` / `SEC-REQ-03` recorded in every report; `/Encrypt`-bearing input fails closed as `UNSUPPORTED` with reason `ENCRYPTED_PDF_REQUIRES_POST_UNLOCK_OUTPUT_SCAN`; genuine encrypted fixtures are `NOT_VERIFIED` (qpdf absent offline — none fabricated). |
| 6 | Raw clamd CLEAN ≠ complete nested-content inspection | Every `CLEAN`-style scanner result is paired with a coverage assessment; `derive_conclusion` can only emit `COMPLETE_SAFE_SCAN` when coverage is complete **and** the ClamAV scanner is verified; the offline suite can therefore never emit it. Phase 0A `D_eicar_zip64` is cited in ledger notes. |

## 4. Design

### 4.1 Verdict taxonomy

Per object and per case: `INSPECTED` | `REJECTED` | `UNSUPPORTED` | `NOT_VERIFIED`.
Rules: unsupported or incomplete inspection **fails closed**; a case with any `REJECTED` targeted
object is `REJECTED`, else `UNSUPPORTED`/`NOT_VERIFIED` propagate; skipped objects are listed with
explicit reasons and never counted as inspected. Absent tooling ⇒ `NOT_VERIFIED`, never PASS.

### 4.2 Resource budget (single end-to-end, conservative offline ceilings)

| Limit | Offline PoC ceiling | Production reference (unchanged) |
| --- | --- | --- |
| Input bytes | 4 MiB | `MAX_FIXTURE_ARCHIVE_BYTES` 16 MiB (0A), `MALWARE_SCAN_MAX_BYTES` 100 MiB |
| Expanded bytes (cumulative) | 16 MiB | `MaxScanSize 400M` is a **cumulative scan-size** reference, not a materialised footprint |
| Per-member actual bytes | 2 MiB | — |
| Entry/attachment count | 256 | — |
| Recursion depth | 3 (root = 0) | — |
| CPU time | 3 s | — |
| Wall-clock time | 5 s | — |
| Memory (reserved-accounting) | 32 MiB | — |
| Temp disk (accounted) | 8 MiB — **0 bytes written** | CI worker tmpfs `size=256m` |
| Max materialized re-parse buffer | 8 MiB | — |
| Read chunk | 64 KiB | `ClamdScanner` 64 KiB INSTREAM chunks |

**400 MiB vs 256 MiB resolution:** the PoC performs **zero filesystem extraction**. Members are
read in bounded 64 KiB streaming chunks; nested containers are held only in a bounded in-memory
re-parse buffer (`max_materialized_object_bytes`) and released after recursion. Temp-disk usage is
accounted and enforced (`temp_disk_bytes_used = 0` in every case). Therefore there is no
simultaneous promise of 400 MiB materialised extraction and a 256 MiB disk ceiling: the 400 MiB
number is a cumulative scan-size reference, and streaming + reclamation are proven by construction
and by the budget accounting in the report.

### 4.3 Streaming bounded ZIP reads

- Central directory parsed byte-exactly (ZIP32 + ZIP64 EOCD/locator/sentinels/`0x0001` extra fields).
- Members are **inflated to EOF and ACTUAL bytes counted** — the declared uncompressed size is
  never trusted (forged-size case `R2-10` proves rejection on mismatch). CRC is verified against
  actual inflated bytes (`R2-06`).
- Encrypted members (flag bit 0 / strong-encryption bits / method 99) and unsupported methods
  (only 0 STORED and 8 DEFLATE supported) fail closed (`R2-07`, `R2-08`).
- Member names pass `safe_member_path` (virtual ledger labels only; the PoC has **no filesystem
  extraction primitive at all**). Traversal/absolute/drive/backslash/control names are rejected
  (`R2-09`).
- Nested containers are detected by **content sniff, not file extension** (spoofed-extension case
  `R2-04`), bounded in size, and recursed under the same budget (`R2-05` depth-limit case).

### 4.4 Narrow PDF attachment parser (R1)

Supported (all explicitly referenced): `/EmbeddedFiles` name tree, `/Filespec` + `/EF /F|/UF`
references, `/FileAttachment` annotations via `/FS`, `/AF` associated-files arrays. Embedded file
streams are extracted by absolute `/Length` only; filtered (`/FlateDecode`) and indirect-`/Length`
streams are `UNSUPPORTED` (no PDF filter decoder is implemented). `/Encrypt` ⇒ `UNSUPPORTED`
fail-closed (genuine encrypted fixtures `NOT_VERIFIED` offline). Incremental revisions
(two `%%EOF`) and duplicate object ids ⇒ `NOT_VERIFIED`. Malformed input (no xref/trailer/EOF) ⇒
`REJECTED` with no recovery attempted. Unreferenced streams and `/ObjStm`-hidden objects are
ledger-skipped with explicit reasons — **attachment-only coverage is not reported as complete R1**.

### 4.5 Scanner adapters (offline)

- `OfflineEicarControlProbe` — deterministic streaming detection of the standard EICAR test
  signature only (independent positive/negative controls). It is explicitly **not** a ClamAV
  scanner; its verdict is always `NOT_VERIFIED` with reason `CLAMAV_OFFLINE_UNAVAILABLE_CONTROL_PROBE_ONLY`.
- `FakeAlwaysCleanScanner` — stub used **only** to prove the invariant: `CLEAN` + incomplete
  coverage ⇒ `NOT_COMPLETE_SAFE_SCAN` (asserted in the unittest suite, never shipped in the suite's
  case verdicts).
- Live ClamAV: **NOT VERIFIED** in this step (`LIVE_CLAMAV_EXPERIMENTS_FORBIDDEN_IN_PHASE_0C_OFFLINE_STEP`).

### 4.6 Coverage ledger and conclusion

Per object: path, depth, detected content type, structural verdict, extracted bytes, scanner verdict
(when scanned), skip reasons, resource limits hit. Per case: structural completeness vs end-to-end
completeness (end-to-end is **always INCOMPLETE offline** because ClamAV is unverified), plus
`derive_conclusion` blockers. `COMPLETE_SAFE_SCAN` is unreachable offline by construction.

## 5. Case matrix (28 cases; all expected == observed in the offline run)

| Case | Description | Expected | Observed |
| --- | --- | --- | --- |
| R1-01 | `/EmbeddedFiles` name tree → `/Filespec` → `/EF` ZIP64 EICAR attachment | INSPECTED | INSPECTED |
| R1-02 | `/Filespec` with both `/EF /F` and `/UF` references | INSPECTED | INSPECTED |
| R1-03 | FileAttachment annotation → `/FS` → `/Filespec` → `/EF` | INSPECTED | INSPECTED |
| R1-04 | `/AF` associated files on Catalog | INSPECTED | INSPECTED |
| R1-05 | Benign ZIP32 attachment (negative structural control) | INSPECTED | INSPECTED |
| R1-06 | Unreferenced `/EmbeddedFile` stream (arbitrary-stream gap) | NOT_VERIFIED | NOT_VERIFIED |
| R1-07 | Synthetic `/Encrypt` marker probe → fail closed | UNSUPPORTED | UNSUPPORTED |
| R1-08 | Incremental revisions (two `%%EOF`) | NOT_VERIFIED | NOT_VERIFIED |
| R1-09 | `/ObjStm` marker + arbitrary streams | NOT_VERIFIED | NOT_VERIFIED |
| R1-10 | Malformed PDF (no xref/startxref/`%%EOF`) | REJECTED | REJECTED |
| R1-11 | Duplicate indirect object ids (parser ambiguity) | NOT_VERIFIED | NOT_VERIFIED |
| R1-12 | Filtered (`/FlateDecode`) embedded stream | UNSUPPORTED | UNSUPPORTED |
| R1-13 | Attachment stream over materialization ceiling | REJECTED | REJECTED |
| R2-01 | ZIP32 containing ZIP32 | INSPECTED | INSPECTED |
| R2-02 | ZIP32 containing ZIP64 (EOCD + locator + sentinels) | INSPECTED | INSPECTED |
| R2-03 | DEFLATE-compressed nested archive | INSPECTED | INSPECTED |
| R2-04 | Spoofed extension (nested ZIP as `notes.txt`) | INSPECTED | INSPECTED |
| R2-05 | Depth limit exceeded (chain of 5, ceiling 3) | REJECTED | REJECTED |
| R2-06 | Corrupt member (CRC mismatch on actual bytes) | REJECTED | REJECTED |
| R2-07 | Encrypted archive member | REJECTED | REJECTED |
| R2-08 | Unsupported compression method (LZMA=14) | UNSUPPORTED | UNSUPPORTED |
| R2-09 | Path traversal member name | REJECTED | REJECTED |
| R2-10 | Forged declared uncompressed size | REJECTED | REJECTED |
| R2-11 | Cumulative expanded-byte ceiling | REJECTED | REJECTED |
| R2-12 | Entry-count ceiling | REJECTED | REJECTED |
| CTRL-POS-01 | Independent positive control: direct EICAR | INSPECTED | INSPECTED |
| CTRL-NEG-01 | Independent negative control: benign bytes | INSPECTED | INSPECTED |
| CTRL-NEG-02 | Clean nested ZIP32 — still NOT `COMPLETE_SAFE_SCAN` | INSPECTED | INSPECTED |

The R1 synthetic marker cases (R1-07) are labelled as **SYNTHETIC PARSER PROBES**, not genuine
encrypted PDFs. No real malware is used anywhere; EICAR is the only detection signature.

## 6. Resource-limit evidence (measured offline run, 28 cases)

- Totals: input 22,412 B; expanded 8,721 B; scanner-fed 15,035 B; peak traced process memory
  ≈1.16 MiB (against 32 MiB ceiling); wall-clock per case ≤ 6 ms.
- `temp_disk_bytes_used = 0` and `filesystem_writes = 0` in **every** case; no extraction
  filesystem primitive exists in the module.
- Limit-hit cases: `RECURSION_DEPTH_LIMIT` (R2-05), `EXPANDED_BYTE_LIMIT` (R2-11),
  `ENTRY_COUNT_LIMIT` (R2-12), `MATERIALIZED_OBJECT_LIMIT` (R1-13) — all fail closed with the hit
  recorded in the case budget snapshot.
- `full_extraction_materialized` is `false` in every case (streaming, bounded re-parse only).
- `live_clamav_executed: false`, `network_calls: 0`, `subprocess_calls: 0` in every report.

## 7. R1 coverage achieved vs not verified

**Achieved (attachment-only, offline):** `/EmbeddedFiles` name tree; `/Filespec` + `/EF /F|/UF`;
FileAttachment annotations; `/AF` associated files; ZIP64 embedded as a referenced attachment
(structure parsed, bytes extracted, controls fed). Malformed fail-closed; encrypted
fail-closed; filtered streams and ambiguity gaps explicitly reported.

**NOT VERIFIED / not covered (explicit gaps):** arbitrary PDF streams including unreferenced
`/EmbeddedFile` streams; compressed `/ObjStm` object streams and indirect `/Length`; genuine
encrypted PDFs and post-unlock output scanning; incremental-revision object enumeration; qpdf
`--json` / PDF.js exhaustive stream inspection (explicitly **not** claimed); pdfdetach parity
(binary absent). **This PoC does NOT claim complete R1 remediation.** R1 remains OPEN.

## 8. R2 coverage achieved vs not verified

**Achieved (offline):** ZIP32⊃ZIP32; ZIP32⊃ZIP64 (byte-exact EOCD/locator/sentinels, bounded
stdlib parse that inspects what ClamAV 1.5.4 silently bypassed); DEFLATE nesting with streaming
reads; spoofed-extension content sniff; depth limit; corrupt member; encrypted member; unsupported
method; path traversal; forged declared size; cumulative byte/entry ceilings; zero-disk
materialization.

**NOT VERIFIED / not covered:** live ClamAV verdicts on nested content (forbidden in this step);
multi-disk archives; BZIP2/LZMA/PPMd/Zstd members; ZIP64 data-descriptor variants; encrypted
members with a key (post-decryption scanning); production-scale expansion under a real tmpfs.
R2 remains OPEN.

## 9. Production placement question (UNRESOLVED — no architecture approved)

> **Question:** How can the required R1/R2 inspection complete **before permanent storage** while
> maintaining isolation and acceptable cost?

Alternatives and trade-offs (options only — **none approved**):

1. **Synchronous pre-storage inspection in the API path** (after `requireCleanUpload`, before
   `storage.put`): strongest boundary fidelity; trade-off: API latency for large/nested inputs,
   CPU contention on web pods, must reuse the single end-to-end budget and hard timeouts.
2. **Pre-storage hold queue** (scan-then-store: objects land in a quarantined, non-public,
   retention-bounded staging location only after inspection passes): keeps web path fast;
   trade-off: staging storage is an attack surface that must itself be isolated, non-public,
   least-privilege, and retention-bounded; "permanent storage" definition must be amended only via
   a Change Request.
3. **Bounded hybrid**: size-capped synchronous inspection (small/medium uploads) + hold queue for
   the tail; trade-off: two code paths, two budgets to keep identical, higher operational cost.

All options keep the rule: **nothing is durably stored before inspection completes; a post-storage
worker scan alone never satisfies the boundary.** Decision requires Security + Product gates.

## 10. Licensing observations

- **No new dependencies** introduced (Python stdlib only; Node built-ins only in the test runner).
  `package.json`, lockfiles, and production sources are untouched.
- ClamAV remains a separate private GPL-2.0-only INSTREAM scanner (`clamav/clamav:1.4.3`, image
  digest review required); this PoC does not link, bundle, or redistribute any ClamAV code and does
  not require the scanner image at runtime. Operators distributing the scanner image must preserve
  GPL source offer, license, and notices.
- qpdf (Apache-2.0) is referenced only as an absent-offline capability; not invoked.
- EICAR test signature is a harmless industry-standard test string, not malware.
- The 2026-09-10 OCR licensing closure applies only to the Ghostscript-free OCR path and does not
  close the Licensing Gate for R1/R2. **Licensing Gate remains OPEN.**

## 11. Governance

Preserved verbatim: `CLAMAV-CR-P01` / `CLAMAV-CR-P02` / `CLAMAV-CR-P03` and `CLAMAV-CR-R1` /
`CLAMAV-CR-R2` are **PROPOSED — NOT APPROVED**. All existing approved decisions are preserved.
MASTER BASELINE is not amended. Security Gate **OPEN**. Licensing Gate **OPEN**. Stage 7
**NOT ACCEPTED**. R1/R2 **OPEN**. CI: NOT CHECKED. No live execution workflow was created; no
workflow was dispatched or polled.

## 12. How to run (offline)

```bash
# full offline suite + summary (exit 0 only if every expected verdict matches)
python3 scripts/experiments/phase0c_r1r2_poc.py run
# self-test: suite + hard invariants (no live scan, no writes, no COMPLETE_SAFE_SCAN, controls)
python3 scripts/experiments/phase0c_r1r2_poc.py self-test
# full JSON coverage report
python3 scripts/experiments/phase0c_r1r2_poc.py report

# python regression suite (explicit; npm test does not run .py files)
python3 test/phase0c-r1r2-offline-artifacts.py

# node runner (also executed by `npm test` in CI; skips honestly without python3)
node --test test/phase0c-r1r2-offline.test.mjs
```

## 13. GO / NO-GO for a future live isolated experiment

**NO-GO today / GO-conditional in future.** The offline PoC proves the bounded prototype, budget
accounting, fail-closed behaviour, and ledger semantics. A live isolated experiment (private
container, pinned `clamav/clamav:1.4.3` image with digest review, EICAR corpus, no production
traffic) may proceed only after:

1. Security + Product approval of the placement question (Section 9) as a Change Request.
2. ClamAV ZIP64 behaviour re-verification on the live scanner (Phase 0A `D_eicar_zip64` regression)
   and decision on `CLAMAV-CR-R1`/`R2` (still PROPOSED — NOT APPROVED).
3. Encrypted-PDF fixture verification with qpdf present (SEC-REQ-02/03) and post-unlock output
   scanning design.
4. Live budget tuning (400 MiB cumulative vs 256 MiB tmpfs) under the single end-to-end budget,
   with tmpfs `size=` proven against worst-case streaming peak (memory + re-parse buffer), not
   materialised extraction.
5. Operator preconditions (private network, non-root, read-only rootfs, bounded tmpfs, digest-pinned
   image) documented and reviewed.

Until then: `CI: NOT CHECKED. Security Gate: OPEN. Licensing Gate: OPEN. Stage 7: NOT ACCEPTED. R1/R2: OPEN.`
