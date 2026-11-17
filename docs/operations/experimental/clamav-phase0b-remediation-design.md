# DIP — Phase 0B Isolated Security Remediation Design, Governance & Licensing Plan

> **CURRENT GATE & EXECUTION STATUS (STRICT — DO NOT MISREPRESENT)**
>
> | Gate / Dimension | Status | Basis |
> | --- | --- | --- |
> | **Security Gate** | **OPEN** | Live Phase 0B verification not yet executed; production upload validation & scanner unchanged |
> | **Licensing Gate** | **OPEN** | GPLv2 §2(a)/§3 Corresponding Source, Rust/Ubuntu SBOM, and legal review not yet signed off |
> | **ClamAV Stage 7** | **NOT ACCEPTED** | Remains blocked by Phase 0A verified failures (`D_eicar_zip64`, `E1_yes_small_zip32_maxfilesize`) |
> | **Phase 0B Live Remediation** | **NOT VERIFIED** | Offline design, artifacts, and static/unit checks only — **zero live Docker/clamd runs executed** |
> | **GHCR Publishing / Production Change** | **NONE** | Zero GHCR push, zero production code/Dockerfile/config/dependency modifications |

---

## 1. Executive Summary & Phase 0A Verified Baseline

Phase 0A isolated runtime testing (GitHub Actions run `43979174287`, commit `75e20a1ae64cf9eefac2012c262fcb6031eb8106`, candidate digest `ghcr.io/mansour1414/dip-clamav@sha256:79c668f48507b347acb67cc59cf1c86ea31a1edbd45e8b005dafe41c874a81df`, Ubuntu Jammy `clamav 1.5.4+dfsg-0ubuntu0.22.04.1`) established **two reproducible security failures** (`6 PASS`, `2 FAIL`) under unmodified `clamav-arm64-stage4-candidate.conf` (SHA-256 `75e2fc17058971c143580579d1d6027b5385c1724a3109e79390a272d95909a6`):

1. **Failure 1 — ZIP64 Silent Bypass (`D_eicar_zip64` -> `stream: OK\0`)**:
   - Root cause verified in upstream `Cisco-Talos/clamav` `clamav-1.5.4` (`fa59fca15872bb8a914ba4c68188bcc8a502cbdf`, `libclamav/unzip.c` L706–733, L1115–1130, L1329 and `libclamav/scanners.c:4486-4495`):
   - `libclamav` ignores ZIP64 extra field `0x0001`, misreads `0xFFFFFFFF` sentinels as `CL_EPARSE`, appends a zeroed `zip_catalogue` record, aborts scanning subsequent members (`#1527`), and `result_should_goto_done()` converts `CL_EPARSE` to `CL_SUCCESS` (`stream: OK\0`).
   - Also affects OOXML containers (`scanners.c:5046-5047`), PDF-embedded ZIP64 streams (`#1888`), 8-byte ZIP64 Data Descriptors (`unzip.c:787-820`), and unsupported compression methods (`LZMA=14`, `PPMd=98`, `unzip.c:330-353`).
   - Upstream issues `#1527`, `#1888`, and `#1928` remain **OPEN** with no official upstream release fix. Unmerged community PR `#1845` (`fca76728`) contains a zeroed-record bug and is **explicitly excluded**.

2. **Failure 2 — ZIP32 `MaxFileSize` Silent Truncation (`E1_yes_small_zip32_maxfilesize` -> `stream: OK\0`)**:
   - Root cause verified in `libclamav/unzip.c` (`unz()`, lines 166, 231, 275, 310): `STORED`, `DEFLATE`/`DEFLATE64`, `BZIP2`, and `IMPLODE` branches truncate member output to `ctx->engine->maxfilesize` without calling `cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxFileSize")`.
   - Officially fixed upstream by Cisco Talos in **PR `#1832` / commit `9f84fb3404b9a66c782e33f3e2b0da5e3d32af76`** (`CLAM-3102`, merged to `main` via `cbb9caa0084c9aa55b9e42334e35770d151069bd` on `2026-10-22`), with zero other code drift in `libclamav/unzip.c` relative to `clamav-1.5.4`.

Phase 0B splits remediation cleanly into **two strictly isolated experimental tracks**:
- **Part A (`CLAM-3102`)**: Isolated ARM64 rebuild of Ubuntu's DFSG-clean `clamav 1.5.4+dfsg-0ubuntu0.22.04.1` applying **only** upstream `CLAM-3102` (PR `#1832`), excluding unreviewed PR `#1845`.
- **Part B (ZIP/OOXML Preflight)**: Isolated, zero-decompression, bounded TypeScript structural preflight prototype (not wired into production) rejecting verified ZIP64 variants, unsupported compression methods, malformed ZIP headers, and encrypted OOXML while preserving valid DOCX/XLSX/PPTX/PDF controls and benign `version_needed=45` archives.

---

## 2. Governance Correction & Provisional Change Request Register

### 2.1 Explicit Correction of `CR-004` Identifier Collision

An earlier proposal informally referenced `CR-004` for ClamAV remediation. Repository and decision-register verification confirms:
- **`CR-004` is ALREADY ASSIGNED** in DIP's decision register to **`CR-004 — Competitive Parity Adoption`**.
- Existing repository change-request documents occupy `CR-002` (`docs/cr-002-groq-evaluation.md`) and `CR-003` (`docs/cr-003-groq-production-routing.md`).
- Zero `CLAMAV-CR-*` identifiers exist anywhere in the repository.

**Governance Rule Enforced**:
- `CR-004` is **never** used for ClamAV.
- All existing decisions (`CR-001` through `CR-004` and baseline policies) are preserved verbatim.
- **MASTER BASELINE is NOT amended.**
- All Phase 0B proposals use non-colliding provisional subject-specific IDs (`CLAMAV-CR-P01`, `CLAMAV-CR-P02`, `CLAMAV-CR-P03`) and remain strictly **`PROPOSED — NOT APPROVED`** until formal human review, live runtime verification, and legal/licensing sign-off.

### 2.2 Provisional Change Requests (`PROPOSED — NOT APPROVED`)

| Provisional ID | Status | Title | Scope & Sunset / Exit Trigger |
| --- | --- | --- | --- |
| **`CLAMAV-CR-P01`** | **PROPOSED — NOT APPROVED** | Isolated ARM64 ClamAV 1.5.4 + Upstream `CLAM-3102` Candidate | Rebuilds Ubuntu Jammy DFSG `1.5.4+dfsg-0ubuntu0.22.04.1` with upstream PR `#1832` (`9f84fb34...`) only; excludes PR `#1845`. **Mandatory de-fork trigger**: retire the DIP quilt patch immediately once Ubuntu Jammy publishes an official security/updates package containing `CLAM-3102` (expected ClamAV `>= 1.5.5` or Ubuntu backport) and live tests confirm parity. |
| **`CLAMAV-CR-P02`** | **PROPOSED — NOT APPROVED** | Bounded Zero-Decompression ZIP/OOXML Structural Preflight & Residual-Risk Disclosure | Evaluates isolated TS prototype (`clamav-phase0b-zip-preflight.mts`) aligned to DIP baseline (`100 MiB` upload, `110 MiB` member, `400 MiB` total, `10,000` entries; `16 MiB` experimental CD cap marked `NOT VERIFIED`) covering ZIP64 variants, unsupported compression methods, encrypted OOXML, and malformed headers without decompressing untrusted inputs and without blindly rejecting benign `version_needed=45`. **Explicit non-goals (open residual risks)**: does **not** resolve PDF-embedded ZIP64 (`#1888`, `R1`) or compressed nested archives inside ZIP/OOXML (`R2`). Production upload-pipeline integration requires a separate approved CR after live Phase 0B evidence and false-positive telemetry validation. |
| **`CLAMAV-CR-P03`** | **PROPOSED — NOT APPROVED** | Phase 0B Live Evidence Matrix, GPLv2 Corresponding Source & SBOM Governance | Governs manual-only, default-branch, confirmation-gated, local-only (no GHCR push) live verification (`.github/workflows/clamav-phase0b-evidence.yml`) and defines mandatory Licensing Gate deliverables (GPLv2 §2(a)/§3 Corresponding Source archive, SPDX/CycloneDX SBOM covering Ubuntu + `libclamav_rust` Cargo crates, UnRAR exclusion proof, and legal sign-off) prior to any private/external registry publication. |

---

## 3. Part A — Isolated ARM64 `CLAM-3102` Candidate Design

### 3.1 Verified Ubuntu Jammy DFSG Source Provenance

Preference is given to Ubuntu's DFSG-clean source package (`clamav 1.5.4+dfsg-0ubuntu0.22.04.1`, `Format: 3.0 (quilt)`, published `2026-09-21` in `jammy-security` / `jammy-updates`, USN-8788-1) rather than raw upstream tarballs because Ubuntu's `+dfsg` repackaging already strips non-free `libclamunrar` and matches the verified Stage 4/7 ABI and packaging baseline (`libclamav12`, `clamav-base`, `clamav-daemon`, `clamav-freshclam`).

| Artifact | Size (Bytes) | Verified SHA-256 |
| --- | ---: | --- |
| `clamav_1.5.4+dfsg.orig.tar.bz2` | `48,134,363` | `b9c10b222d3302e6eed7496de5d01a766b68f023dbae2646866d96c25f13fd7c` |
| `clamav_1.5.4+dfsg-0ubuntu0.22.04.1.debian.tar.xz` | `508,168` | `69e5adfdab189ab44b7ed04d1ad26c34183475ddabbedd9bd0b059da1b3578e9` |
| `clamav_1.5.4+dfsg-0ubuntu0.22.04.1.dsc` | `~3.1 KiB` | `d47b5139fcd190c7fc665db464380e32eecddb2e966c047ac668fefef43b0ac3` |
| `ubuntu:22.04` base OCI digest | — | `sha256:b8b6ee6aa931ecd9d0d952abc34dc0e5f7c6a30c6bb71b079fe399fde0329c02` |
| `docs/operations/experimental/patches/clamav-1.5.4-clam-3102.patch` | `3,707` | `503040ebfc3a950ca3f5303c1591bb637e5d42ccb46cb3ca63fa94dab98cf013` |
| `docs/operations/experimental/clamav-arm64-stage4-candidate.conf` (unmodified) | — | `75e2fc17058971c143580579d1d6027b5385c1724a3109e79390a272d95909a6` |
| `docs/operations/experimental/clamd-freshness-gate.sh` (unmodified) | — | `b1bff15489ece75f5baa20d6f244761492265ce52c072afdfde110461d9aade6` |

### 3.2 Upstream Patch Verification (`CLAM-3102` / PR `#1832`)

- **Upstream source**: `https://github.com/Cisco-Talos/clamav/commit/9f84fb3404b9a66c782e33f3e2b0da5e3d32af76` (merged via `cbb9caa0084c9aa55b9e42334e35770d151069bd`).
- **Target file**: `libclamav/unzip.c` (upstream `clamav-1.5.4` SHA-256 `087fcc9267a4c910571cb5ab97343da1e5b7e295184e2f28ba3004e303d31fb3`).
- **Exact functional delta**: Adds `cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxFileSize");` at the four exact `maxfilesize` truncation sites inside `unz()` (`STORED`, `DEFLATE`/`DEFLATE64`, `BZIP2`, `IMPLODE`), plus a prominent GPLv2 §2(a) modification notice header.
- **Offline dry-run verification**: Applied cleanly with `patch -p1 --fuzz=0 --dry-run` and `patch -p1 --fuzz=0` against official `clamav-1.5.4` `libclamav/unzip.c`, producing exact count `4` alert call sites and zero fuzz.
- **Build-time fail-closed guards** (`docs/operations/experimental/clamav-arm64-phase0b-candidate.Dockerfile`):
  - Mandatory `sha256sum --check --strict` on all three Ubuntu source files, the CLAM-3102 patch, `clamd.conf`, and `clamd-freshness-gate.sh`.
  - Mandatory `test ! -d /build/src/libclamunrar` and runtime `! dpkg-query -W '*unrar*'` / `! ldd /usr/sbin/clamd | grep -qi unrar`.
  - Mandatory `! grep -q 'cli_zip_parse_zip64_extra_field' /build/src/libclamav/unzip.c` proving unreviewed PR `#1845` is excluded.
  - Mandatory `QUILT_PATCH_OPTS="--fuzz=0" quilt push -a` and `test "$(grep -c ...)" -eq 4`.
  - Multi-stage runtime image strips all compilers (`gcc`, `g++`, `cmake`, `cargo`, `rustc`, `dpkg-buildpackage`, `quilt`) and preserves non-root `USER clamav` (`101:102`).
  - Optional `FROM scratch AS corresponding-source` target exports the exact pinned source package, patch, checksums, `Cargo.lock`/`Cargo.toml`, and `COPYING*` files for GPLv2 §3 archival.

### 3.3 Why Unreviewed ZIP64 PR `#1845` Is Explicitly Excluded

Upstream community PR `#1845` (`fca76728`) is **unreviewed and unmerged**, still contains a zeroed `zip_catalogue` record bug in multi-entry error paths, does not address all 8-byte ZIP64 Data Descriptor / OOXML / PDF-embedded ZIP64 edge cases, and would place DIP on an unsupported security-critical C parser fork. Until Cisco Talos merges and releases an audited ZIP64 fix, Part B structural preflight is the bounded, auditable mitigation layer for OOXML/ZIP uploads.

---

## 4. Part B — Bounded ZIP / OOXML Structural Preflight Prototype Design

Implementation: `docs/operations/experimental/clamav-phase0b-zip-preflight.mts` (zero external npm dependencies; ES2017/strict TypeScript; **NOT** wired into `src/lib/uploads/validation.ts` or `src/lib/malware/*`).

### 4.1 Security & Resource Invariants (Aligned with DIP Baseline & Stage 4 `clamd.conf`)

1. **Zero Decompression (`decompressionPerformed: false`)**: Never inflates untrusted compressed streams. Inspects strictly EOCD, ZIP64 EOCD/Locator, Central Directory File Headers (CDH), Local File Headers (LFH), TLV Extra Fields, and Data Descriptor byte geometry.
2. **Baseline-Aligned Resource Bounds (No Silent Stricter Production Ceilings)**:

| Preflight Bound | Experimental Default | Authoritative Repo / Baseline Reference | Alignment & Production Status |
| --- | --- | --- | --- |
| `maxInputBytes` | **`100 MiB`** (`104,857,600 B`) | `src/config/index.ts` `BASE_LIMITS.maxBytes` (`100 MiB`) & `src/lib/malware/index.ts` `MALWARE_SCAN_MAX_BYTES` (`100 MiB`) | **Aligned** with DIP tool baseline (does not silently tighten 100 MiB limit) |
| `maxDeclaredMemberBytes` | **`110 MiB`** (`115,343,360 B`) | `docs/operations/experimental/clamav-arm64-stage4-candidate.conf` `MaxFileSize 110M` | **Aligned** with Stage 4 `clamd.conf` |
| `maxDeclaredTotalBytes` | **`400 MiB`** (`419,430,400 B`) | `docs/operations/experimental/clamav-arm64-stage4-candidate.conf` `MaxScanSize 400M` | **Aligned** with Stage 4 `clamd.conf` |
| `maxEntries` | **`10,000`** | `docs/operations/experimental/clamav-arm64-stage4-candidate.conf` `MaxFiles 10000` | **Aligned** with Stage 4 `clamd.conf` |
| `maxExtraFieldBytes` | **`65,535 B`** | PKWARE ZIP APPNOTE `u16` header ceiling | Specification ceiling |
| `maxCentralDirectoryBytes` | **`16 MiB`** (`16,777,216 B`) | No equivalent `clamd.conf` directive (experimental header-memory cap sized at ~1.6 KiB avg per entry across 10,000 entries) | **EXPERIMENTAL ONLY — production compatibility NOT VERIFIED** (requires real corpus telemetry before production adoption) |

3. **Comprehensive ZIP64 Detection**:
   - `ZIP64_EOCD_LOCATOR_PRESENT` (`PK\x06\x07`) and `ZIP64_EOCD_RECORD_PRESENT` (`PK\x06\x06`)
   - `ZIP64_EOCD_SENTINEL` (`0xFFFF` / `0xFFFFFFFF` in standard EOCD)
   - `ZIP64_CDH_SENTINEL` / `ZIP64_LFH_SENTINEL` (`0xFFFFFFFF` sizes/offsets or `0xFFFF` disk)
   - `ZIP64_EXTRA_FIELD_PRESENT` (extra field ID `0x0001` in LFH or CDH)
   - `ZIP64_DATA_DESCRIPTOR_DETECTED` (20-byte / 24-byte 64-bit Data Descriptor when bit `0x0008` is set — detected via exact inter-member byte geometry even when `0xFFFFFFFF` sentinels and `0x0001` extra fields are omitted!)
4. **Nuanced `version_needed = 45` Policy (No Blind Rejection)**:
   - Does **NOT** blindly reject all archives with `version_needed = 45` (ZIP 4.5).
   - Valid archives with `version_needed = 45` that contain standard 32-bit headers, no `0x0001` extra field, no ZIP64 EOCD/Locator/sentinels, and (if bit `0x0008` is set) a verified 12/16-byte 32-bit Data Descriptor are **ALLOWED** with informational telemetry code `BENIGN_VERSION_NEEDED_45_NO_ZIP64_STRUCTURES`.
   - **False-positive operational tradeoff (documented explicitly)**: Some real-world streaming OOXML generators (documented in `office-open-xml-viewer#1976`, `duckdb-excel#110`, LibreOffice Bug `162944`, `apache/poi#154`) emit small DOCX/XLSX files containing `0x0001` extra fields or 24-byte ZIP64 Data Descriptors. Because ClamAV 1.5.4 fails to scan these structures safely (returning `stream: OK\0`), Phase 0B rejects them fail-closed (`ZIP64_EXTRA_FIELD_PRESENT` / `ZIP64_DATA_DESCRIPTOR_DETECTED`). Before any future production CR is approved, shadow-mode telemetry over real DIP OOXML uploads is required to measure real-world reject rates.
5. **Unsupported Compression, Encrypted OOXML & Malformed Headers**:
   - Rejects compression methods outside `ooxml-strict` (`{0, 8}` per ECMA-376) for OOXML or `clamav-supported` (`{0, 6, 8, 9, 12}`) for generic ZIP (`UNSUPPORTED_COMPRESSION_METHOD`, e.g., LZMA `14`, Zstd `93`, PPMd `98`).
   - Rejects encrypted ZIP/OOXML (`flags & 0x0001`, `0x0040`, `0x2000`, WinZip AES method `99` / extra `0x9901`) while preserving `AlertEncrypted no` in `clamd.conf` so password-protected PDFs for `unlock-pdf` continue to function.
   - Rejects LFH/CDH mismatches, missing/ambiguous EOCD, multi-disk archives, malformed TLV extra fields, overlapping member ranges, unreferenced preambles, and missing `[Content_Types].xml` on declared OOXML inputs.
   - Decodes UTF-8 filenames (`flags & 0x0800`) cleanly so Arabic/Unicode member names are preserved without corruption.

### 4.2 Explicit Residual Risks & Architectural Separation of Duties

| Residual Risk / Boundary | Why It Exists | Disposition |
| --- | --- | --- |
| **PDF-Embedded ZIP64 (`upstream ClamAV #1888`)** | OOXML-only preflight returns `ALLOW_WITH_RESIDUAL_RISK_WARNING` (`OOXML_PREFLIGHT_DOES_NOT_INSPECT_PDF_EMBEDDED_ZIP64`) for PDFs so PDF processing and `unlock-pdf` are not broken. It does **NOT** parse PDF `/EmbeddedFiles` object streams or detect ZIP64 attachments inside PDFs. | **OPEN RESIDUAL RISK (`R1_pdf_embedded_zip64_residual_risk`)** — Explicitly flagged (`pdf_embedded_zip64_remediated: false`). Even if all scoped Phase 0B checks pass, overall remediation status remains `PARTIAL_RESIDUAL_RISKS_OPEN`. Requires upstream ClamAV ZIP64 fix or a separate bounded PDF-attachment inspection design before closing the Security Gate for PDF-embedded archive threats. |
| **Compressed Nested Archives Inside ZIP/OOXML** | Because Part B preflight strictly performs **zero decompression** (`decompressionPerformed: false`), it **cannot** inspect inside any compressed nested archive (e.g., a DEFLATE-compressed ZIP64 archive stored inside a valid outer ZIP32 or OOXML container, regardless of filename extension). Known archive-extension nested members emit `COMPRESSED_NESTED_ARCHIVE_NOT_INSPECTED_RESIDUAL_RISK` warning; arbitrary-extension compressed nested archives cannot be detected statically without decompression. | **OPEN RESIDUAL RISK (`R2_compressed_nested_zip64_inside_zip32_residual_risk`)** — Explicitly flagged (`compressed_nested_archives_inspected_by_preflight: false`). Classified as `RESIDUAL_RISK_OPEN` (never counted as a security `PASS`). Requires upstream ClamAV ZIP64 support (`#1527`/`#1928`) or isolated bounded sandbox decompression in a separate CR. |
| **Forged-Size ZIP32 Archives** | Because Part B preflight strictly performs **zero decompression**, an archive whose LFH/CDH falsely declares `uncompressed_size = 100` while inflating to `65,536` bytes intentionally passes Part B preflight (`A7_forged_size_header_zip32_maxfilesize`). | **MITIGATED BY PART A (`CLAM-3102`)** — Patched `clamd` counts actual inflated bytes during decompression and emits `Heuristics.Limits.Exceeded.MaxFileSize`. Proves Part A and Part B are complementary, not interchangeable. |

---

## 5. GPLv2 Licensing, SBOM, Transitive Licenses & Distribution Governance

> **Licensing Gate Status: OPEN** — No binary image built from this Dockerfile may be distributed or published to GHCR until legal review signs off on every requirement below.

1. **ClamAV Primary License**: `GPL-2.0-only` (with Cisco OpenSSL linking exception, see upstream `COPYING.txt` and `COPYING/`).
2. **GPLv2 §2(a) Prominent Modification Notices**:
   - Modifying `libclamav/unzip.c` creates a modified GPLv2 work.
   - Satisfied in source by: (a) prominent dated modification header inside `libclamav/unzip.c`, (b) DEP-3 patch metadata in `docs/operations/experimental/patches/clamav-1.5.4-clam-3102.patch`, and (c) explicit `debian/changelog` entry (`1.5.4+dfsg-0ubuntu0.22.04.1+dipphase0b1`).
3. **GPLv2 §3 Complete Corresponding Source**:
   - **Internal-only execution** (running the container solely inside DIP's own infrastructure without conveying binary images to external parties) does not trigger GPLv2 §3 distribution to third parties, **provided** the image is never published to a public registry or delivered to external customers/contractors.
   - **Any binary/image distribution** (including publishing to any public registry, sharing container images with third parties, or distributing on-prem appliances) **strictly triggers GPLv2 §3**: DIP must accompany or make available the Complete Corresponding Source for ClamAV **and** all GPL/LGPL Ubuntu packages in the image (`orig.tar.bz2`, `debian.tar.xz`, `.dsc`, `clamav-1.5.4-clam-3102.patch`, build scripts/Dockerfile, and Ubuntu package source mirrors).
   - The Dockerfile's `corresponding-source` stage (`docker buildx build --target corresponding-source`) packages the exact ClamAV source artifacts and provenance deterministically for compliance archival.
4. **Rust Staticlib (`libclamav_rust`) & Transitive Ubuntu Licenses**:
   - ClamAV 1.5.4 links `libclamav_rust` statically into `libclamav12`, embedding numerous crates (MIT, Apache-2.0, BSD-2/3-Clause, MPL-2.0, Unicode-3.0, ISC, Zlib, etc.).
   - Notice: Apache-2.0 is compatible with GPLv3, whereas GPLv2-only compatibility with statically linked Apache-2.0 crates requires explicit legal verification under Cisco Talos's upstream license declarations (`COPYING.txt`) and DIP's `docs/license-registry.md`.
   - Runtime container copies `libclamav_rust/Cargo.lock`, `Cargo.toml`, `COPYING*`, `dpkg-manifest.txt`, and `/usr/share/doc/*/copyright` into `/usr/share/doc/dip-phase0b/` so an SPDX 2.3 / CycloneDX 1.5 SBOM can be generated and audited before closing the Licensing Gate.
5. **Non-Free UnRAR Exclusion**:
   - Upstream `libclamunrar` carries a non-free RAR license incompatible with GPLv2 distribution and DIP policy.
   - Ubuntu's `+dfsg` source strips `libclamunrar`; the Dockerfile and workflow enforce fail-closed assertions verifying zero `libclamunrar` source directories, zero `*unrar*.deb` packages, zero installed `*unrar*` packages, and zero `ldd` linkage to `unrar`.

---

## 6. Complete Live Test Matrix, Pre-Scan Gates & Verdict Integrity (Prepared — NOT YET EXECUTED LIVE)

All 26 deterministic fixtures are generated by `scripts/experiments/clamav-phase0b-evidence.py` and executed sequentially across **three isolated scanner profiles** by `.github/workflows/clamav-phase0b-evidence.yml`:

| Profile | Key Effective Limits | Purpose | Pre-Scan Fail-Closed Gate |
| --- | --- | --- | --- |
| `candidate` | Unmodified `clamav-arm64-stage4-candidate.conf`: `StreamMaxLength=110M`, `MaxFileSize=110M`, `MaxScanSize=400M`, `MaxThreads=12`, `AlertExceedsMax=yes` | Genuine bilingual Office/PDF controls, EICAR ZIP32, observational raw-`clamd` ZIP64, open residual-risk probes (`R1`, `R2`) | Full **22-key `clamconf`** validation + `zPING` + `zVERSION` (`1.5.4`) |
| `reduced_alert_yes` | Isolated `CLAM-3102` profile (matching Phase 0A): `StreamMaxLength=1M`, `MaxFileSize=16K`, **`MaxScanSize=512K`**, `MaxThreads=4`, `AlertExceedsMax=yes` (all other 17 baseline keys preserved verbatim) | Isolates `MaxFileSize=16K` without `MaxScanSize` confounding 64 KiB expanded ZIP inputs (`A1`–`A9`) | Full **22-key `clamconf`** validation + `zPING` + `zVERSION` (`1.5.4`) |
| `reduced_alert_no` | Same `1M / 16K / 512K / 4` isolated limits with `AlertExceedsMax=no` | Observational comparison controls (`A4`, `A7`) confirming `AlertExceedsMax` wiring | Full **22-key `clamconf`** validation + `zPING` + `zVERSION` (`1.5.4`) |

### 6.0 Genuine Fixture Authenticity & Verdict Taxonomy Rules

- **Genuine Office/PDF/Attachment Authenticity (`verify-fixtures`)**:
  - `B9`, `B10`, `B11`, `B12` are complete ECMA-376 OPC packages containing **both English and Arabic UTF-8 content** (`_rels/.rels`, `[Content_Types].xml`, WordprocessingML/SpreadsheetML/PresentationML XML parts). In the live workflow, ephemeral runner-only LibreOffice (`soffice --headless --convert-to pdf`) + `qpdf --check` + `pdftotext` verify real open/convert compatibility and English/Arabic text preservation.
  - `B14` is encrypted with real `qpdf --password-mode=unicode --encrypt ... 256` (AES-256/R6) and verified via `--show-encryption`, valid-password `--decrypt` + `--check`, and wrong-password exit-code-2 rejection.
  - `R1` embeds `B1` via a genuine ISO 32000-1 `/Catalog -> /Names << /EmbeddedFiles >> -> /Filespec -> /EF -> /EmbeddedFile` attachment tree, verified via `qpdf --check` and `pdfdetach -list`/`-save` SHA-256 parity.
  - **Offline honesty rule**: When `soffice`, `qpdf`, or `pdfdetach` are absent offline, fixture tool verification is recorded as **`NOT VERIFIED`** (never `PASS`), and `assemble-report` / `--require-tool-verification` fail closed.
- **Strict Verdict Taxonomy**:
  - Unexpected `CLEAN` on any required security check (`EICAR_FOUND`, `MAXFILESIZE_FOUND`) is classified explicitly as **`SECURITY FAILURE`**.
  - Wrong limit alert (e.g., `MaxScanSize` firing when `MaxFileSize` was required) is classified as **`FAIL`**.
  - `OBSERVATIONAL_CONTROL_OK` (`AlertExceedsMax=no`), `OBSERVATIONAL_RECORD_ONLY` (direct raw `clamd` scans of `B1`/`B2`/`B3` bypassing preflight), and `RESIDUAL_RISK_OPEN` (`R1`, `R2`) are **NEVER** counted as security passes.
  - Even when all scoped required checks pass, `overall_remediation_status` is explicitly **`PARTIAL_RESIDUAL_RISKS_OPEN`** with `pdf_embedded_zip64_remediated: false` and `compressed_nested_archives_inspected_by_preflight: false`.

### 6.1 Part A — CLAM-3102 Live `clamd` Matrix (9 Cases under `MaxFileSize=16K`, `MaxScanSize=512K`)

| ID | Input Description | Expected Preflight | Expected `reduced_alert_yes` | Expected `reduced_alert_no` |
| --- | --- | --- | --- | --- |
| `A1_eicar_zip32_control` | EICAR in normal ZIP32 | `ALLOW` | `EICAR_FOUND` (also `candidate`) | — |
| `A2_exact_boundary_zip32_eq_maxfilesize` | DEFLATE ZIP32 expanding to **exact** `16,384 B` (`== MaxFileSize`) | `ALLOW` | `CLEAN` (`stream: OK\0`) | — |
| `A3_over_boundary_plus1_zip32_deflate` | DEFLATE ZIP32 expanding to `16,385 B` (`MaxFileSize + 1`) | `ALLOW` | `Heuristics.Limits.Exceeded.MaxFileSize` | — |
| `A4_phase0a_e1_repro_zip32_64k_deflate` | Phase 0A `E1_yes` reproduction (`65,536 B` DEFLATE ZIP32, `<< 512K MaxScanSize`) | `ALLOW` | `Heuristics.Limits.Exceeded.MaxFileSize` | `OBSERVATIONAL_CONTROL_OK` (`CLEAN`) |
| `A5_over_boundary_zip32_stored` | STORED (method 0) `20,480 B` ZIP32 (`unz()` line 166) | `ALLOW` | `Heuristics.Limits.Exceeded.MaxFileSize` | — |
| `A6_over_boundary_zip32_bzip2` | BZIP2 (method 12) `32,768 B` ZIP32 (`unz()` line 274) | `ALLOW` | `Heuristics.Limits.Exceeded.MaxFileSize` | — |
| `A7_forged_size_header_zip32_maxfilesize` | **Forged-size control**: LFH/CDH lie `usize=100`, DEFLATE inflates to `65,536 B` | `ALLOW` (zero-decomp boundary) | `Heuristics.Limits.Exceeded.MaxFileSize` | `OBSERVATIONAL_CONTROL_OK` (`CLEAN`) |
| `A8_eicar_hidden_past_maxfilesize_zip32` | EICAR placed after byte `20,480` inside DEFLATE ZIP32 | `ALLOW` | `Heuristics.Limits.Exceeded.MaxFileSize` | — |
| `A9_raw_non_zip_64k_maxfilesize_control` | Raw non-ZIP `65,536 B` payload | `REJECT` (`MALFORMED_NOT_ZIP_MAGIC`) | `Heuristics.Limits.Exceeded.MaxFileSize` | — |

### 6.2 Part B — Bounded ZIP/OOXML Preflight & Genuine Bilingual Controls Matrix (15 Cases)

| ID | Input Description | Expected Preflight Action | Required Reason / Telemetry Code | Live `candidate` Profile Role |
| --- | --- | --- | --- | --- |
| `B1_zip64_eicar_lfh_python312` | Phase 0A `D_eicar_zip64` repro (`0xFFFFFFFF` LFH + `0x0001`) | `REJECT` | `ZIP64_LFH_SENTINEL` | `OBSERVATIONAL_RECORD_ONLY` (not counted as PASS) |
| `B1b_zip64_extra_field_without_sentinels` | `0x0001` extra field without `0xFFFFFFFF` sentinels | `REJECT` | `ZIP64_EXTRA_FIELD_PRESENT` | — |
| `B2_zip64_eicar_full_eocd_cdh` | Full ZIP64 EOCD + Locator + CDH/LFH sentinels + EICAR | `REJECT` | `ZIP64_EOCD_LOCATOR_PRESENT` | `OBSERVATIONAL_RECORD_ONLY` (not counted as PASS) |
| `B3_zip64_data_descriptor_no_sentinels` | `version_needed=45`, bit `0x0008`, 24B 64-bit DD, no sentinels | `REJECT` | `ZIP64_DATA_DESCRIPTOR_DETECTED` | `OBSERVATIONAL_RECORD_ONLY` (not counted as PASS) |
| `B4_unsupported_method_lzma_14` | ZIP member compressed with LZMA (`method=14`) | `REJECT` | `UNSUPPORTED_COMPRESSION_METHOD` | — |
| `B5_unsupported_method_ppmd_98` | ZIP member compressed with PPMd (`method=98`) | `REJECT` | `UNSUPPORTED_COMPRESSION_METHOD` | — |
| `B6_encrypted_ooxml_traditional` | OOXML with PKWARE encryption bit `0x0001` | `REJECT` | `ENCRYPTED_MEMBER_TRADITIONAL` | — |
| `B7_encrypted_ooxml_winzip_aes` | OOXML with WinZip AES (`method=99` / `0x9901`) | `REJECT` | `ENCRYPTED_MEMBER_AES` | — |
| `B8_malformed_lfh_cdh_mismatch` | OOXML with LFH/CDH compression method mismatch | `REJECT` | `MALFORMED_LFH_CDH_MISMATCH` | — |
| `B9_benign_version_needed_45_docx` | Genuine bilingual (EN/AR) OPC DOCX with `version_needed=45`, 32-bit headers | `ALLOW` | `BENIGN_VERSION_NEEDED_45_NO_ZIP64_STRUCTURES` | `CLEAN` + LibreOffice verification |
| `B10_valid_docx_control` | Genuine bilingual (EN/AR) ECMA-376 OPC DOCX | `ALLOW` | — | `CLEAN` + LibreOffice verification |
| `B11_valid_xlsx_control` | Genuine bilingual (EN/AR) ECMA-376 OPC XLSX | `ALLOW` | — | `CLEAN` + LibreOffice verification |
| `B12_valid_pptx_control` | Genuine bilingual (EN/AR) ECMA-376 OPC PPTX | `ALLOW` | — | `CLEAN` + LibreOffice verification |
| `B13_valid_pdf_control` | Valid ISO 32000-1 PDF (EN body + EN/AR UTF-16BE metadata) | `ALLOW_WITH_RESIDUAL_RISK_WARNING` | `OOXML_PREFLIGHT_DOES_NOT_INSPECT_PDF_EMBEDDED_ZIP64` | `CLEAN` + `qpdf --check` |
| `B14_encrypted_pdf_unlock_pdf_control` | Genuinely AES-256/R6 encrypted PDF via `qpdf` (`unlock-pdf` control) | `ALLOW_WITH_RESIDUAL_RISK_WARNING` | `OOXML_PREFLIGHT_DOES_NOT_INSPECT_PDF_EMBEDDED_ZIP64` | `CLEAN` + `qpdf` decrypt & wrong-pw check |

### 6.3 Open Residual Risk Probes (2 Cases — NEVER Counted as PASS)

| ID | Input Description | Expected Preflight Action | Live `candidate` Classification |
| --- | --- | --- | --- |
| `R1_pdf_embedded_zip64_residual_risk` | ISO 32000-1 PDF with structurally referenced `/Names -> /EmbeddedFiles -> /Filespec -> /EmbeddedFile` ZIP64 EICAR attachment (`#1888`) | `ALLOW_WITH_RESIDUAL_RISK_WARNING` (`OOXML_PREFLIGHT_DOES_NOT_INSPECT_PDF_EMBEDDED_ZIP64`) | **`RESIDUAL_RISK_OPEN`** (verified extractable via `pdfdetach`; never counted as `PASS`) |
| `R2_compressed_nested_zip64_inside_zip32_residual_risk` | Valid outer ZIP32 containing DEFLATE-compressed inner ZIP64 EICAR archive | `ALLOW_WITH_RESIDUAL_RISK_WARNING` (`COMPRESSED_NESTED_ARCHIVE_NOT_INSPECTED_RESIDUAL_RISK`) | **`RESIDUAL_RISK_OPEN`** (proves zero-decompression preflight cannot inspect compressed nested archives; never counted as `PASS`) |

---

## 7. Risk Register

| Risk ID | Severity | Description | Mitigation / Exit Condition |
| --- | --- | --- | --- |
| `R-P0B-01` | High | PDF-embedded ZIP64 bypass (`#1888`) remains unmitigated by OOXML-only preflight | Explicitly flagged (`RESIDUAL_RISK_OPEN`, `pdf_embedded_zip64_remediated: false`); track upstream ClamAV fix or design bounded PDF attachment preflight in separate CR |
| `R-P0B-02` | High | Compressed nested archives inside ZIP/OOXML cannot be inspected by zero-decompression preflight (`R2`) | Explicitly flagged (`RESIDUAL_RISK_OPEN`, `compressed_nested_archives_inspected_by_preflight: false`); requires upstream ClamAV ZIP64 fix or isolated sandboxed decompression in a separate CR |
| `R-P0B-03` | High | GPLv2 §3 / Rust staticlib transitive license noncompliance if image is distributed before legal review | Zero GHCR push in Phase 0B; `corresponding-source` stage + `/usr/share/doc/dip-phase0b/` artifacts prepared for legal/SBOM review; Licensing Gate remains OPEN |
| `R-P0B-04` | Medium | Custom `CLAM-3102` quilt patch drift if Ubuntu Jammy issues subsequent ClamAV security updates | Pinned source SHA-256 fails closed on drift; mandatory de-fork trigger under `CLAMAV-CR-P01` once Ubuntu ships official `CLAM-3102` fix |
| `R-P0B-05` | Medium | Streaming OOXML writers emitting `0x0001` extra fields or 64-bit Data Descriptors rejected by Part B preflight; experimental `maxCentralDirectoryBytes = 16 MiB` ceiling not verified on production corpora | Benign `version_needed=45` without ZIP64 structures is allowed; `maxCentralDirectoryBytes` explicitly marked `EXPERIMENTAL ONLY — production compatibility NOT VERIFIED`; require shadow-mode telemetry before any future production CR enables blocking |
| `R-P0B-06` | Low | `ubuntu-24.04-arm` native build time or Ubuntu `jammy-security` source index rollover | Dockerfile resolves `Build-Depends` directly from SHA-256-verified extracted `debian/control` with Launchpad archive fallback; 60-minute job timeout |

---

## 8. Operator Execution Preconditions (DO NOT RUN BEFORE MERGE & AUTHORIZATION)

1. Review Draft PR `#14` and obtain explicit human approval before merging to `main`.
2. Only **after** merge to `main`, an authorized maintainer may manually dispatch `.github/workflows/clamav-phase0b-evidence.yml` on branch `main` with confirmation string `run-phase0b-clamav-remediation-poc`.
3. Inspect the uploaded evidence artifact (`phase0b-evidence-summary.md`, `phase0b-evidence.json`, `fixture-verification.json`, `dpkg-manifest.txt`, `clamconf-candidate.txt`, `clamconf-reduced-yes.txt`, `clamconf-reduced-no.txt`).
4. Even if all scoped live checks pass (`overall_remediation_status = PARTIAL_RESIDUAL_RISKS_OPEN`), **Security Gate** and **Licensing Gate** remain **OPEN** until formal approval of `CLAMAV-CR-P01`, `CLAMAV-CR-P02`, and `CLAMAV-CR-P03`, SBOM/legal sign-off, residual-risk disposition for `R1`/`R2`, and separate audited production integration.
