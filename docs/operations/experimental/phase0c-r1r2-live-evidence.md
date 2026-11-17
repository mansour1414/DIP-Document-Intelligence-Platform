# DIP Phase 0C R1/R2 Live Evidence Harness — Experimental Design

**Status:** Experimental harness only. This document and its implementation do not authorize a run, approve an architecture, close a gate, or change production. The live workflow is manual-only and must not be dispatched without separate owner authorization.

## Scope and preserved decisions

The harness evaluates the existing bounded Phase 0C inspector against a real, locally built Phase 0B ARM64 ClamAV candidate using only synthetic fixtures and harmless EICAR controls. It is not production integration. It does not change the approved pre-storage sequence:

`validateUpload → requireCleanUpload → storage.put`

A post-storage worker scan does not meet that requirement. Scanner placement remains undecided and is not changed here. Security Gate and Licensing Gate remain **OPEN**; Stage 7 remains **NOT ACCEPTED**; R1/R2 remain **OPEN**; all relevant Change Requests remain **PROPOSED — NOT APPROVED**.

## Runtime topology and limits

The manual workflow builds the existing Phase 0B ClamAV candidate locally and an experimental Python client image. It starts exactly two persistent runtime containers on one Docker `--internal` network: `clamd` and the client. Neither publishes ports; the client can reach only the clamd service and its read-only fixture mount. The client gets no Docker socket, signature database, production document, secret, or writable source mount. The ClamAV database and configuration are mounted read-only. Database update and independent fixture verification happen before this network is created.

Both containers run non-root, with read-only root filesystems, all capabilities dropped, `no-new-privileges`, and bounded tmpfs. Docker CPU, memory, swap, and PID limits are set on each container. GNU `timeout` and `RLIMIT_CPU` (`--ulimit cpu`) provide actual per-container process/lifetime limits; workflow timeout and cleanup are additional outer bounds.

| Resource | ClamAV service | Python client | Scope / interpretation |
| --- | ---: | ---: | --- |
| CPU | 2 CPUs | 1 CPU | Separate Docker CPU cgroups; not a shared CPU budget. |
| Memory / swap | 3 GiB / 3 GiB | 512 MiB / 512 MiB | Separate hard container limits. |
| PIDs | 128 | 64 | Separate Docker PID limits. |
| Per-container wall lifetime | 1,800 s | 1,200 s | `timeout` kills the respective service/process. The client timer is the end-to-end test deadline. |
| CPU time limit | 1,800 s | 120 s | Per-container/process `RLIMIT_CPU`; the client CPU limit covers Python, not clamd. |
| tmpfs | `/tmp` 256 MiB; `/run/clamav` and `/var/log/clamav` 32 MiB each | `/tmp` 16 MiB | `noexec,nosuid,nodev`; no extraction to disk. |
| Workflow outer bound | 60 minutes | 60 minutes | GitHub job limit; cleanup runs under `always()`. |

One monotonic client deadline of **20 minutes** starts before fixture-manifest and fixture reads and covers fixture reading, original-container scans, structural extraction, transfer, response parsing, and cancellation. Each case has a maximum **90-second** sub-deadline. The offline PoC's 3-second CPU / 5-second wall-clock settings are not asserted sufficient for live work; live mode uses 15 seconds of client-process CPU accounting per case, while its actual process CPU and wall lifetime are independently bounded by the client container. Clamd CPU and memory remain separately bounded by its own cgroup. There is no shared cgroup and no claim that client CPU accounting includes clamd CPU.

The input/inspection caps remain: 4 MiB input, 16 MiB cumulative expanded bytes, 2 MiB per member, 256 entries, depth 3 (root 0), 8 MiB re-parse buffer, and 64 KiB transfer chunks. Live INSTREAM traffic is additionally capped at 256 MiB over the entire client run. Timeouts, malformed replies, protocol errors, exceeded limits, and interrupted scans fail closed; the client closes the one-shot INSTREAM connection to cancel an incomplete request.

## Evidence semantics and matrix

The machine-readable `phase0c-live-evidence.json` keeps separate:

- `TEST_CASE_RESULT`: `PASS`, `FAIL`, or `NOT_VERIFIED`.
- `SECURITY_COVERAGE_STATUS`: `INSPECTED`, `REJECTED`, `UNSUPPORTED`, or `NOT_VERIFIED`.
- The full original input's ClamAV result, always labelled **OBSERVATIONAL_ONLY**.
- Each structurally discovered member/attachment's INSTREAM result, labelled as directly tested evidence.

A clean original-container result never proves complete nested inspection. A case may pass its experiment expectation while Security Gate and R1/R2 remain open. The offline inspector's `derive_conclusion` still receives `clamav_verified=False`; this harness does not promote its offline `COMPLETE_SAFE_SCAN` conclusion.

The live set reuses the Phase 0C ZIP/PDF cases and Phase 0B generated, tool-verified fixtures. It includes:

- Direct EICAR bytes checked against SHA-256 `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`.
- Referenced PDF ZIP64 EICAR attachment and compressed ZIP32→ZIP64 and nested ZIP32 controls.
- Standards-compliant ZIP32/ZIP64 data descriptors and CPython non-seekable `force_zip64` writer cases; valid archive controls are cross-read with Python `zipfile`, independent of the Phase 0C custom reader.
- Bilingual DOCX/XLSX/PPTX and PDF controls generated and verified using Phase 0B's LibreOffice, qpdf, pdfdetach, and Poppler utilities. The independent Phase 0B R1 attachment verification compares the extracted attachment hash; an independent ZIP reader checks the nested R2 EICAR payload.
- Truncated DEFLATE, malformed PDFs, CRC/size conflicts, encrypted archive-member flags, unsupported compression, depth/entry/expansion/member/input/memory limits, and PDF coverage gaps.
- A genuine AES-256/R6 encrypted PDF control. Its password is used only transiently by the existing Phase 0B fixture verifier and is never passed to the client or retained. This harness classifies encrypted content `UNSUPPORTED`/`NOT_VERIFIED`; it does not perform a post-unlock scan.

The machine-readable ledger records fixture hashes and provenance, independent verification, paths/depth/actual bytes, budget and limit events, original and extracted scan results, ClamAV engine/signature versions, local image IDs/config hash, test result, and the verified cleanup status. No synthetic `/Encrypt` marker is represented as independently verified encryption. Arbitrary PDF streams, Object Streams, unreferenced streams, encrypted content, incremental revisions, and unsupported archive methods remain explicit gaps; they cannot produce a complete-coverage claim.

### Result rules

- EICAR controls pass only on a correctly framed `FOUND` result whose signature identifies EICAR. A clean response is a security failure.
- Benign controls pass only on correctly framed `CLEAN` responses for the original input and all inspected payloads.
- Malformed/unsupported/budget cases pass only when the expected fail-closed status and reason are recorded; they are not counted as inspected content.
- Missing/stale fixture verification, unexpected tool/version/database provenance, scanner `ERROR`, malformed framing, premature EOF, timeout, cancellation, or absent result is `NOT_VERIFIED` or `FAIL`, never PASS.
- Original-container results for R1/R2 are observational regardless of their verdict.

## Evidence retention and cleanup

The workflow keeps only JSON/text metadata, manifests, hashes, tool/version data, effective `clamconf`, bounded scan results, and cleanup verification. It does not upload fixture binaries, production documents, passwords, signature databases, images, raw input bytes, or raw ClamAV payloads. Total artifacts are capped at 5 MiB and retained 30 days.

Evidence is finalized only after the cleanup step has attempted and verified removal of both containers, both local image tags, the private network, and the fixed scratch directory. Cleanup writes `cleanup-status.json`; the finalizer merges that actual result into the ledger and enforces the evidence limit. Any cleanup failure fails the job even if an artifact is uploaded for diagnosis.

## Client image and licensing

`clamav-phase0c-client.Dockerfile` is experimental-only. It uses the immutable Ubuntu 22.04 base digest already used by the Phase 0B candidate, installs only Ubuntu's `python3-minimal` for standard-library execution, records the resolved dpkg manifest and available copyright notices, and runs as numeric UID/GID 10001. The workflow records the built local image ID and package manifest. The image is not published, shipped, or added to application dependencies. APT package resolution occurs at build time; the exact resulting package inventory is evidence, not a promise of byte-reproducible future builds.

Licensing considerations remain open and are not approvals:

- ClamAV is a separate GPL-2.0-only scanner process; the candidate includes the Phase 0B CLAM-3102 modification. Any distribution requires the applicable modification notices, Corresponding Source, third-party notices, Ubuntu/Rust-crate SBOM, and legal review identified in Phase 0B. The experiment does not publish or distribute the image.
- The client uses Python's PSF license and Ubuntu package components; their package manifest and copyright files are retained only in the bounded artifact for audit. No Python package is added to DIP production.
- Fixture authenticity tools are transient runner subprocesses: qpdf (Apache-2.0), LibreOffice (MPL-2.0 and bundled notices), and Poppler utilities (their package-specific license/notice inventory must be captured and reviewed). They are not copied into the client or production image.
- EICAR is a harmless antivirus test signature. No additional application dependency is introduced.

## Authorization and operating restriction

The workflow is `workflow_dispatch` only, checks the intended repository/default branch and a unique confirmation string, has read-only GitHub permissions, and uses immutable action SHAs. Its existence is not authorization to dispatch it. No live execution, deployment, production change, Change Request approval, Security Gate closure, Licensing Gate closure, or Stage 7 acceptance is implied.
