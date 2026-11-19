# ClamAV Phase 0C — isolated live evidence register

**Evidence date: 2026-11-19 (Asia/Riyadh); run and source review: 2026-11-18 UTC.**
This metadata-only, append-only record covers one experiment on synthetic inputs. In both `R1-LIVE-01` and
`R2-LIVE-01`, the independent artifact auditor observed a `CLEAN` original container and an
`INFECTED` extracted EICAR payload. **The original scans did not establish nested-content safety.**

**Disposition unchanged:** Security Gate **OPEN**; Licensing Gate **OPEN**; Stage 7 **NOT ACCEPTED**;
R1/R2 **OPEN**. `CLAMAV-CR-P01`, `CLAMAV-CR-P02`, `CLAMAV-CR-P03`, `CLAMAV-CR-R1` and
`CLAMAV-CR-R2` remain **PROPOSED — NOT APPROVED**.

## Run and archive identity

| Item | Verified against GitHub metadata in this review |
| --- | --- |
| Repository and source | `mansour1414/DIP-Document-Intelligence-Platform`, `main` at [commit `64a88a73283e6ffbccc4ccde4f94fae6d0754f56`][commit] |
| Workflow and run | `ClamAV Phase 0C Isolated Live Evidence (Experimental)`; [run 44396720677][run], number 4, attempt 1, `workflow_dispatch`, `completed` / `success` |
| Job | [135128502896][job], `ubuntu-24.04-arm`, `success`. Run started 2026-11-18 20:59:15 UTC; job finished 21:07:15 UTC. |
| Artifact | [14471197885][artifact], `clamav-phase0c-live-evidence-44396720677-64a88a73283e6ffbccc4ccde4f94fae6d0754f56`; artifact metadata identifies the same run and head SHA. |
| Original ZIP | 69,026 bytes; SHA-256 `f76512317e4a9d8b3cf4162ea1f1e3d208654c69c2c5900380a99a739c486e66` |
| Retention | 30 days in the workflow; GitHub expiry **2026-12-18 21:07:09 UTC**. |

**Custody: preservation pending confirmation.** The repository owner (`mansour1414`) or a formally
authorized custodian must preserve the **original ZIP, without repacking**, in restricted, long-lived
storage before expiry. Compare its byte count and SHA-256 with the GitHub record on receipt and after
storage. Record the custodian, UTC time, restricted storage reference and checksum receipt in the
custody record. No long-term copy or custody receipt was supplied or created by this review. Neither
this register nor the sanitized audit substitutes for that ZIP.

## Sources and verification boundary

- **Authority:** The approved DIP MASTER BASELINE and approved decisions govern production. The
  [Phase 0B remediation design][0b], [Phase 0C offline PoC and baseline review][offline] and
  [Phase 0C live harness design][design] define the technical scope. The committed [ingress sequence][ingress]
  is `validateUpload → requireCleanUpload → storage.put`; a post-storage worker scan is not a substitute.
  No standalone MASTER BASELINE or formal hierarchy text was supplied with the audit or found in the run tree.
  The five G0 records belong to the **2026-09-28 Structural Grayscale freeze**, not ClamAV. None is
  used as ClamAV evidence. This entry supplements the specialist designs; it revises no prior record.
- **Independent observations:** The supplied *DIP Phase 0C Independent Artifact Audit (Sanitized)*,
  `DIP_Phase0C_Artifact_Audit_2026-11-19_SANITIZED.md` (Asia/Riyadh; attachment SHA-256
  `6356a35b239e6fa541b50d5245f5c6c0eb9ef52d013644e6ab6b0d6fe7de103d`), reports direct read-only
  inspection of the downloaded ZIP. The auditor counted **22 members**, checked ZIP CRC integrity
  (**PASS**) and computed the archive digest shown above. The auditor read the ledger; these are
  observations, not expected values inferred from a green job.
- **This review:** Queried GitHub run, job and artifact records; matched their identifiers, source,
  size, digest and expiry to the audit. Hashed the attachment, recounted its sanitized case rows and
  compared all 39 IDs and structural statuses to the [committed case matrix][matrix]. The original
  ZIP download redirected to object storage unreachable from this environment. We did not recompute
  the ZIP digest or CRC, or inspect the raw ledger, archived manifest, image IDs or logs.
  Source-file checks below use Git blobs, not a rebuild. No experiment or fixture generator was run.

## Results from the independent audit

Ledger: `phase0c-live-evidence.json`, schema `phase0c-live-evidence-v1`. The four fields answer
*different questions*. These four distributions were recounted from the sanitized rows. Reply
framing, signature freshness and the offline-reason count come from the audit, not that recount.

| Ledger field | Unit and measured distribution | Meaning |
| --- | --- | --- |
| `TEST_CASE_RESULT` | 39 distinct cases; 39 `PASS` | Did the experimental assertion hold? An expected refusal or documented coverage gap can pass. |
| `SECURITY_COVERAGE_STATUS` | 39 cases: 18 `INSPECTED`, 13 `REJECTED`, 4 `UNSUPPORTED`, 4 `NOT_VERIFIED` | Structural outcome for the targeted objects. `INSPECTED` does not assert exhaustive inspection of the file. |
| `ORIGINAL_CONTAINER_SCAN_RESULT` | 39 whole-input replies: 27 `CLEAN`, 12 `INFECTED` | One direct scan per case, including the raw positive control. For R1/R2 it is `OBSERVATIONAL_ONLY`. |
| `EXTRACTED_PAYLOAD_SCAN_RESULT` | 53 payload replies: 37 `CLEAN`, 16 `INFECTED` | Zero or more replies per case, for discovered payloads only. Zero replies do not mean clean contents. |

- **`R1-LIVE-01`:** The original PDF with a referenced ZIP64 attachment was `CLEAN`. Of four
  extracted results, two were `CLEAN` and two `INFECTED`; the auditor identified `Eicar-Test-Signature`
  on extracted EICAR.
- **`R2-LIVE-01`:** The original ZIP32 containing a DEFLATE-compressed ZIP64 was `CLEAN`. Of two
  extracted results, one was `CLEAN` and one `INFECTED` (`Eicar-Test-Signature`).

Both cases were `PASS` / `INSPECTED` for their targets. Neither establishes full R1 or R2 coverage.
In the other coverage categories, 21 cases passed precisely because the expected outcome was
`REJECTED`, `UNSUPPORTED` or `NOT_VERIFIED`, not because their contents were safe.

<details>
<summary>Sanitized case rows used for the recount (39 cases; extracted columns count replies)</summary>

| Case ID | Test | Structural coverage | Original scan | Extracted CLEAN | Extracted INFECTED |
| --- | --- | --- | --- | ---: | ---: |
| `CTRL-EICAR-RAW` | PASS | INSPECTED | INFECTED | 0 | 0 |
| `R1-06` | PASS | NOT_VERIFIED | INFECTED | 0 | 0 |
| `R1-07` | PASS | UNSUPPORTED | CLEAN | 0 | 0 |
| `R1-08` | PASS | NOT_VERIFIED | CLEAN | 2 | 0 |
| `R1-09` | PASS | NOT_VERIFIED | CLEAN | 2 | 0 |
| `R1-10` | PASS | REJECTED | CLEAN | 0 | 0 |
| `R1-12` | PASS | UNSUPPORTED | INFECTED | 0 | 0 |
| `R1-13` | PASS | REJECTED | CLEAN | 0 | 0 |
| `R2-01` | PASS | INSPECTED | INFECTED | 0 | 2 |
| `R2-02` | PASS | INSPECTED | CLEAN | 1 | 1 |
| `R2-03` | PASS | INSPECTED | INFECTED | 0 | 2 |
| `R2-04` | PASS | INSPECTED | INFECTED | 0 | 2 |
| `R2-05` | PASS | REJECTED | INFECTED | 0 | 3 |
| `R2-06` | PASS | REJECTED | INFECTED | 0 | 0 |
| `R2-07` | PASS | REJECTED | CLEAN | 0 | 0 |
| `R2-08` | PASS | UNSUPPORTED | CLEAN | 0 | 0 |
| `R2-10` | PASS | REJECTED | CLEAN | 0 | 0 |
| `R2-11` | PASS | REJECTED | CLEAN | 0 | 0 |
| `R2-12` | PASS | REJECTED | CLEAN | 0 | 0 |
| `R2-13` | PASS | REJECTED | INFECTED | 0 | 0 |
| `R2-14` | PASS | REJECTED | INFECTED | 0 | 0 |
| `R2-15` | PASS | INSPECTED | INFECTED | 0 | 1 |
| `R2-17` | PASS | INSPECTED | CLEAN | 1 | 0 |
| `R2-18` | PASS | REJECTED | CLEAN | 0 | 0 |
| `R2-24` | PASS | INSPECTED | CLEAN | 0 | 1 |
| `R2-25` | PASS | INSPECTED | INFECTED | 1 | 1 |
| `R2-38` | PASS | INSPECTED | CLEAN | 1 | 0 |
| `R2-39` | PASS | INSPECTED | CLEAN | 1 | 0 |
| `CTRL-NEG-01` | PASS | INSPECTED | CLEAN | 1 | 0 |
| `CTRL-NEG-02` | PASS | INSPECTED | CLEAN | 2 | 0 |
| `LIMIT-INPUT-01` | PASS | REJECTED | CLEAN | 0 | 0 |
| `LIMIT-MEMORY-01` | PASS | REJECTED | CLEAN | 0 | 0 |
| `R1-LIVE-01` | PASS | INSPECTED | CLEAN | 2 | 2 |
| `R2-LIVE-01` | PASS | INSPECTED | CLEAN | 1 | 1 |
| `BENIGN-DOCX-EN-AR` | PASS | INSPECTED | CLEAN | 5 | 0 |
| `BENIGN-XLSX-EN-AR` | PASS | INSPECTED | CLEAN | 6 | 0 |
| `BENIGN-PPTX-EN-AR` | PASS | INSPECTED | CLEAN | 11 | 0 |
| `BENIGN-PDF-EN-AR` | PASS | NOT_VERIFIED | CLEAN | 0 | 0 |
| `ENCRYPTED-PDF-UNLOCK-REQUIRED` | PASS | UNSUPPORTED | CLEAN | 0 | 0 |

</details>

**Scanner and run checks:**

| Evidence source | Finding |
| --- | --- |
| Audit: live scanner | ClamAV engine `1.5.4`; signature DB `28187`, date string `Wed Nov 18 06:28:39 2026`. `FRESHNESS_GATE=PASS`: daily signature age 14 h against a 72 h limit. |
| Audit: transfer | 49,629 bytes transferred to the scanner. All 53 extracted replies have framing `ONE_NUL_TERMINATED_REPLY` and reason `CLAMD_INSTREAM_COMPLETE`. |
| Audit: verification | `required_evidence.status: PASS`; `runtime_verification.status: PASS`; independent fixture verification `PASS` (7/7 checks); `cleanup.status: PASS`. The archived offline PoC log separately reports 60/60 matches, not 60 additional live cases. |
| Audit: conclusion | `OVERALL_RESULT: PASS`; **`COMPLETE_SAFE_SCAN: false`**. |
| Pinned source: scanner identity | The workflow requires the locally built Phase 0B Ubuntu Jammy ARM64 candidate, package `1.5.4+dfsg-0ubuntu0.22.04.1+dipphase0b1`, with the `CLAM-3102` patch. The client uses clamd INSTREAM; this is not the production scanner. |
| Audit: archive inventory | The ZIP includes package/source manifests, config, local image IDs, tool versions and exit status. The supplied report does not give the image ID values. |
| Pinned source: isolation | The host checks two containers on an internal Docker network, no published ports, read-only root filesystems and separate bounded client/scanner resources. Passing these configuration checks is not an independent test of every possible egress path. |

### Why an offline reason appears beside live results

The audit counted `CLAMAV_SCANNER_NOT_VERIFIED_OFFLINE` in **38 of 39** case reason records.
In the run source, the [offline coverage builder][reason-origin] appends it unconditionally;
[the live reason record][reason-copy] copies structural reasons into `CASE_REASON.coverage_reason_codes`. The raw EICAR
control takes a separate path without that structural report. The live client records actual
original-input and extracted-payload replies separately. This is an **inherited metadata-classification
issue**, not 38 missing live scans, and not evidence that 38 cases were fully inspected. Retain the
original reasons and the genuine skipped-object, stream, unsupported-format and limit findings.

## `source-files.sha256`: source verified, archive comparison pending

The audit reports 12 entries but does not quote their digests. For each path named by the
[pinned manifest producer][manifest], this review hashed the raw bytes from
`git cat-file blob <run-sha>:<path>` with SHA-256 and checked byte equality with GitHub's Contents
API at that exact SHA. **12/12 source files verified; 0/12 compared to the archived entries.**
The last column is the status against the ZIP, not a mismatch and not a scanner verdict.

| Path from workflow (repository-relative) | SHA-256 computed from run commit | Against archived entry |
| --- | --- | --- |
| `.github/workflows/clamav-phase0c-live-evidence.yml` | `54870ca20a6b879eae96522c7ae9f676480f94d9f5e7dc2c399c3920a75f0fe4` | Not compared |
| `scripts/experiments/phase0c_r1r2_live_evidence.py` | `f6e471502f04f7a5e18683e4e1c360e792d7610fd8a8bb4545262a55131b667b` | Not compared |
| `scripts/experiments/phase0c_r1r2_poc.py` | `2a83139ecb671bce5e20dc5af61809e9c266c0dfa3be4e03c0335a7190942fe3` | Not compared |
| `scripts/experiments/phase0c_r1r2_fixtures.py` | `236a25fe47798a463a8379fa63669652232e3640c7fcf2122b1402cf4a8702e0` | Not compared |
| `scripts/experiments/phase0c_safe_scratch_cleanup.sh` | `4f7098386f31f6bb369f56715081cbfb8ec6a4ce2202b17640e7f990e3726560` | Not compared |
| `scripts/experiments/clamav-phase0b-evidence.py` | `03b1920a964400afe71ed8866f8c37d76b2e72f930edb93bd9d2b2436d926c52` | Not compared |
| `docs/operations/experimental/clamav-phase0c-client.Dockerfile` | `e57140170d7632a11f5e7d67601e6cf1c93a7ced9566127f6becf4b0ccaa545d` | Not compared |
| `docs/operations/experimental/clamav-phase0c-client.Dockerfile.dockerignore` | `c1e63e1c0d75fc613af181c454d2a71938c97a70d68a15276dfb520388c80253` | Not compared |
| `docs/operations/experimental/clamav-arm64-phase0b-candidate.Dockerfile` | `ccdc9745b22303f67961a3d1a75541de7b2668a53589f7bec2fc0be9d1849334` | Not compared |
| `docs/operations/experimental/clamav-arm64-phase0b-candidate.Dockerfile.dockerignore` | `cfbb2fac243944250ed1d1cffe9ea597cabf409020d524c2ff934bb13b3dd6d7` | Not compared |
| `docs/operations/experimental/clamav-arm64-stage4-candidate.conf` | `75e2fc17058971c143580579d1d6027b5385c1724a3109e79390a272d95909a6` | Not compared |
| `docs/operations/experimental/clamd-freshness-gate.sh` | `b1bff15489ece75f5baa20d6f244761492265ce52c072afdfde110461d9aade6` | Not compared |

The last two source digests also match the workflow's explicit config and freshness-script pins.
The separately pinned `CLAM-3102` patch matched SHA-256
`503040ebfc3a950ca3f5303c1591bb637e5d42ccb46cb3ca63fa94dab98cf013`; it is **not** a 13th
manifest entry. None of these source-side checks authenticates the unseen manifest lines.

## Open requirements and proposed engineering actions

These are **proposals for separate review**, not work orders, approved designs or exit decisions.

| Open item | Proposed acceptance criteria |
| --- | --- |
| Offline/live reason provenance | Version the schema without altering v1. Tests must distinguish offline-only reasons, live replies and missing/failed replies; preserve every genuine gap/limit code. Neither `CLEAN` nor `PASS` may promote incomplete coverage. |
| R1: PDF content beyond referenced attachments | Reconcile an independent inventory of arbitrary, unreferenced and filtered streams, indirect lengths, Object Streams (`/ObjStm`) and incremental revisions. Require a completed scan of the correct bytes for each expected object or an explicit fail-closed outcome. Attachment enumeration, qpdf metadata and PDF.js alone are insufficient. |
| Encrypted inputs and post-unlock outputs (`SEC-REQ-02` / `SEC-REQ-03`) | The genuine AES-256/R6 control had a `CLEAN` original, `UNSUPPORTED` coverage and no extracted replies. No post-unlock scan was demonstrated. Require fail-closed ingress and a scan of the decrypted output before persistence or reuse after an authorized unlock. Missing/wrong credentials, incomplete inspection or scanner error must block output. |
| R2: nested archives beyond bounded STORED/DEFLATE inspection | Reconcile per-member inventories, actual byte counts and completed replies with an independent reader. Unsupported compression, encrypted members, multi-disk archives and unsupported descriptors must remain explicit gaps. Malformed or over-budget members must fail closed. Measure false rejections using benign bilingual Office controls. |
| Production-scale resources and isolation | Test agreed concurrency and at-limit/over-limit cases. Measure CPU, peak memory and tmpfs for both client and scanner, transfer and latency under one end-to-end deadline. Require bounded peaks, fail-closed cancellation, verified cleanup and independent isolation checks. |
| Pre-storage placement and distribution | Security/Product must review evidence that uninspected inputs cannot reach durable storage or job creation. Before distribution require modification notices, Corresponding Source, an Ubuntu/Rust SBOM, UnRAR exclusion evidence and legal review. |

For scale, the live inspector's 4 MiB input, 2 MiB/member, 16 MiB cumulative expansion, 256 entries
and depth 3 are **fixture limits**. They do not validate the 100 MiB upload or the candidate's
110 MiB/member, 400 MiB cumulative scan and 10,000-file references. Future tests must distinguish
cumulative bytes scanned from peak materialization in a bounded tmpfs.

**Next action — authorized owner:** preserve the original ZIP before expiry, then compare its
`source-files.sha256` path/digest pairs with the table above. Require exactly the 12 distinct paths;
report missing, extra, mismatched or unreadable entries individually. Append a dated, metadata-only
custody and comparison result. Do not replace this entry, publish the ZIP or logs, or rerun the
experiment to reconstruct evidence.

[run]: https://github.com/mansour1414/DIP-Document-Intelligence-Platform/actions/runs/44396720677
[job]: https://github.com/mansour1414/DIP-Document-Intelligence-Platform/actions/runs/44396720677/job/135128502896
[artifact]: https://api.github.com/repos/mansour1414/DIP-Document-Intelligence-Platform/actions/artifacts/14471197885
[commit]: https://github.com/mansour1414/DIP-Document-Intelligence-Platform/commit/64a88a73283e6ffbccc4ccde4f94fae6d0754f56
[0b]: https://github.com/mansour1414/DIP-Document-Intelligence-Platform/blob/64a88a73283e6ffbccc4ccde4f94fae6d0754f56/docs/operations/experimental/clamav-phase0b-remediation-design.md
[offline]: https://github.com/mansour1414/DIP-Document-Intelligence-Platform/blob/64a88a73283e6ffbccc4ccde4f94fae6d0754f56/docs/operations/experimental/phase0c-r1r2-offline-poc.md
[design]: https://github.com/mansour1414/DIP-Document-Intelligence-Platform/blob/64a88a73283e6ffbccc4ccde4f94fae6d0754f56/docs/operations/experimental/phase0c-r1r2-live-evidence.md
[ingress]: https://github.com/mansour1414/DIP-Document-Intelligence-Platform/blob/64a88a73283e6ffbccc4ccde4f94fae6d0754f56/src/lib/jobs/orchestrator.ts#L26-L40
[matrix]: https://github.com/mansour1414/DIP-Document-Intelligence-Platform/blob/64a88a73283e6ffbccc4ccde4f94fae6d0754f56/scripts/experiments/phase0c_r1r2_live_evidence.py#L50-L68
[reason-origin]: https://github.com/mansour1414/DIP-Document-Intelligence-Platform/blob/64a88a73283e6ffbccc4ccde4f94fae6d0754f56/scripts/experiments/phase0c_r1r2_poc.py#L407-L439
[reason-copy]: https://github.com/mansour1414/DIP-Document-Intelligence-Platform/blob/64a88a73283e6ffbccc4ccde4f94fae6d0754f56/scripts/experiments/phase0c_r1r2_live_evidence.py#L669-L711
[manifest]: https://github.com/mansour1414/DIP-Document-Intelligence-Platform/blob/64a88a73283e6ffbccc4ccde4f94fae6d0754f56/.github/workflows/clamav-phase0c-live-evidence.yml#L85-L104
