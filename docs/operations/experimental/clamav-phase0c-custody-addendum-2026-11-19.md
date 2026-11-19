# ClamAV Phase 0C — evidence custody and source-manifest reconciliation addendum

**Addendum date: 2026-11-19 (UTC and Asia/Riyadh).** This metadata-only entry supplements the
[Phase 0C isolated live evidence register][register] for [run 44396720677][run]. It records the two
results that register left pending:

- **Custody:** the repository owner confirms that the original artifact ZIP is preserved in private
  Windows storage, that its SHA-256 is
  `f76512317e4a9d8b3cf4162ea1f1e3d208654c69c2c5900380a99a739c486e66`, and that a second backup
  exists. The exact UTC custody timestamp is **PENDING**.
- **Reconciliation:** an external audit session opened an unmodified copy of the ZIP, read-only,
  and compared its archived `source-files.sha256` with the source digests in the register.
  **12/12 MATCH; 0 missing; 0 extra; 0 mismatched.** This review did not open the ZIP.

The register was merged by [PR #21][pr21] at `16eae9777bd94979acfde05fe56ec4f19ba2b5e1` and is
**not edited** here. Its statements stand as written for their date.

**Disposition unchanged:** Security Gate **OPEN**; Licensing Gate **OPEN**; Stage 7 **NOT ACCEPTED**;
R1/R2 **OPEN**. `CLAMAV-CR-P01`, `CLAMAV-CR-P02`, `CLAMAV-CR-P03`, `CLAMAV-CR-R1` and
`CLAMAV-CR-R2` remain **PROPOSED — NOT APPROVED**. Archive custody and a matching source manifest
are evidence-handling facts. They are not scanner results and they approve nothing.

## Who verified what

Each source is credited only with what it observed itself. **Independent artifact verification** —
opening the ZIP, recomputing its digest, checking its CRCs and reading the archived manifest — was
performed only by external audit sessions: the artifact audit recorded in the register and the
reconciliation session recorded here. It is not this review's work, and it is distinct from the
owner's custody check.

| Source | Observed directly | Limits |
| --- | --- | --- |
| **GitHub metadata** | [Artifact 14471197885][artifact] of run 44396720677 at [commit `64a88a73283e6ffbccc4ccde4f94fae6d0754f56`][commit]: 69,026 bytes; `digest` equal to the SHA-256 above; created 2026-11-18 21:07:10 UTC; expires 2026-12-18 21:07:09 UTC. | Does not expose the ZIP members or the archived manifest. |
| **External audit** (reconciliation session) | Worked read-only on an unmodified copy of the original ZIP: 69,026 bytes; computed SHA-256 equal to the GitHub digest; 22 members; CRC **PASS**. Read the archived `source-files.sha256` and compared it with the register. | Disclaims a second independent re-hash of the Git source. Did not verify owner custody; its working copy is not an archival location. |
| **Repository owner** (`mansour1414`) | Custody of the original ZIP: the storage, the SHA-256 of the preserved copy and the second backup. | An attestation; no other source observed the storage. Exact UTC custody timestamp not yet supplied. |
| **This review** | The source side only: SHA-256 of the 12 Git blobs at the run commit, GitHub metadata, and agreement between the supplied report and the register. | Never held the ZIP. It computed no ZIP digest or CRC, counted no members and read no archived manifest. It did not observe the owner's storage. |

"This review" is the agent-assisted review environment that also prepared the register in PR #21;
the reconciliation report calls it "Arena". "Independent" here means outside that environment and
on bytes it never held.

The reconciliation comes from the supplied *DIP Phase 0C — Source Manifest Reconciliation
(Sanitized)*, `DIP_Phase0C_Source_Manifest_Reconciliation_2026-11-19.md` (audit date 2026-11-19,
Asia/Riyadh; 4,299 bytes; attachment SHA-256
`adc8cf9d6e13632dcbbb53e1a40f99b6e1e665e03c25aa161a082e6b2f6e1a67`). The report names no author
and reached this review as an owner-supplied attachment. Its own classification reads: "Read-only
evidence comparison; not a custody receipt, production approval, or independent source-code
rebuild." As with the earlier audit attachment, it is identified by hash and not committed.

## Custody record

The [register][register-custody] asked the owner or an authorized custodian to preserve the
original ZIP, without repacking, before expiry; to compare its byte count and SHA-256 with the
GitHub record on receipt and after storage; and to record the custodian, UTC time, restricted
storage reference and checksum receipt. The owner's confirmation reached this review on 2026-11-19
UTC. It is recorded here field by field.

| Receipt field | Recorded | Status |
| --- | --- | --- |
| Object preserved | Original artifact ZIP of run 44396720677 (artifact 14471197885). The matching SHA-256 below means it is not a repack. | **CONFIRMED** by owner |
| Storage reference | Private Windows storage. No path, device or account is recorded in this public file. | **CONFIRMED** by owner |
| SHA-256 of the preserved copy | `f76512317e4a9d8b3cf4162ea1f1e3d208654c69c2c5900380a99a739c486e66` | **CONFIRMED** by owner; equal to the GitHub digest and to the digest the external audit computed |
| Second backup | Exists. | **CONFIRMED** by owner |
| Exact UTC custody timestamp | Not yet supplied. | **PENDING** |
| Custodian | Repository owner (`mansour1414`), who gave the confirmation. No other custodian was named. | Read from the confirmation; not named separately |
| Byte count as observed by the owner | GitHub and the external audit record 69,026 bytes. A matching SHA-256 implies the same bytes and therefore the same length. | Not stated in the confirmation |
| SHA-256 on receipt and again after storage | One SHA-256 was confirmed. The stage at which it was taken is not given. | Not stated in the confirmation |
| Second backup: storage reference and checksum | — | Not stated in the confirmation |

**Timing.** This custody record is incomplete until the exact UTC custody timestamp is appended.
Records already held bound it: the copy cannot predate the artifact, created 2026-11-18 21:07:10
UTC, and the owner's confirmation was received on 2026-11-19 UTC. Both precede the GitHub expiry
of **2026-12-18 21:07:09 UTC**, so on the owner's statement the preservation deadline was met.
These bounds do not replace the timestamp.

**Limit.** The custody facts are the owner's attestation. Neither this review nor the external
audit observed the storage, the preserved copy or the backup. The audit report records long-term
preservation by the owner as "not verified" and describes its own working copy as "not a verified
owner-owned archival location".

## Source-manifest reconciliation: 12/12

The register hashed the 12 files named by the [pinned manifest producer][manifest] from Git blobs
at the run commit and [recorded][register-manifest] "12/12 source files verified; 0/12 compared to
the archived entries", because that review could not reach the ZIP. The external audit has since
made the missing comparison. It read `source-files.sha256` from the ZIP, found exactly 12 unique,
syntactically valid path/digest records, and compared each path and digest with the register's
table by exact string equality.

**Result (external audit): 12/12 MATCH; 0 missing; 0 extra; 0 mismatched.** The report lists no
unreadable entry. The audit worked on its own copy of the ZIP. The owner confirms the same SHA-256
for the preserved copy, which therefore holds the same manifest.

| Path from workflow (repository-relative) | SHA-256 (archived entry = source digest) | Archived entry vs. register (external audit) | Re-hash of Git blob at run commit (this review) |
| --- | --- | --- | --- |
| `.github/workflows/clamav-phase0c-live-evidence.yml` | `54870ca20a6b879eae96522c7ae9f676480f94d9f5e7dc2c399c3920a75f0fe4` | MATCH | Equal |
| `scripts/experiments/phase0c_r1r2_live_evidence.py` | `f6e471502f04f7a5e18683e4e1c360e792d7610fd8a8bb4545262a55131b667b` | MATCH | Equal |
| `scripts/experiments/phase0c_r1r2_poc.py` | `2a83139ecb671bce5e20dc5af61809e9c266c0dfa3be4e03c0335a7190942fe3` | MATCH | Equal |
| `scripts/experiments/phase0c_r1r2_fixtures.py` | `236a25fe47798a463a8379fa63669652232e3640c7fcf2122b1402cf4a8702e0` | MATCH | Equal |
| `scripts/experiments/phase0c_safe_scratch_cleanup.sh` | `4f7098386f31f6bb369f56715081cbfb8ec6a4ce2202b17640e7f990e3726560` | MATCH | Equal |
| `scripts/experiments/clamav-phase0b-evidence.py` | `03b1920a964400afe71ed8866f8c37d76b2e72f930edb93bd9d2b2436d926c52` | MATCH | Equal |
| `docs/operations/experimental/clamav-phase0c-client.Dockerfile` | `e57140170d7632a11f5e7d67601e6cf1c93a7ced9566127f6becf4b0ccaa545d` | MATCH | Equal |
| `docs/operations/experimental/clamav-phase0c-client.Dockerfile.dockerignore` | `c1e63e1c0d75fc613af181c454d2a71938c97a70d68a15276dfb520388c80253` | MATCH | Equal |
| `docs/operations/experimental/clamav-arm64-phase0b-candidate.Dockerfile` | `ccdc9745b22303f67961a3d1a75541de7b2668a53589f7bec2fc0be9d1849334` | MATCH | Equal |
| `docs/operations/experimental/clamav-arm64-phase0b-candidate.Dockerfile.dockerignore` | `cfbb2fac243944250ed1d1cffe9ea597cabf409020d524c2ff934bb13b3dd6d7` | MATCH | Equal |
| `docs/operations/experimental/clamav-arm64-stage4-candidate.conf` | `75e2fc17058971c143580579d1d6027b5385c1724a3109e79390a272d95909a6` | MATCH | Equal |
| `docs/operations/experimental/clamd-freshness-gate.sh` | `b1bff15489ece75f5baa20d6f244761492265ce52c072afdfde110461d9aade6` | MATCH | Equal |

**What this shows.** For each of the 12 files, the digest the runner wrote during the run equals
the digest of the Git blob at the run commit. The files the run hashed were byte-identical to the
Git source at that commit.

**What it does not show.**

- It is not a second independent re-hash of the Git source. The source-side digests are this
  review's: computed for PR #21 and reproduced for this entry. The audit compared against them.
- This review has still not seen the archived manifest, only the report's transcription of it.
- It is not an image rebuild, a scanner verdict or a coverage result. `COMPLETE_SAFE_SCAN: false`
  and every open requirement in the register are unaffected.

**Reading the register now.** Its "0/12 compared" and its twelve "Not compared" cells describe what
that review could do on its date. They remain historically correct and are not rewritten. The
comparison they left pending is the one recorded above, and it belongs to the external audit.

## Checks made for this addendum

This review made these read-only checks on 2026-11-19 UTC.

| Check | Result |
| --- | --- |
| Supplied report | Hashed; SHA-256 above. Its run, commit and artifact identifiers, the 69,026-byte size, 22 members and CRC **PASS** agree with the register. It quotes the earlier audit attachment's SHA-256, `6356a35b239e6fa541b50d5245f5c6c0eb9ef52d013644e6ab6b0d6fe7de103d`, which equals the register's value. |
| Report table against register table | All 12 path/digest pairs are string-equal and in the same order; each is marked MATCH. Recount: 12 distinct paths; 0 missing, 0 extra, 0 mismatched. |
| ZIP digest | The owner-confirmed SHA-256, the report's computed SHA-256, the register's value and GitHub's `digest` are the same 64-character hex string. |
| GitHub metadata, re-queried 03:11 UTC | Artifact 14471197885: 69,026 bytes, not expired, expiry as above; it is the run's only artifact. Run 44396720677: `workflow_dispatch`, `completed` / `success`, at the run commit. |
| Source digests | Reproduced 12/12 from `git cat-file blob <run-sha>:<path>`. GitHub's Contents API at that SHA returned bytes with the same digests. Same party and method as PR #21: a reproduction, not an independent check. |
| Register unchanged | Git blob `f44e57eb4515beee6706d3a29e21dda133783e42` at the PR #21 head `1cdabeba351d18c2e7dca8fdf87cc0b3b1f56918`, at the merge commit and in this change. PR #21 was a Draft until 2026-11-19 02:36:22 UTC and was merged at 02:36:52 UTC with no further commit, so the values the audit compared are those on `main`. |
| ZIP bytes | One download attempt at 03:07 UTC was redirected to object storage unreachable from this environment. Nothing was downloaded and no archive was opened. |

No workflow was dispatched, and no experiment or fixture generator was run. This entry contains no
archive, fixture, payload, credential, signature database or raw log.

## Pending and unchanged

| Item | Status |
| --- | --- |
| Exact UTC custody timestamp | **PENDING** — repository owner |
| Receipt details not stated in the confirmation: custodian named separately, byte count as observed, SHA-256 on receipt and after storage, second-backup reference and checksum | Not stated — the owner may add them with the timestamp |
| Independent verification of custody | Not performed. Custody rests on the owner's attestation. |
| Second independent re-hash of the Git source | Not performed. The register did not request it. |
| [Open requirements and proposed engineering actions][register-open] in the register | Unchanged. They remain proposals for separate review. |

**Next action — repository owner:** append the exact UTC custody time as a dated, metadata-only
entry. Do not edit the register, publish the ZIP or logs, or rerun the experiment to reconstruct
evidence. GitHub's copy expires at **2026-12-18 21:07:09 UTC**. After that the owner's preserved
copies are the only archival originals, and the SHA-256 recorded here is the reference for checking
them.

[register]: https://github.com/mansour1414/DIP-Document-Intelligence-Platform/blob/16eae9777bd94979acfde05fe56ec4f19ba2b5e1/docs/operations/experimental/clamav-phase0c-evidence-register-2026-11-19.md
[register-custody]: https://github.com/mansour1414/DIP-Document-Intelligence-Platform/blob/16eae9777bd94979acfde05fe56ec4f19ba2b5e1/docs/operations/experimental/clamav-phase0c-evidence-register-2026-11-19.md#run-and-archive-identity
[register-manifest]: https://github.com/mansour1414/DIP-Document-Intelligence-Platform/blob/16eae9777bd94979acfde05fe56ec4f19ba2b5e1/docs/operations/experimental/clamav-phase0c-evidence-register-2026-11-19.md#source-filessha256-source-verified-archive-comparison-pending
[register-open]: https://github.com/mansour1414/DIP-Document-Intelligence-Platform/blob/16eae9777bd94979acfde05fe56ec4f19ba2b5e1/docs/operations/experimental/clamav-phase0c-evidence-register-2026-11-19.md#open-requirements-and-proposed-engineering-actions
[pr21]: https://github.com/mansour1414/DIP-Document-Intelligence-Platform/pull/21
[run]: https://github.com/mansour1414/DIP-Document-Intelligence-Platform/actions/runs/44396720677
[artifact]: https://api.github.com/repos/mansour1414/DIP-Document-Intelligence-Platform/actions/artifacts/14471197885
[commit]: https://github.com/mansour1414/DIP-Document-Intelligence-Platform/commit/64a88a73283e6ffbccc4ccde4f94fae6d0754f56
[manifest]: https://github.com/mansour1414/DIP-Document-Intelligence-Platform/blob/64a88a73283e6ffbccc4ccde4f94fae6d0754f56/.github/workflows/clamav-phase0c-live-evidence.yml#L85-L104
