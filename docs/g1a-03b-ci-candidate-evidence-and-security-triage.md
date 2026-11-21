# G1-A/03B — CI Candidate Evidence and Vulnerability Triage

Status: **READY FOR OWNER-RUN CI; Licensing Gate OPEN — NOT APPROVED**
Scope: isolated candidate supply-chain evidence only. No production adoption, deployment, registry publication, or public exposure.

## pypdf 6.10.0 triage

The original OSV response contained 45 identifiers. After grouping GHSA, CVE, and PYSEC aliases, it represents **23 unique advisories**, not 45 independent vulnerabilities. OSV identifies `6.10.0` as affected by all 23. Fixed versions range from `6.10.1` to `6.16.1`; this record does not change the reviewed dependency set.

The canonical GHSA records classify two findings as **HIGH** (`GHSA-5xf7-4p34-54qr`, `GHSA-g867-7843-wf8q`) and 21 as **MODERATE**. The evidence retains the published CVSS vector for every advisory.

Stage 3C uses `PdfReader`, plain-mode `page.extract_text()`, `get_fields()`, and `PdfWriter.clone_document_from_reader()`. The evidence classifies 10 advisories as directly reachable by those parser/text paths, 11 as conditional pending a bounded trigger fixture, and two layout-mode findings as not reached by the current call pattern. “Not reached” is not a waiver and “affected” is not proof of successful exploitation. Detailed aliases, vectors, fixed versions, and call paths are in `docs/evidence/g1a03b/pypdf-6.10.0-security-triage.json`.

Decision: **FAIL_PENDING_SECURITY_REVIEW**. Security must choose a documented experimental exception, removal of pypdf from the candidate design, or review of a separate dependency change. No upgrade is included here.

## CI design

`.github/workflows/g1a03b-candidate-evidence.yml` is isolated from the production CI file. It runs for a narrowly path-filtered pull request or by `workflow_dispatch`, uses `ubuntu-24.04`, has read-only repository permission, and contains no deployment or registry-push step. It:

1. Pulls and re-verifies `docker.io/library/node:22.20.0-bookworm-slim@sha256:b21fe589dfbe5cc39365d0544b9be3f1f33f55f3c86c87a76ff65a02f8f5848e`.
2. Downloads Syft 1.52.0 and Grype 0.119.0 from their official GitHub releases and rejects binaries whose SHA-256 differs from the pinned release checksum.
3. Downloads the reviewed nine-wheel set and runs the G1-A/02 hash verification before building.
4. Builds the unchanged worker Dockerfile only as an intermediate base and then the isolated candidate Dockerfile.
5. Extracts Debian, Python, Node, native-library, and Debian copyright inventories; produces SPDX and CycloneDX; runs Grype; and reconciles the Python versions.
6. Uploads the evidence directory as a 30-day GitHub Actions artifact.

## Image identity boundary

The trusted registry query on 2026-09-28 returned the base OCI index digest above. CI verifies that digest again before use and fails closed on mismatch.

The built candidate has a local Docker image ID and a local archive SHA-256. Those values identify local build material only. Because the workflow performs no registry push and no independent pull, the candidate registry OCI digest remains **NOT VERIFIED**. The reconciliation requires the candidate `RepoDigests` list to be empty.

## Notices boundary

The previous count of 167 Node packages means no top-level file beginning with LICENSE, LICENCE, COPYING, or NOTICE was found in the local installed directory. This is an **evidence gap, not a confirmed license violation**. The CI bundle preserves the list for source-distribution and metadata review. Debian `/usr/share/doc/*/copyright` files and their hashes are collected from the actual candidate image.

## What the candidate proves

- Exact base digest was pulled at build time.
- Reviewed wheels passed the frozen G1-A/02 hash inventory.
- Local image contents were inventoried and scanned.
- SPDX, CycloneDX, Grype JSON, notices, and reconciliation were produced from that local build.
- The local image ID is distinguishable from a registry digest.

## What remains NOT VERIFIED

- An immutable candidate registry digest, because publication and independent pull are prohibited.
- Reproducibility of the local image ID across runners.
- Security acceptance of the 23 pypdf advisories and the Grype findings.
- Final licensing approval of Python, Node, Debian, native, and embedded components.
- Source-level notice review for Node packages without a top-level notice file.
- Production suitability: the candidate deliberately contains **no Grayscale engine implementation or dispatch**, so it is not final production-image evidence.

No G1-A/04 or G1-B work is authorized by this record.
