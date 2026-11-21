# G1-A/03 Candidate Image and Supply Chain Verification Report

Overall status: **BLOCKED / NOT VERIFIED**. Licensing Gate remains **OPEN — NOT APPROVED**. The isolated Candidate Image definition and review tooling are prepared, but no image was built because this host has no OCI build runtime. No production file, dependency, Registry, Worker, API, UI, Workflow, Agent, or feature-flag state was changed.

## Owner decision applied

The owner conditionally authorized the exact Stage 3C dependency set, including duplicate qpdf and libjpeg implementations, solely to build and test an isolated Candidate Image. The authorization is recorded in `docs/g1a-02-licensing-gate-decision-record.md`. It is not final dependency approval and does not close the Licensing Gate.

## Build environment result

| Check | Result | Evidence |
| --- | --- | --- |
| Docker | FAIL | command absent; standard Docker Desktop executable absent |
| Podman / nerdctl / Buildah | FAIL | commands absent |
| WSL | FAIL for build | Windows feature command exists, but no Linux distribution is installed |
| Syft | FAIL | command absent |
| Grype / Trivy | FAIL | commands absent |
| Registry credentials/approved target | NOT VERIFIED | none supplied; publication prohibited |

Because there is no usable builder, the following values do not exist and were not invented:

- Candidate local image ID: `NOT GENERATED`.
- Candidate local archive SHA-256: `NOT GENERATED`.
- Candidate registry repository digest: `NOT VERIFIED`.
- Actual image-derived Debian/Python/Node/native inventories: `NOT VERIFIED`.
- Image-derived SPDX and CycloneDX: `NOT VERIFIED`.
- Image vulnerability scan: `NOT VERIFIED`.

## Prepared isolated candidate

`scripts/experiments/Dockerfile.structural-grayscale-g1a03-candidate` extends a local base built from the unchanged `Dockerfile.worker`. It installs the nine reviewed wheels into `/opt/dip-gray-candidate`, does not copy the Grayscale engine, does not dispatch jobs, does not expose ports, and exits after printing an evidence-only message. It confirms Ghostscript absence.

`scripts/experiments/build-structural-grayscale-g1a03-candidate.sh` is fail-closed and:

1. requires Docker, Syft, Grype, Python, and the exact nine-wheel directory;
2. requires `G1A03_NODE_IMAGE` to be an approved `repository@sha256:...` reference rather than the mutable default tag;
3. rebuilds the unchanged Production Worker definition under a candidate-only local tag;
4. builds the isolated derivative without modifying or pushing a production image;
5. records the local image ID separately from RepoDigests and a local Docker archive hash;
6. extracts actual dpkg, Python, Node, and Python-native inventories;
7. emits SPDX JSON, CycloneDX JSON, and Grype JSON;
8. never performs `docker push`.

The build definition itself is ready, but a successful execution is required before any of these evidence items can be marked PASS.

## Prebuild reconciliation

| Evidence area | Status | Result |
| --- | --- | --- |
| G1-A/02 wheel hashes | PASS | nine downloaded Linux wheels matched all frozen SHA-256 values |
| G1-A/02 native hashes | PASS | 41 wheel native members inventoried, including libqpdf, both libjpeg builds, LittleCMS, OpenJPEG and PDFium |
| Candidate Dockerfile vs Production Worker | PASS | separate Dockerfile; `Dockerfile.worker` unchanged |
| Node production lock audit | PASS for lock only | `npm audit --omit=dev` returned zero known vulnerabilities; not an image scan |
| PyPI OSV query | FAIL pending triage | `pypdf 6.10.0` returned 45 OSV/GHSA/PYSEC identifiers; other eight queried packages returned no matches in the batch response |
| Actual image vs prior inventory | NOT VERIFIED | image not built |
| Debian 301-package reconciliation | NOT VERIFIED | raw image and complete SPDX unavailable |
| Actual pruned Node inventory | NOT VERIFIED | requires extraction from built image |
| Image native filesystem reconciliation | NOT VERIFIED | requires extraction from built image |

The OSV result is a security blocker for candidate acceptance. It is not interpreted here as proof that all listed issues are exploitable in DIP, but Security must map affected functions and fixed versions or approve removal/replacement. Since pypdf is an experimental validator dependency rather than the transformer, exclusion from the eventual runtime is a viable option, but that decision belongs to the next approved dependency revision and must not be made silently.

## Vulnerability status

`docs/evidence/g1a03/g1a03-prebuild-vulnerability-evidence.json` preserves the prebuild results:

- npm production lock: `PASS`, 0 reported vulnerabilities.
- PyPI OSV batch: `FAIL`, because pypdf `6.10.0` returned 45 identifiers requiring triage.
- OCI image scan: `NOT VERIFIED`, because no image or scanner exists on this host.

Final Security review requires a Grype or Trivy scan against the immutable registry digest, not only a local tag, lockfile, or package query.

## Notices bundle

The deterministic candidate notices bundle was generated from the exact nine wheel archives and available non-dev Node package directories:

- bundle: `docs/evidence/g1a03/g1a03-notices-bundle.zip`;
- bundle SHA-256: `5811d2398e41a952bc2a3498eff1170e9305be78706e048ce6a6e961ece256e1`;
- manifest SHA-256: `9e0e9ce36f46a8197145b2df5486057186713ac114524420c238787dda9bf56c`;
- 514 bundle entries;
- 167 Node production-lock candidates had no top-level notice/license file in the locally installed directory and remain review items rather than presumed violations.

The bundle is partial by design. Debian `/usr/share/doc/*/copyright`, the actual pruned Node filesystem, and any base-image notices must be extracted from the built image. Licensing must also determine whether package metadata or nested notice locations satisfy each component's obligation.

## Image identity and provenance

The candidate build script requires the Node base as an immutable `repository@sha256:...`. No approved base digest was supplied, so source-image provenance is currently `NOT VERIFIED`. The existing `ARG NODE_IMAGE=node:22.20.0-bookworm-slim` tag in `Dockerfile.worker` is not treated as immutable provenance.

A local image ID, once generated, proves only the local image configuration/content identity. A `docker image save` SHA-256 proves only the exported local archive. Neither is an OCI registry repository digest. Approval requires an independently retrievable `registry/repository@sha256:...` and SBOM/scan evidence bound to it.

## Registry publication boundary

No approved registry target or credentials were supplied, and publication is outside this task. Nothing was pushed.

After a registry and credentials are explicitly approved, the reviewer may execute commands equivalent to the following manually; they are intentionally absent from the build script:

```sh
docker tag dip-structural-grayscale:g1a03-candidate APPROVED_REGISTRY/APPROVED_REPOSITORY:g1a03-candidate
docker push APPROVED_REGISTRY/APPROVED_REPOSITORY:g1a03-candidate
docker image inspect APPROVED_REGISTRY/APPROVED_REPOSITORY:g1a03-candidate --format '{{json .RepoDigests}}'
```

The returned RepoDigest must be independently pulled and verified before it is used in an approval record.

## Security and Licensing gate matrix

| Gate | Status | Requirement to change status |
| --- | --- | --- |
| Owner conditional candidate-build authorization | PASS | already recorded; limited to isolated candidate testing |
| Isolated non-production build definition | PASS | definition and fail-closed runner present |
| Actual candidate build | NOT VERIFIED | approved OCI builder and immutable base digest required |
| Production isolation | PASS | no Production Worker/Registry/API/UI integration changes |
| Actual mixed-layer inventory | NOT VERIFIED | extract from candidate image |
| SPDX + CycloneDX image SBOM | NOT VERIFIED | run Syft and reconcile outputs |
| Vulnerability acceptance | FAIL | triage pypdf findings, then scan the built digest and resolve findings |
| Notices/source obligations | PARTIAL | candidate Python/Node bundle exists; image/Debian notices and legal review remain |
| Base-image provenance | NOT VERIFIED | approved Node repository digest required |
| Candidate registry digest | NOT VERIFIED | approved registry push/pull verification required |
| Security approval | PENDING | requires actual image evidence and vulnerability disposition |
| Licensing approval | PENDING | requires complete notices/SBOM and obligation review |
| Owner final approval | PENDING | must bind the accepted evidence to the immutable digest |

## Gaps before G1-A/04

1. Provide an approved Linux OCI builder with Docker or equivalent, plus Syft and Grype/Trivy.
2. Approve and supply the exact Node base `repository@sha256` digest.
3. Triage all pypdf `6.10.0` OSV matches; choose a fixed version, remove it from the candidate runtime, or record an explicit Security exception after reachability analysis.
4. Execute the candidate build script and retain its local image ID, local archive hash, inventories, SPDX, CycloneDX, and vulnerability JSON.
5. Reconcile actual image contents against G1-A/02, including all 301 Debian packages, the pruned Node tree, Python packages, and every native file.
6. Extract Debian and base-image notices and resolve the 167 Node notice-location review items.
7. Obtain Security and Licensing review of the actual image evidence.
8. Approve a private registry target and credentials if an immutable OCI digest is required; then push only under a separately authorized action.
9. Independently pull and verify the registry digest, rerun SBOM and vulnerability scans against it, and bind final approvals to those hashes.

G1-A/04 must not treat the prepared Dockerfile, local lock audits, or notices bundle as a built or approved image.
