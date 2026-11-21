# G1-A/02 Structural Grayscale Licensing Gate Decision Record

Decision status: **OPEN — NOT APPROVED**. This record closes the evidence collection tranche only. It does not approve a production dependency, production integration, public exposure, or G1-B work.

## Owner conditional candidate-build authorization

Owner decision recorded for G1-A/03: the Stage 3C dependency set, including the duplicate qpdf and libjpeg implementations, is **conditionally authorized only for building and testing an isolated Candidate Image**. This authorization does not approve the Licensing Gate, production dependencies, Production Worker changes, product integration, Registry/API/UI exposure, deployment, public claims, or G1-B. Every component disposition below remains `NOT APPROVED` until the final Owner, Security, and Licensing decisions are bound to verified image evidence and an immutable OCI registry digest.

Evidence date: 2026-09-28. Repository basis: `f1a785820234d72c7e2e0723244c4b1278700caa` plus the uncommitted G1-A/01 internal flag foundation. Controlling authority remains DIP MASTER BASELINE / CR-001, approved prelaunch CR-003, and owner decision `DIP-OWNER-G0-2026-09-28` authorizing internal-only G1-A subject to licensing and security gates.

## Evidence set

- Frozen Stage 3C artifact ZIP SHA-256: `96db802a0afa3fec8866a8dfe106fdc3fd75bc7e5561ed1b6005e4d7f1d3af6e`.
- Frozen production-worker Debian SPDX artifact ZIP SHA-256: `f5fa8b1326956309a0bb829fd2da4a0e300a1d75c54b3fd7fb707fc9f046a3a2`; G0 reports 301 Debian packages.
- Exact Linux wheel archives were downloaded to a temporary evidence directory using the frozen versions. All nine wheel hashes matched G0.
- `docs/evidence/g1a02/g1a02-python-native-inventory.json` SHA-256: `f1cc4543a1879ab4f8c10497a632fe0fcfef5606fed4c454cc9d84ee3542b541`.
- `docs/evidence/g1a02/g1a02-unified-candidate-sbom.cdx.json` SHA-256: `cda2294009845f60ffc44954d83f9c7faff1dddf57880d28ae0eaa1ff6dc021b`.
- Collector: `scripts/experiments/collect-structural-grayscale-g1a02-evidence.py`. It opens wheel archives without installing or loading their native code.

The historical Debian SPDX ZIP is digest-anchored, but its complete raw SPDX file is not locally available in this workspace and the private GitHub artifact could not be fetched without authenticated artifact access. The unified candidate SBOM therefore materializes the 11 Debian components explicitly preserved in G0 and records the remaining Debian layer as incomplete. It does not invent the other 290 package records.

## Image identity decision

| Identity | Evidence | Decision |
| --- | --- | --- |
| Local Docker image ID | Stage 3C captured local IDs in its artifact, but the raw values are not available in the local evidence set | `NOT VERIFIED` here; even a verified local ID would identify local image content only |
| Registry repository digest | Stage 3C `production-base-image-digests.json` was `[]`; no pushed immutable digest is evidenced | `NOT VERIFIED` |
| Artifact ZIP digests | GitHub-recorded ZIP digests are frozen above | Verified artifact identities only; they are not OCI registry digests |

No local image ID is represented as a registry digest. Licensing approval must bind to a future immutable OCI digest such as `repository@sha256:...` produced by the approved build and registry.

## Python dependency inventory

| Component | Version | Role | License evidence | Source | Wheel SHA-256 | Commercial obligations and boundary | Decision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| pikepdf | `10.13.0.post1` | candidate direct transformer | `MPL-2.0` from wheel metadata and license file | `https://github.com/pikepdf/pikepdf` | `365b94f2be7e2857c6cb5445b56dc52dc7417ba9f06c8a4282d9f521cb2d0fb8` | retain notices; identify modified MPL-covered files and satisfy source availability obligations if distributed; preserve bundled qpdf/libjpeg notices; legal review of planned distribution | NOT APPROVED |
| Pillow | `12.3.0` | candidate direct JPEG/ICC/pixel path | wheel SPDX expression `MIT-CMU` | `https://github.com/python-pillow/Pillow` | `23d27a3e0307ec2244cc51e7287b919aa68d097504ebe19df4e76a98a3eea5bd` | retain Pillow license and all bundled third-party notices; freeze codec build; review optional/native component set | NOT APPROVED |
| lxml | `6.1.3` | pikepdf transitive | `BSD-3-Clause` | `https://github.com/lxml/lxml` | `527195c188d7d0af748cd48d220ab8cdc5cb99be3d49ac4d9be7324d8abf9bc0` | retain license/copyright; review exact statically or dynamically included XML components and security posture | NOT APPROVED |
| packaging | `26.3` | pikepdf transitive | `Apache-2.0 OR BSD-2-Clause` | `https://github.com/pypa/packaging` | `d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c` | record selected terms and preserve corresponding notices | NOT APPROVED |
| charset-normalizer | `3.5.1` | reportlab transitive | `MIT` | `https://github.com/jawah/charset_normalizer` | `c7b742bf31c88566b4bb6335a7f393bb322e580b6bb98df7bd0c25e6e3519ce8` | retain license/copyright | NOT APPROVED; fixture chain only |
| pypdf | `6.10.0` | experimental semantic validator | `BSD-3-Clause` | `https://github.com/py-pdf/pypdf` | `90005e959e1596c6e6c84c8b0ad383285b3e17011751cedd17f2ce8fcdfc86de` | retain notice; technical independence must be approved separately | NOT APPROVED |
| pypdfium2/PDFium | `5.13.0` | experimental reference reader; existing OCR pin | wrapper BSD-3-Clause/Apache-2.0 plus PDFium build license bundle | `https://github.com/pypdfium2-team/pypdfium2` | `81df25c1ab4c13ff773102d3cbea1967511d079123b067fc077bd0c4d57d91d8` | distribute the included PDFium/third-party notices; verify Grayscale role separately from existing OCR clearance | NOT APPROVED for Grayscale role |
| reportlab | `4.4.9` | fixture generation | bundled BSD license | `https://www.reportlab.com/` | `68e2d103ae8041a37714e8896ec9b79a1c1e911d68c3bd2ea17546568cf17bfd` | retain package/font notices; exclude from production candidate unless separately justified | NOT A PRODUCTION CANDIDATE |
| uharfbuzz | `0.56.2` | fixture shaping | Apache-2.0 wrapper; bundled HarfBuzz notice | `https://github.com/trufont/uharfbuzz` | `f058d70848312366e82068ebef54ead53269bdf34e893c25a3174ea1f5c6d2d3` | retain both notice sets; exclude from production candidate unless separately justified | NOT A PRODUCTION CANDIDATE |

`reportlab`, `charset-normalizer`, and `uharfbuzz` were part of Stage 3C fixture/evidence generation. They are not justified runtime dependencies for the transformer candidate.

## Key embedded native findings

The inventory records all 41 native wheel members with exact file SHA-256 values. The most important decision points are:

| Component | Version evidence | Exact embedded member | SHA-256 | License evidence and obligations | Decision |
| --- | --- | --- | --- | --- | --- |
| libqpdf bundled by pikepdf | `12.3.2` | `pikepdf.libs/libqpdf-b00d82b7.so.30.3.2` | `63ddaa79f709b48d2d555c289ec1b6724acf343edff07eb8b2ed3d3fb32342d7` | Apache-2.0; retain license/NOTICE as applicable. This is distinct from Debian qpdf/libqpdf `11.3.0-1+deb12u1`. | NOT APPROVED |
| libjpeg-turbo bundled by pikepdf | embedded SBOM `1.5.3-14.el8_10`; SONAME `62.2.0` | `pikepdf.libs/libjpeg-e87d2658.so.62.2.0` | `b11b9abc297ac74cc03eb64e11cb1814c00e2c47e61a3886ee5ea7d9ff52eea9` | IJG + BSD-3-Clause + Zlib notice set from pikepdf wheel | NOT APPROVED |
| libjpeg/libjpeg-turbo bundled by Pillow | source SBOM `3.1.4.1`; SONAME `62.4.0` | `pillow.libs/libjpeg-31e2ca52.so.62.4.0` | `6d7c754529b30aff22efaaf88ba02061714591702c03f297f00ccb32ee6d9d9a` | IJG + BSD-3-Clause; retain third-party notices | NOT APPROVED |
| Little CMS 2 | source SBOM `2.19.1`; filename ABI `2.0.19` | `pillow.libs/liblcms2-dade1fbf.so.2.0.19` | `2549d6886e7de9960792e10ac87acfb9895e2afae85b7aac02108080cc7d3a71` | MIT; retain notice; security must review ICC parser exposure | NOT APPROVED |
| OpenJPEG present through Pillow | `2.5.4` | `pillow.libs/libopenjp2-b07f72ad.so.2.5.4` | `185cb358047fd8b351c1d05b84a7e906c59d68d7f41222805f7042895ae266d8` | BSD-2-Clause; presence in Pillow does not authorize JPX support or G1-B | NOT APPROVED for Grayscale/JPX |
| PDFium binary | pypdfium2 `5.13.0` wheel binary | `pypdfium2_raw/libpdfium.so` | `224f8ece41f7e35891f11c10073b7b7062d7a18e9ef870586162a85c46130f7d` | BSD-style plus full wheel BUILD_LICENSES bundle; retain all third-party notices | NOT APPROVED for Grayscale role |
| libimagequant | Pillow source SBOM lists `4.4.1`, GPL-3.0-or-later, scope `optional` | no matching archive member; no `DT_NEEDED`; no symbol evidence in the tested wheel | no file, so no file hash | The tested wheel/path does not bundle or use it. This is not approval of libimagequant and not a waiver for another Pillow build. | ABSENT FROM THIS CANDIDATE; NOT APPROVED GENERALLY |

Other native members and their hashes are in the machine-readable inventory. Several native libraries have permissive licenses, but license compatibility alone does not approve their parser/codec attack surface or a production role.

## Unified Candidate SBOM scope

The CycloneDX candidate combines:

- 9 exact Python wheel records and 41 native member records with SHA-256;
- 629 non-dev entries from `package-lock.json` as production-lock candidates, with npm source URLs and SHA-512 integrity where available;
- 11 Debian packages explicitly preserved by G0 from the 301-package SPDX artifact.

The Node list is a lockfile candidate set, not proof every optional platform package exists in a Linux image. Node tarball SHA-256 is `NOT VERIFIED`; npm SHA-512 integrity is preserved instead. Debian per-package SHA-256 is `NOT VERIFIED` because the raw 301-package SPDX and `.deb` payloads are not locally available. These limits are explicit properties in the SBOM.

## Risk decision

| Risk | Evidence-based assessment | Required disposition |
| --- | --- | --- |
| MPL obligations and bundled notices | pikepdf is MPL-2.0 and bundles native qpdf/libjpeg notice material | Licensing review of the intended image distribution and notices/source procedure |
| Multiple qpdf identities | pikepdf libqpdf 12.3.2 differs from Debian qpdf/libqpdf 11.3.0 | Security and engineering must approve duplication, patch/CVE policy, and authoritative runtime identity |
| Multiple JPEG implementations | distinct pikepdf and Pillow binaries/versions | Security must approve duplicate codec exposure and patch ownership |
| ICC parsing | LittleCMS is directly exercised by the candidate path | Security review, malformed-profile tests, limits, and vulnerability scan required |
| Optional codec inventory | Pillow carries OpenJPEG, TIFF, WebP, AVIF and other native libraries even if the bounded path does not intend all formats | Prove runtime reachability policy, minimize image if approved, and scan every shipped binary |
| GPL optional component ambiguity | Pillow SBOM mentions libimagequant GPL-3.0-or-later as optional | Candidate wheel absence is proven; future wheel/build must repeat the check and fail closed if present without approval |
| Incomplete base-image proof | full Debian SPDX raw file and immutable OCI digest are absent locally | Rebuild approved candidate, capture complete mixed-layer SBOM and registry digest, then repeat reconciliation |
| Node lock over-approximation | lockfile includes optional platform candidates | Capture actual pruned `/app/node_modules` inventory in the immutable Linux image |

## Required approvals

No checkbox is selected by this record.

- `[ ] Owner`: approve the exact candidate dependency set and accept or reject duplicate qpdf/JPEG implementations; confirm fixture-only packages must remain outside runtime.
- `[ ] Security`: approve parser/codec threat model, vulnerability results, native duplication, ICC handling, and immutable image hardening evidence.
- `[ ] Licensing`: confirm commercial/SaaS and distribution obligations for every direct, transitive, native, Node, and Debian component; approve the notices/source procedure.
- `[ ] Engineering evidence custodian`: reproduce the inventory from the immutable build, attach full SPDX + CycloneDX, and reconcile every shipped file to the OCI registry digest.

## Remaining hard requirements before Gate approval

1. Build the candidate only after dependency-set approval, without changing `Dockerfile.worker` in G1-A/02.
2. Push that candidate through the approved private registry workflow and capture an immutable repository digest; a local image ID is insufficient.
3. Export the complete 301-package Debian SPDX file, actual pruned Node inventory, Python environment inventory, and native filesystem hashes from that same image.
4. Generate and reconcile SPDX and CycloneDX documents so no vendored native library is omitted, especially libqpdf, both libjpeg builds, LittleCMS, PDFium, and Pillow codecs.
5. Produce the complete notices bundle and written source/modification compliance procedure.
6. Run vulnerability scanning against the immutable digest and record remediation or explicit exceptions.
7. Obtain the four approvals above and bind the signed decision to the digest and SBOM hashes.

Until all seven requirements are satisfied, `DIP_GRAYSCALE_LICENSING_GATE_APPROVED` must remain unset/false. Grayscale remains OFF and absent from Registry, Worker, API, UI, Workflow, and Agent surfaces.
