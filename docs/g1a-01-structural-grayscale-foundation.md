# G1-A/01 Structural Grayscale Internal Foundation

Status: internal engineering foundation only. Grayscale is not production-adopted, registered, dispatched, or publicly exposed.

Evidence baseline: repository HEAD `f1a785820234d72c7e2e0723244c4b1278700caa`; approved G0 documentary closure `DIP-OWNER-G0-2026-09-28`; Stage 3C artifact ZIP SHA-256 `96db802a0afa3fec8866a8dfe106fdc3fd75bc7e5561ed1b6005e4d7f1d3af6e`; production-worker Debian SPDX artifact ZIP SHA-256 `f5fa8b1326956309a0bb829fd2da4a0e300a1d75c54b3fd7fb707fc9f046a3a2`.

## Current path review

The Stage 3C implementation remains under `scripts/experiments/` and runs only through its derivative sandbox image and CI orchestration. `Dockerfile.worker` does not install the Stage 3C wheel set or copy the experimental engine. `workers/document-worker.ts` dispatches only the existing PDF, qpdf, Office/OCR, and AI tool sets. `src/config/index.ts` and `src/lib/tools/registry.ts` contain no `grayscale-pdf` definition, and the public API derives eligibility from that Registry and worker allowlist.

Therefore the current path ends at experimental evidence:

`Stage 3C experiment -> no production package -> no worker dispatch -> no Registry entry -> no API/UI/Workflow/Agent exposure`

This G1-A/01 change adds only an internal fail-closed configuration foundation. It does not move or import the experimental transformer.

## Internal feature gate contract

The server/worker-only module `src/lib/grayscale/internal-feature-flag.ts` evaluates two exact runtime values:

- `DIP_INTERNAL_GRAYSCALE_ENABLED=true` requests internal activation.
- `DIP_GRAYSCALE_LICENSING_GATE_APPROVED=true` records the separate licensing approval prerequisite.

Both values must be exactly `true`. Missing values, alternative truthy spellings, or a requested feature without licensing approval remain disabled. Neither variable uses the `NEXT_PUBLIC_` prefix. The module is not imported by the Registry, worker, routes, UI, Workflow, or Agent code. Until a later approved G1-A step adds a production package and dispatch path, even a fully affirmative configuration has no execution effect.

Rollback for this foundation is removal or unset of `DIP_INTERNAL_GRAYSCALE_ENABLED`; default behavior requires no configuration.

## Licensing Gate candidate inventory

The following versions and SHA-256 values are frozen Stage 3C Linux wheel evidence. They are not approved production dependencies and are not added by G1-A/01.

| Component | Exact candidate evidence | Relationship | License evidence | Obligations or review points | Disposition |
| --- | --- | --- | --- | --- | --- |
| pikepdf | `10.13.0.post1`; wheel SHA-256 `365b94f2be7e2857c6cb5445b56dc52dc7417ba9f06c8a4282d9f521cb2d0fb8` | proposed direct transformer parser/writer | MPL-2.0 | retain license/notices; identify and make available source for any distributed modified MPL-covered files; document dynamic/native packaging; review the exact wheel's bundled licenses | NOT APPROVED |
| Pillow | `12.3.0`; wheel SHA-256 `23d27a3e0307ec2244cc51e7287b919aa68d097504ebe19df4e76a98a3eea5bd` | proposed direct JPEG/ICC/pixel runtime | Pillow HPND-style license | retain required copyright/license notice; freeze optional codec features and native linkage; preserve third-party notices | NOT APPROVED |
| lxml | `6.1.3`; wheel SHA-256 `527195c188d7d0af748cd48d220ab8cdc5cb99be3d49ac4d9be7324d8abf9bc0` | pikepdf transitive/native | BSD-3-Clause | retain notice; verify libxml2/libxslt and other exact wheel native components and notices | NOT APPROVED |
| packaging | `26.3`; wheel SHA-256 `d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c` | pikepdf transitive | Apache-2.0 OR BSD-2-Clause | record selected terms and preserve applicable notice | NOT APPROVED |
| charset-normalizer | `3.5.1`; wheel SHA-256 `c7b742bf31c88566b4bb6335a7f393bb322e580b6bb98df7bd0c25e6e3519ce8` | resolved auxiliary/transitive candidate | exact package license and runtime need package-level confirmation | confirm provenance, actual runtime use, license file, and notices | NOT APPROVED |
| pypdf | `6.10.0`; wheel SHA-256 `90005e959e1596c6e6c84c8b0ad383285b3e17011751cedd17f2ce8fcdfc86de` | experimental semantic/appearance validator | BSD-3-Clause | retain notice; validator independence and production need remain separate technical gates | NOT APPROVED for Grayscale production |
| pypdfium2/PDFium | `5.13.0`; wheel SHA-256 `81df25c1ab4c13ff773102d3cbea1967511d079123b067fc077bd0c4d57d91d8` | experimental reference renderer; already pinned for approved OCR use | wrapper Apache-2.0 OR BSD-3-Clause; PDFium BSD-style with third-party inventory | preserve wheel PDFium and third-party license inventory; existing OCR clearance does not approve a new Grayscale role | NOT APPROVED for Grayscale production role |
| reportlab | `4.4.9`; wheel SHA-256 `68e2d103ae8041a37714e8896ec9b79a1c1e911d68c3bd2ea17546568cf17bfd` | fixture generation only | BSD-style | keep outside runtime unless separately justified; retain notice | NOT A PRODUCTION CANDIDATE |
| uharfbuzz | `0.56.2`; wheel SHA-256 `f058d70848312366e82068ebef54ead53269bdf34e893c25a3174ea1f5c6d2d3` | fixture shaping only | wrapper Apache-2.0; bundled HarfBuzz Old MIT | keep outside runtime unless separately justified; preserve both notice sets | NOT A PRODUCTION CANDIDATE |

### Native and embedded components

| Component | Frozen observation | Required gate action | Disposition |
| --- | --- | --- | --- |
| bundled libqpdf in pikepdf | `12.3.2`, file `pikepdf.libs/libqpdf-b00d82b7.so.30.3.2`; distinct from Debian qpdf CLI `11.3.0-1+deb12u1` | record Apache-2.0 notices, provenance, CVEs and exact native hash; prevent identity confusion with the approved CLI path | NOT APPROVED |
| bundled libjpeg in pikepdf | `pikepdf.libs/libjpeg-e87d2658.so.62.2.0` | establish upstream identity/version, license text, native hash, CVEs and notice packaging | NOT APPROVED |
| Pillow libjpeg | exact bundled filename/hash not frozen in the G0 summary | extract from the candidate wheel/image and record provenance, license and CVEs | NOT VERIFIED / NOT APPROVED |
| Pillow LittleCMS | `pillow.libs/liblcms2-dade1fbf.so.2.0.19`; runtime `2.19`; supplemental SBOM `2.19.1` | reconcile version evidence, hash the shipped binary, preserve MIT-style notice, review ICC attack surface | NOT APPROVED |
| Pillow optional native chain | observed `libopenjp2`, `libtiff`, `libxcb`, `libzstd`, `liblzma` and others | enumerate exact files, versions, hashes, dependency edges, licenses, notices and CVEs from the immutable production image | NOT VERIFIED / NOT APPROVED; presence does not approve JPX |
| libimagequant | absent from bundled archives, `DT_NEEDED`, symbols, and runtime feature in the tested wheel/path | repeat the absence check on the exact production candidate; a different build reopens GPL/licensing review | NOT PRESENT IN FROZEN CANDIDATE; no general waiver |

Ghostscript, MuPDF/PyMuPDF, OpenJPEG as a new direct dependency, and jbig2dec remain outside this gate. Ghostscript and MuPDF/PyMuPDF have no approved Grayscale path. OpenJPEG belongs to the later G1-B JPX PoC. Artifex jbig2dec is AGPL-3.0 and requires an independent legal/commercial decision if ever proposed. No G1-B work is authorized by this document.

## Gate approval checklist

The gate remains open until all items are recorded against one immutable production image digest:

- exact direct Python wheels, source URLs, hashes, signatures if available, and selected license terms;
- complete Python dependency graph, Debian/OS packages, Node runtime packages, and every vendored native library with file hashes;
- SPDX and CycloneDX outputs reconciled with wheel inspection and runtime linkage;
- notices bundle and source/modification obligations reviewed for the intended SaaS worker distribution model;
- vulnerability scan and exception record for direct, transitive, and native components;
- confirmation that fixture-only packages are absent from the production runtime;
- security review of parser/codec attack surface and the independent validator design;
- owner, security, and licensing approval record tied to the image digest.

Until that approval exists, `DIP_GRAYSCALE_LICENSING_GATE_APPROVED` must remain unset or false, the internal gate remains disabled, and the Stage 3C engine must remain experimental.

## G1-A/01 verification boundary

Automated tests verify default OFF behavior, exact dual opt-in, Licensing Gate fail-closed behavior, absence of `NEXT_PUBLIC_`, and continued absence of `grayscale-pdf` from the catalog, Registry, and worker dispatcher. They do not claim engine, validator, worker E2E, production image, or public readiness.
