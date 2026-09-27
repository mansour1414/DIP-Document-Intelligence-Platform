# DIP Structural Grayscale Engine - Stage 3B Readiness Gate

## Decision

Stage 3B resolved the Arabic regression attribution and the Pillow/libimagequant ambiguity for the exact inspected Linux wheel. It also generated a supplemental libqpdf inventory and passed the expanded JPEG, appearance-color, and mutation tests.

Production adoption is still not approved because the isolated PoC could not be executed inside the production container sandbox on this host. Arabic appearance regeneration with the fixture's Helvetica font also cannot represent Arabic glyphs safely. Phase 1 remains NOT COMPLETE.

This experiment did not expand the Stage 3A supported PDF feature set. It is not connected to the Tool Registry, Job/Worker, Workflow, Agent, Public API, UI, production Dockerfile, or CI. It does not use MuPDF, PyMuPDF, Ghostscript, AI, or page rasterization.

## Inputs reviewed

- MASTER BASELINE and the approved Prelaunch Expansion Plan;
- Stage 1, Stage 2, and Stage 3A reports and experiment code;
- Phase 1 capability audit;
- `Dockerfile.worker`, worker runtime documentation, and the production-worker CI sandbox gates;
- exact CPython 3.11 Linux wheels for pikepdf 10.13.0.post1, Pillow 12.3.0, and lxml 6.1.3.

## Arabic attribution result

Two independent fixture paths were evaluated:

1. The Stage 3A Chromium fixture with an explicit logical search/copy layer and ToUnicode mapping.
2. A separate ReportLab/Arial Unicode fixture used only to test logical-order behavior, not shaping fidelity.

For each fixture, source and transformed PDFs were read by pypdf 6.10.0, PDF.js 6.3.289, and PDFium 5.13.0. The source and output result was identical for every reader. No reader changed from pass to fail or fail to pass after transformation.

### Chromium fixture

| Reader | Source | Output | Regression |
| --- | --- | --- | --- |
| pypdf | logical phrase found | logical phrase found | no |
| PDF.js | logical phrase found | logical phrase found | no |
| PDFium extraction | logical phrase not found | logical phrase not found | no |
| PDFium search API, `مرحلة` | 0 matches | 0 matches | no |
| PDFium search API, visual-order `ةلحرم` | 1 match at character 102, length 5 | same match | no |

### ReportLab fixture

All three readers expose visual-order Arabic for the fixture before transformation. PDFium actual search finds the visual-order word at character 0 and does not find the logical-order word, identically in source and output.

### Finding

The PDFium result is an existing source-fixture/reader interaction, not a grayscale transformation regression. The engine preserves the original PDF text objects and ToUnicode data. Reversing or rewriting text solely to satisfy PDFium would alter semantics for pypdf/PDF.js and is explicitly rejected.

Actual PDFium search was exercised through its native search API. PDF.js and pypdf copy/search equivalence was evaluated through their extracted Unicode text. Direct Chrome PDF-viewer UI automation against a local `file:` PDF was unavailable because the browser automation security policy disallows local-file navigation; this was not bypassed.

## Linux wheel and SBOM findings

The isolated environment used the following exact package set. The auxiliary
packages remain fixture/validation-only and are not proposed as production
runtime dependencies.

| Package | Exact version | Stage 3B role | License finding |
| --- | --- | --- | --- |
| pikepdf | 10.13.0.post1 | structural parser/writer and token filtering | MPL-2.0; direct adoption remains gated |
| Pillow | 12.3.0 | JPEG decode/encode, pixel checks, and LittleCMS binding | HPND-style Pillow license; native feature inventory described below |
| lxml | 6.1.3 | pikepdf dependency | BSD-3-Clause; native extensions, no wheel SBOM observed in the prior exact-wheel audit |
| packaging | 26.3 | pikepdf dependency | Apache-2.0 OR BSD-2-Clause |
| reportlab | 4.4.9 | independent fixture generation only | BSD |
| pypdf | 6.10.0 | independent structure/text and appearance-regeneration validation only | BSD-3-Clause |
| pypdfium2/PDFium | 5.13.0 | independent rendering, extraction, and actual search validation only | BSD-3-Clause/Apache-2.0 plus bundled PDFium notices |
| uharfbuzz/HarfBuzz | 0.56.2 | Arabic fixture shaping only | Apache-2.0 binding; bundled HarfBuzz uses the Old MIT license |
| PDF.js | 6.3.289 | independent text extraction using the repository's existing JavaScript stack | Apache-2.0 |

This table records the experimentally used versions and upstream license
identities; it is not legal approval. Native linkage evidence was collected
for the pikepdf and Pillow Linux wheels because those are the proposed runtime
components. The remaining packages are test-only in Stage 3B.

### Pikepdf/libqpdf

Exact wheel:

`pikepdf-10.13.0.post1-cp311-cp311-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`

SHA-256:

`365b94f2be7e2857c6cb5445b56dc52dc7417ba9f06c8a4282d9f521cb2d0fb8`

Verified native contents:

- `pikepdf/_core.cpython-311-x86_64-linux-gnu.so`;
- `pikepdf.libs/libqpdf-b00d82b7.so.30.3.2` - libqpdf 12.3.2;
- `pikepdf.libs/libjpeg-e87d2658.so.62.2.0`.

ELF `DT_NEEDED` proves `_core` dynamically loads the bundled libqpdf. The bundled libqpdf in turn loads the bundled libjpeg plus libc, libgcc, libm, libstdc++, and zlib.

The wheel's auditwheel CycloneDX contains pikepdf and libjpeg-turbo but omits libqpdf. That omission is confirmed, not assumed. Stage 3B generated `supplemental-sbom.cdx.json` with pikepdf, libqpdf 12.3.2, Pillow, and LittleCMS dependencies and explicit evidence paths. This closes the experimental inventory gap, but a production SBOM must still merge operating-system packages and all application/runtime dependencies.

Pikepdf remains MPL-2.0 and libqpdf is Apache-2.0. No legal approval is claimed.

### Pillow/libimagequant

Exact wheel:

`pillow-12.3.0-cp311-cp311-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`

SHA-256:

`23d27a3e0307ec2244cc51e7287b919aa68d097504ebe19df4e76a98a3eea5bd`

Evidence:

- The wheel contains no libimagequant shared library or archive member.
- `_imaging.so` has no `DT_NEEDED` entry for libimagequant.
- No `liq_*` symbol strings were found in `_imaging.so`.
- Pillow's full SBOM labels libimagequant 4.4.1 as optional, not as an included shared object.
- Pillow's official wheel build configuration sets `imagequant=disable` and its build documentation says official binaries are not distributed with libimagequant enabled because of GPLv3.
- The grayscale path never calls `Image.quantize` or `Quantize.LIBIMAGEQUANT`. It uses libjpeg decode, ImageCms/LittleCMS conversion where needed, RGB-to-L conversion, and libjpeg encode.

Conclusion for this exact wheel: libimagequant is neither bundled as a file, dynamically linked, evidenced as statically linked, nor invoked by the Stage 3B execution path. Its SBOM entry describes an optional source capability. This removes the earlier technical GPL linkage concern for this wheel, but exact-wheel pinning and owner/legal review remain required.

LittleCMS is dynamically loaded by `_imagingcms.so` as `liblcms2-dade1fbf.so.2.0.19`; Pillow's full SBOM records LittleCMS 2.19.1 under MIT.

### Licensing-safe proposed configuration

If production adoption is approved later:

1. pin the exact pikepdf and Pillow Linux wheels by version and SHA-256;
2. require runtime assertions that pikepdf reports libqpdf 12.3.2 and Pillow reports no libimagequant support;
3. retain Pillow's official `imagequant=disable` wheel policy, or build an internally reproducible wheel with `-C imagequant=disable -C lcms=enable -C jpeg=enable`;
4. merge the supplemental libqpdf component into the production CycloneDX/SPDX inventory;
5. preserve MPL notices and source-offer obligations for any modified MPL-covered pikepdf files;
6. track the embedded libqpdf separately from the approved qpdf 11.3.0 CLI;
7. require legal/security approval before direct production use.

## Production sandbox gate

The existing production architecture already defines:

- UID/GID `10001:10001`;
- read-only root filesystem;
- `/tmp` tmpfs 64 MB;
- `/tmp/dip` tmpfs 256 MB owned by UID/GID 10001;
- non-root execution;
- qpdf 11.3.0-1+deb12u1;
- fail-closed Ghostscript absence checks.

Stage 3B added an isolated derivative Dockerfile and reproduction script that additionally requests:

- `--network none`;
- `--cpus 1`;
- `--memory 768m --memory-swap 768m`;
- `--pids-limit 128`;
- a 180-second external timeout and 5-second kill grace;
- exact pip freeze and ELF `ldd` inventory;
- temporary-output cleanup and final PDF validation.

Docker, Podman, nerdctl, and an installed WSL distribution are unavailable on this host. Therefore the derivative was not executed. The scripts are implemented but the production sandbox gate remains an ENVIRONMENT-GATED TEST. No claim is made that local Windows execution proves Linux sandbox behavior.

## JPEG validation

The corpus contains nine independently generated naturalistic images:

- three scene classes;
- source JPEG qualities 55, 72, and 92;
- 4:2:0, 4:2:2, and 4:4:4 subsampling;
- 360 x 240 pixels each;
- three PDF pages.

The expected PDF is generated independently by decoding each source JPEG, applying the documented linear-light sRGB grayscale policy, and encoding the expected grayscale JPEG at the same Stage 3A output quality. The transformer does not create the expected fixture.

Results:

| Renderer | Pages | MAE | Maximum delta | Changed pixels |
| --- | ---: | ---: | ---: | ---: |
| PDFium 5.13.0 | 3 | 0 on every page | 0 | 0 |
| Poppler | 3 | 0 on every page | 0 | 0 |

Text snapshots were equal before and after transformation. The output had zero chroma and all three PDFs reopened successfully. These are deterministic synthetic naturalistic fixtures, not a substitute for a licensed camera-photo corpus; real photographic diversity remains recommended before product release.

## Appearance regeneration

Four values were tested through pypdf `auto_regenerate=True`, followed by whole-document grayscale processing:

- English;
- Arabic;
- mixed Arabic/English/numeric/email;
- empty.

For all four, the canonical field value survived, all nine `/AP/N`, `/AP/R`, and `/AP/D` entries remained present, `/MK` arrays remained one-component gray, `/DA` contained no RGB/CMYK operator, colored pixels were zero, and residual color operators were zero.

The fixture uses Helvetica for its appearance font. Pypdf explicitly warns that Helvetica cannot encode the Arabic values. Therefore Arabic and mixed-value appearance glyph fidelity did not pass even though field semantics and grayscale color policy passed. A production policy must preserve an existing Unicode-capable appearance font or reject appearance regeneration when the field font cannot represent the value.

## Hostile-input and bounded mutation results

Twelve deterministic mutation probes ran in separate processes with a 20-second outer timeout and the engine's 15-second internal deadline:

- 7 rejected safely;
- 5 remained parseable and were transformed, reopened, and independently validated as grayscale;
- 0 timeouts;
- 0 partial outputs.

The rejected cases covered truncation and a corrupted JPEG stream. This is bounded mutation testing, not comprehensive fuzzing. Coverage-guided Linux fuzzing under cgroup limits remains a pre-production security requirement.

## Proposed production Change Request

**Title:** Approve a production-sandbox validation run for the bounded DIP Structural Grayscale Engine.

Approval requested only for the next gate, not production release:

1. allow the isolated derivative to run in CI using the exact production-worker base image;
2. pin pikepdf 10.13.0.post1 and Pillow 12.3.0 by wheel SHA-256 in the derivative only;
3. merge and publish the supplemental libqpdf CycloneDX inventory;
4. assert libimagequant is absent and disabled at runtime;
5. run with UID/GID 10001, read-only root, bounded tmpfs, no network, CPU/RAM/PID limits, and external timeout;
6. retain every Stage 3A unsupported feature as fail-closed;
7. add a Unicode-capable form-appearance fixture or explicitly reject regeneration where the field font cannot encode the new value;
8. run a licensed natural-photo corpus plus coverage-guided malformed-input tests;
9. require separate owner/legal/security approval before production Tool Registry or API integration.

## Remaining blockers

- **ENVIRONMENT-GATED TEST:** the Stage 3B derivative has not run in the actual Linux production sandbox.
- **SECURITY GATE:** coverage-guided fuzzing and hard cgroup enforcement must be observed in CI.
- **CAPABILITY/PoC BLOCKER:** Arabic/mixed widget appearance regeneration is not visually reliable with a non-Unicode fixture font.
- **LICENSING GATE:** technical wheel linkage is resolved, but direct pikepdf/Pillow adoption and MPL obligations still need owner/legal approval.
- **CHANGE REQUEST REQUIRED:** no production dependency, worker, registry, UI, Workflow, Agent, or API integration is authorized.

Phase 1 remains NOT COMPLETE.
