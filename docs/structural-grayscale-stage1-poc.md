# DIP Structural Grayscale Engine — Stage 1 PoC

**Status:** isolated experiment only; not production-integrated; Phase 1 remains **NOT COMPLETE**.

## Decision context and independence boundary

This experiment follows the MASTER BASELINE and approved Prelaunch Expansion Plan: the modular monolith, Tool Registry/Job/Worker contracts, worker sandbox, output validation, Arabic/English obligations, licensing registry, and Change Request gates remain unchanged. The experiment does not register a tool, add a route, alter a worker image, or modify an application dependency manifest.

The implementation was written from ISO 32000 operator semantics and the public pikepdf/qpdf APIs. It does not copy, translate, or adapt MuPDF code. MuPDF, PyMuPDF, Ghostscript, and their binaries are not imported or invoked. The earlier MuPDF experiments were used only as historical evidence of the product problem and were not implementation references.

## Proposed engine architecture

The production design should be a bounded transformation pipeline with explicit capability negotiation:

1. **Admission and policy:** verify magic/MIME/size, reject signed documents, route encrypted inputs only through an authorized secret-bearing path, scan for malware, and establish page/object/stream/decoded-byte/time/memory/temp budgets.
2. **Object graph walker:** traverse indirect objects with identity-based cycle detection and a depth bound. Build a work list for pages, Form XObjects, images, annotations, widgets, appearance states, patterns, shadings, and resources without mutating the source.
3. **Color policy and color-management adapter:** normalize calibrated spaces through a pinned ICC engine. DeviceRGB and DeviceCMYK require an explicit assumed/source profile policy; they are not intrinsically colorimetric. The adapter must be independent of the PDF token transformer.
4. **Content-stream transformer:** tokenize without reconstructing unrelated instructions. Transform color-setting operators and recursively transform referenced Forms/resources. Unsupported operators or malformed operand stacks fail the document before persistence.
5. **Image transformer:** decode only explicitly supported filters/color spaces under pixel and decompression budgets; transform samples/profile; preserve masks, soft masks, decode arrays, interpolation and geometry; re-encode deterministically. Unsupported filters fail closed.
6. **Appearance transformer:** process `/AP/N`, `/AP/R`, `/AP/D` direct streams and appearance-state dictionaries; transform `/MK/BG`, `/MK/BC`, `/DA`, inherited field attributes, and nested resources without changing field identity/type/value.
7. **Writer:** save to a private temporary output, never in place, with deterministic policy and no partial result on failure.
8. **Independent validator:** reopen, run syntax checks, compare page/order/geometry/text/link/annotation/form invariants, scan transformed resources for residual color, render with an independent renderer, enforce output budgets, and persist only after success.

The Stage 1 script implements only a deliberately small slice of modules 1, 4, 6, 7 and 8. It does not establish production readiness for the full architecture.

## Exact experimental implementation

The isolated script is `scripts/experiments/structural-grayscale-stage1.py`; its disposable exact environment is recorded in `scripts/experiments/structural-grayscale-stage1.requirements.txt`. Neither file is referenced by the application or worker. Its source fixture and expected grayscale fixture are generated independently with ReportLab; the expected fixture does not pass through the transformer. The fixture contains searchable vector text, an RGB-filled/CMYK-stroked vector rectangle, and a colored AcroForm text widget with a stable name, type, and value.

Reproduction uses a fresh virtual environment, installs only that requirements file, then runs `python scripts/experiments/structural-grayscale-stage1.py --self-test --output-dir <temporary-directory>`. Generated PDFs and renders are temporary QA evidence and are not production fixtures or application assets.

The transformer uses `pikepdf.TokenFilter`, not `parse_content_stream`/`unparse_content_stream`. It replaces only the ISO 32000 DeviceRGB `rg/RG` and DeviceCMYK `k/K` convenience instructions with DeviceGray `g/G`; existing `g/G` is normalized. It separately transforms the widget's direct `/AP/N` Form stream, `/MK/BG`, `/MK/BC`, the widget `/DA`, and AcroForm `/DA`. All unrelated tokens and PDF objects remain structural PDF content.

Stage 1 assumes sRGB for DeviceRGB and computes relative luminance after transfer-function linearization. Its DeviceCMYK formula is explicitly provisional: `RGB = (1-C/M/Y) × (1-K)`, then the same luminance calculation. This is not acceptable as the final arbitrary-DeviceCMYK policy because Device spaces do not carry complete colorimetry.

### Enforced PoC limits

- input: 1,000,000 bytes;
- output: 2,000,000 bytes;
- pages: 10;
- indirect objects: 500;
- streams: 100;
- decoded bytes per transformed stream: 2,000,000;
- object traversal depth: 16, with indirect-object cycle detection;
- elapsed transformation budget: 10 seconds;
- private temporary directory and deletion after the test.

The PoC does not provide a hard OS-level memory/CPU kill boundary on Windows. The decoded/object/input budgets constrain its tested allocation surface, but production still requires the existing non-root container limits, read-only root, bounded tmpfs, external watchdog, and hard RAM/CPU controls. This is an open security gate, not an implied production guarantee.

## Measured result

Run date: 2026-09-26. The self-test completed successfully.

| Measurement | Result |
| --- | --- |
| Pages reopened | 1/1 |
| Searchable text | exact match before/after |
| Field identity/type/value | `customer_note`, `/Tx`, `Preserved field value` preserved |
| RGB/CMYK/widget-related instructions transformed | 12 |
| Source maximum channel delta | 204 |
| Output maximum channel delta | 0 |
| Colored output pixels (`max(R,G,B)-min(R,G,B)>1`) | 0 |
| Expected-fixture maximum channel delta | 0 |
| Output vs independently generated expected fixture MAE | 0.0 |
| Output vs expected maximum pixel delta | 0 |
| Transform elapsed time | 15 ms |
| Reopen/syntax validation | passed |
| Fail-closed probes | unsupported color space, signed marker, AES-256 encrypted input, truncated input all rejected without output |
| Temporary cleanup | passed |

The rendered source, output, and expected fixture were visually inspected. The output and independent expected render were pixel-identical for this fixture. This is evidence for the narrow Stage 1 subset only.

## Dependency and license assessment

The packages were installed only in a disposable experiment virtual environment; no project or production dependency was added.

| Component | Exact tested version | Role | License / binary facts | SaaS assessment |
| --- | --- | --- | --- | --- |
| pikepdf | 10.13.0.post1 | structural PDF access and token filter | MPL-2.0; direct deps `Pillow>=10.0.1`, `lxml>=4.8`, `packaging`; Windows wheel contained native `_core`, qpdf DLL and MSVC runtime | generally compatible with proprietary SaaS when MPL-covered modifications and notices/source obligations are honored; direct adoption still needs owner/license/SBOM approval |
| embedded libqpdf | 12.3.2 | parser/writer used in-process by pikepdf | Apache-2.0; separate from production CLI qpdf 11.3.0-1+deb12u1 | permissive, but creates a second exact qpdf runtime that must be explicitly approved and vulnerability tracked |
| Pillow / ImageCms | 12.3.0 | candidate Python adapter and test image metrics | HPND-style Pillow license; tested ImageCms reports LittleCMS 2.19 | permissive; direct color-management use and wheel-native SBOM need approval |
| LittleCMS | 2.19 (reported at runtime) | candidate ICC v2/v4 conversion engine | MIT; reached through Pillow `_imagingcms`; optional LittleCMS GPL/commercial plugins were not installed or evaluated for adoption | core library is commercially permissive; exact linkage and binary inventory must be proven in the target Linux wheel/image |
| lxml | 6.1.3 | pikepdf direct dependency | BSD-3-Clause; native extension | permissive, native/SBOM tracking required |
| packaging | 26.3 | pikepdf direct dependency | Apache-2.0 or BSD-2-Clause upstream | permissive |
| ReportLab | 4.4.9 | fixture generation only | BSD | test-only |
| pypdf | 6.10.0 | independent semantic validation only | BSD-3-Clause | test-only |
| pypdfium2/PDFium | 5.13.0 | independent visual validation only | BSD-3-Clause / Apache-2.0 plus dependency notices | already approved elsewhere for rendering; test-only here |

The pikepdf Windows wheel also recorded libjpeg-turbo (IJG/BSD/Zlib), OpenSSL 3.6.0 and zlib 1.3.1 statically in the qpdf DLL, plus the Microsoft distributable runtime. Its wheel includes license notices. The wheel documentation states Linux wheels carry a CycloneDX SBOM; this Windows wheel did not establish the exact production Linux inventory. OCRmyPDF 17.10.0 already declares `pikepdf>=10`, but indirect installation does not approve direct use and does not pin the exact pikepdf wheel. A production Change Request must pin and inventory the exact Linux artifacts rather than infer them from this Windows experiment.

LittleCMS core is the leading candidate for ICC transforms because it is a dedicated ICC v2/v4 engine under MIT. Stage 1 verified only that Pillow's ImageCms binding loads LittleCMS 2.19; it did not test ICC conversion accuracy. No LittleCMS plugin is proposed because the separately licensed plugins introduce GPL/commercial terms.

## Unsupported features and fail-closed policy

Stage 1 rejects rather than transforms:

- `CS/cs`, `SC/sc`, `SCN/scn`, ICCBased, CalRGB/CalGray, Lab, Indexed, Separation, DeviceN and Pattern color spaces;
- shadings, patterns, inline images, embedded image XObjects, masks/soft masks, transparency groups and blend-mode interactions;
- page Form XObjects and nested resource dictionaries (the production design reserves a bounded recursive module, but it is intentionally absent here);
- `/AP/R` and `/AP/D`, appearance-state dictionaries, non-text widgets, inherited field trees, XFA and appearance regeneration;
- signed PDFs, encrypted PDFs, malformed PDFs, and any annotation other than the one tested text widget;
- correct ICC profile selection, black-point compensation, rendering intents, spot-color policy and overprint behavior.

Changing a field value or regenerating an appearance was not exercised by this independent Stage 1 PoC. The previous experiment showed why `/DA` and `/MK` must be converted, but a production engine still needs multi-viewer tests proving that regeneration cannot reintroduce color for every supported field type. Until then, this remains unsupported.

## Comparison with the previous MuPDF PoCs

The previous broad MuPDF PoC covered more real PDF features but failed the widget-appearance case until pikepdf explicitly transformed `/AP`, `/MK`, and `/DA`; it also remained blocked by MuPDF licensing. This Stage 1 PoC removes MuPDF entirely and proves that direct token-level transformation can preserve the tested content and widget semantics. It is much narrower: it does not yet handle images, ICC, transparency, patterns, shadings, nested Forms, general annotations, or field regeneration. Therefore it removes one architectural uncertainty but does not close the Grayscale capability gate.

## Estimated implementation effort

Assuming two experienced PDF engineers plus security/QA support:

- core traversal, token transformation, cycle/limit framework: 3–5 engineer-weeks;
- ICC policy and LittleCMS adapter with measured reference corpus: 2–4 weeks;
- image/filter/mask pipeline: 4–7 weeks;
- Form XObjects, patterns/shadings/transparency: 4–8 weeks;
- annotations/widgets/AP states, regeneration and signed/encrypted policies: 3–6 weeks;
- adversarial corpus, cross-renderer visual validation, fuzzing, sandbox/SBOM/CI and production integration: 5–8 weeks.

These workstreams overlap, but the realistic elapsed estimate is **12–20 weeks** for two engineers before product acceptance, with higher risk around spot colors, transparency, malformed PDFs, image filters and cross-viewer form appearances. This is an engineering estimate, not a commitment.

## Proposed Change Request

**CR title:** Approve development of the DIP-owned Structural Grayscale Engine beyond Stage 1.

Owner approval is requested for a gated Stage 2, not production release:

1. approve direct, pinned production evaluation of pikepdf 10.13.0.post1 (or a separately reviewed exact version), acknowledging its embedded libqpdf runtime is distinct from the qpdf 11.3 CLI;
2. approve LittleCMS core through a pinned, SBOM-verified binding after Linux-image linkage and license verification; do not approve GPL/commercial LittleCMS plugins;
3. approve an explicit color policy for uncalibrated DeviceRGB/DeviceCMYK and output ICC profile/rendering intent;
4. fund the bounded recursive Form/image/color-space modules and hostile/cross-viewer corpus above;
5. keep signed inputs rejected and encrypted inputs outside the non-secret tool until separately authorized;
6. require fail-closed behavior for every unsupported filter/color space/operator and retain all current sandbox/output-validation gates;
7. prohibit production registration until structural, visual, security, license/SBOM, Arabic/English, forms, links, annotation, image, ICC, transparency and performance acceptance suites pass.

**Recommendation:** approve Stage 2 investigation only. Do not approve production Grayscale yet. Phase 1 remains **NOT COMPLETE**.

## Primary references

- Adobe, *PDF 32000-1:2008* (ISO 32000-1), color-space and color-operator semantics: <https://opensource.adobe.com/dc-acrobat-sdk-docs/standards/pdfstandards/pdf/PDF32000_2008.pdf>
- pikepdf content-stream guidance and token-filter API: <https://pikepdf.readthedocs.io/en/latest/topics/content_streams.html>
- pikepdf filter API: <https://pikepdf.readthedocs.io/en/latest/api/filters.html>
- pikepdf 10.13.0.post1 package metadata: <https://pypi.org/project/pikepdf/10.13.0.post1/>
- Mozilla MPL 2.0 FAQ: <https://www.mozilla.org/en-US/MPL/2.0/FAQ/>
- LittleCMS upstream repository and MIT license: <https://github.com/mm2/Little-CMS>
- LittleCMS 2.18 technical tutorial (ICC architecture): <https://www.littlecms.com/LittleCMS2.18%20tutorial.pdf>

