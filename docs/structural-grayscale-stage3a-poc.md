# DIP Structural Grayscale Engine - Stage 3A PoC

## Decision

**Stage 3A passed for the newly bounded structural/image subset, but the logical-order Arabic multi-reader gate did not pass. Production adoption is not approved. Phase 1 remains NOT COMPLETE.**

This is an isolated capability-expansion experiment. It is not referenced by the application, Tool Registry, Job/Worker, Workflow, Agent, Public API, UI, or production image. It does not use MuPDF, PyMuPDF, Ghostscript, AI, or page rasterization.

## Implementation boundary

Stage 3A extends the Stage 2 experiment at runtime through:

- `scripts/experiments/structural-grayscale-stage3a.py` - bounded color, image, fixture, validation, and adversarial logic;
- `scripts/experiments/structural-grayscale-stage3a-browser.mjs` - independent Chromium Arabic source/expected fixture generation plus PDF.js extraction;
- `scripts/experiments/structural-grayscale-stage3a.requirements.txt` - exact disposable Python QA environment.

The implementation remains whole-document fail-closed. It does not silently preserve an unsupported colored object, flatten content, remove an object, or substitute a rendered page.

## Logical-order Arabic result

The Arabic source and expected PDFs were generated independently by Chromium 1243, not by the grayscale transformer. Chromium's Windows font subset emitted visual-order presentation glyph mappings, so the fixture added a separate invisible Type3 search/copy layer with an explicit ToUnicode CMap. The visible shaped Arabic remained untouched.

The source and transformed output were independently read by pypdf 6.10.0, PDFium through pypdfium2 5.13.0, and PDF.js 6.3.289. Unicode comparison used NFKC, removal of extraction-only whitespace, and normalization of common Arabic/Persian glyph variants. It did not reverse text or accept a visual rendering as proof.

| Reader | Source logical phrase | Output logical phrase | Exact finding |
| --- | --- | --- | --- |
| pypdf 6.10.0 | found | found | phrase survives after Unicode compatibility normalization |
| PDF.js 6.3.289 | found | found | phrase survives after removing extractor-inserted inter-character spaces |
| PDFium 5.13.0 | **not found** | **not found** | returns portions of the Arabic string in visual RTL order; full logical query and the word `مرحلة` are not found, while visually reversed `ةلحرم` is found |

The source and output produce the same result in each reader, proving that the grayscale rewrite did not worsen text semantics. It does **not** prove the required cross-reader logical-order behavior. Therefore `arabic_logical_order_gate=false` is recorded in `metrics.json`; the PoC does not convert this failure into a skip.

Visually, the Arabic output matched its independently generated grayscale expected PDF exactly at 893 x 1263 pixels: MAE 0, maximum delta 0, and zero changed pixels. That visual success is explicitly insufficient to close the logical-order gate.

## DCT/JPEG result

Stage 3A supports only a single `/DCTDecode` filter with:

- DeviceRGB, DeviceGray, or an explicit ICCBased RGB profile;
- 8-bit samples decoded by Pillow/libjpeg;
- the existing pixel, decoded-byte, image-count, input/output, object, recursion, and wall-clock budgets;
- no color-key mask and only the already supported DeviceGray soft-mask policy;
- deterministic grayscale conversion through the sRGB policy;
- re-encoding as an 8-bit DeviceGray JPEG while preserving width, height, interpolation, placement, page structure, and image-object semantics.

The tested 48 x 32 ICC RGB JPEG remained `/DCTDecode`, became `/DeviceGray`, preserved dimensions and `/Interpolate true`, reopened successfully, and retained JPEG magic bytes. The output render had no chroma.

The only Stage 3A visual difference against the independently generated expected PDF was the JPEG region:

| Measurement | Whole structural page | JPEG region only |
| --- | ---: | ---: |
| MAE | 0.008362 | 0.422176 |
| Maximum channel delta | 6 | 6 |
| Changed pixels | 8,237 | 8,237 |
| Changed fraction | 0.755283% | 38.134259% |

All differences are low-amplitude and confined to the 180 x 120 rendered JPEG placement. Lab, Separation, ICCBased CMYK, radial shading, the corrected inline-image reference, vectors, Forms, and appearances were pixel-identical to their expected regions. The cause is the unavoidable lossy chain: source RGB JPEG decode, structural color conversion, and a second grayscale JPEG encode versus a separately encoded grayscale expected JPEG.

The proposed Stage 3B visual threshold for this exact controlled JPEG class is:

- output chroma must be zero;
- whole-page MAE <= 0.05;
- per-JPEG-region MAE <= 0.5;
- maximum channel delta <= 8;
- differences must remain inside the original image bounds;
- structure, dimensions, masks, placement, interpolation, links, text, fields, metadata, and syntax must remain unchanged.

This threshold is provisional and requires a larger natural-image corpus at several JPEG quality levels before product approval.

JPX, JBIG2, CCITT, compound filter chains, color-key masks, and unprofiled CMYK JPEGs remain rejected. No support is claimed merely because Pillow contains optional decoders.

## Color-management expansion

| Feature | Stage 3A policy | Result |
| --- | --- | --- |
| Lab content | Validated D50 white point and range; Lab to XYZ, Bradford D50-to-D65 adaptation, then sRGB relative luminance | supported for content operators; expected region pixel-identical |
| Separation | One component, supported alternate space, domain `[0,1]`, one exponential Type 2 tint function | supported for content operators; expected region pixel-identical |
| ICCBased CMYK content | Explicit valid CGATS001 profile; LittleCMS perceptual transform to sRGB, then luminance | supported; expected region pixel-identical |
| Unprofiled CMYK image | no assumed printing condition | rejected |
| DeviceN/NChannel | no safe general multi-component tint/function policy established | rejected |
| Lab Image XObject | sample/decode/range/profile behavior not yet independently covered | rejected |
| Arbitrary Separation tint functions | sampled, PostScript calculator, stitching, and malformed functions unproved | rejected |

The Stage 3A corpus used the existing `pdfjs-dist` `CGATS001Compat-v2-micro.icc` only as a test profile. That does not establish a product default for unprofiled CMYK.

## Transparency, patterns, shadings, and graph behavior

Stage 2 transparency, DeviceGray soft masks, colored tiling patterns, nested/shared Forms, appearance dictionaries, and active-stack cycle rejection remained green. Stage 3A added radial `/ShadingType 3` with one Type 2 function; the output region matched independently calculated grayscale output exactly.

Still rejected:

- mesh shadings and multi-function/stitching shadings;
- uncolored patterns;
- non-gray explicit masks and unproved soft-mask color spaces;
- arbitrary blend/overprint interactions not represented in the corpus;
- DeviceN/NChannel resource graphs.

## Widget editing and appearance regeneration

The transformed file was edited through pypdf with `auto_regenerate=True`, then passed through the whole-document transformer again. The result:

- field value: `Stage 3A regenerated value`;
- `/AP/N`: 3 streams/states;
- `/AP/R`: 3 streams/states;
- `/AP/D`: 3 streams/states;
- total supported appearance entries: 9;
- `/MK/BG` and `/MK/BC`: four arrays, all one-component gray;
- `/DA`: `/Helv 12 Tf 0.331016 g` and `/Helv 0 Tf 0.000000 g`;
- forbidden RGB/CMYK `/DA` operators: 0;
- colored pixels after edit/reprocessing: 0;
- residual supported color operators: 0.

This proves one independently available open-source editing path. Acrobat, Preview, browser viewer editing, XFA, JavaScript calculations, custom font substitution, and other proprietary regeneration paths remain unproved and unsupported.

## Stage 2 render-difference root cause

The Stage 2 difference was reproduced exactly: MAE 0.060903, maximum delta 70, 1,296 changed pixels, bounding box `[165,237,200,272]` at a 918 x 1188 render. The box is exactly the 36 x 36 rendered inline image and every changed pixel was classified as an edge/transition pixel.

The root cause was the Stage 2 expected fixture, not the structural transformer: its four hard-coded grayscale inline samples `[65,150,40,210]` did not implement the stated linear-light sRGB luminance policy. Stage 3A generated the expected samples independently from the policy; the corrected inline-image region then became pixel-identical, MAE 0 and maximum delta 0. The committed Stage 2 engine and completed product tools were not modified.

## Security and fail-closed evidence

Eleven probes were rejected with no partial output:

- JPXDecode;
- JBIG2Decode;
- CCITTFaxDecode;
- DeviceN;
- unprofiled CMYK JPEG;
- cyclic Form graph;
- structural signature marker;
- AES-256 encrypted input without an authorized path;
- malformed PDF;
- Separation using an unsupported Type 4 tint function;
- oversized 4,000,000-pixel JPEG declaration.

The Stage 2 bounds remain active: 4 MB input, 8 MB output, 8 MB aggregate decoded data, 2 MB per decoded stream/JPEG, 1,000,000 pixels per image, 50 images, 2,000 objects, 400 streams, 10 pages, recursion depth 20, and 15 seconds per transformation. Temporary self-test work was cleaned. These are in-process PoC bounds; hard CPU/RAM/tmpfs/process enforcement remains a real-production-worker Stage 3B gate.

## Exact dependency and Linux wheel audit

No project or production dependency was added. The disposable runtime used pikepdf 10.13.0.post1, embedded libqpdf 12.3.2, Pillow 12.3.0, LittleCMS 2.19, lxml 6.1.3, packaging 26.3, reportlab 4.4.9, pypdf 6.10.0, pypdfium2 5.13.0, and uharfbuzz 0.56.2.

The production Dockerfile is Debian Bookworm and installs the distribution `python3`, so Stage 3A separately downloaded and inspected CPython 3.11 manylinux wheels rather than assuming the Windows or CPython 3.12 inventories were representative:

| Exact Linux wheel | SHA-256 | Native/SBOM finding |
| --- | --- | --- |
| `pikepdf-10.13.0.post1-cp311-cp311-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl` | `365b94f2be7e2857c6cb5445b56dc52dc7417ba9f06c8a4282d9f521cb2d0fb8` | `_core.so`, bundled `libqpdf...so.30.3.2`, bundled libjpeg; MPL-2.0 plus notices; auditwheel CycloneDX present |
| `pillow-12.3.0-cp311-cp311-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl` | `23d27a3e0307ec2244cc51e7287b919aa68d097504ebe19df4e76a98a3eea5bd` | `_imagingcms.so`, LittleCMS, libjpeg, OpenJPEG, libtiff, libwebp and other native libraries; two CycloneDX SBOMs present |
| `lxml-6.1.3-cp311-cp311-manylinux_2_26_x86_64.manylinux_2_28_x86_64.whl` | `527195c188d7d0af748cd48d220ab8cdc5cb99be3d49ac4d9be7324d8abf9bc0` | native lxml extensions; BSD-3-Clause notices; no wheel SBOM |
| `uharfbuzz-0.56.2-cp310-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl` | `f058d70848312366e82068ebef54ead53269bdf34e893c25a3174ea1f5c6d2d3` | two native HarfBuzz extensions; Apache-2.0 wheel license; no wheel SBOM; fixture-only |

The manylinux 2.28 wheels are ABI-compatible with Bookworm's newer glibc baseline, but they were not installed or executed inside the production image.

Two supply-chain findings remain gates:

1. Pikepdf's auditwheel CycloneDX lists pikepdf and libjpeg-turbo but omits the visibly bundled `libqpdf...so.30.3.2`. License files cover qpdf, but the SBOM is not complete enough for production inventory by itself.
2. Pillow's full CycloneDX lists Little CMS 2.19.1 under MIT as expected, but also lists `libimagequant` 4.4.1 under GPL-3.0-or-later among its build/runtime inventory. The wheel listing does not expose a separate libimagequant shared object, so static inclusion/feature activation and resulting obligations must be established in the exact Linux image. This is a **LICENSING GATE**, not an automatic rejection or approval.

MPL-2.0 pikepdf direct use, notices/source obligations for any modified covered files, bundled libqpdf 12.3.2 alongside the controlled qpdf 11.3 CLI, and the complete native CVE/SBOM chain still require owner/legal/security approval. Indirect installation through OCRmyPDF is not direct-use approval.

## Unsupported-feature matrix

| Feature | Status | Reason |
| --- | --- | --- |
| Logical Arabic in pypdf/PDF.js | PoC-supported | independently found before and after transform after non-semantic Unicode/spacing normalization |
| Logical Arabic in PDFium | **blocked** | PDFium extraction/search returns visual RTL order for part of the independent fixture |
| RGB/ICC RGB DCT JPEG | PoC-supported | decoded, transformed, re-encoded, structurally and visually measured |
| JPX/JBIG2/CCITT/compound filters | rejected | separate decoder/security/semantics work required |
| ICCBased CMYK content | PoC-supported | explicit profile only |
| Unprofiled CMYK image | rejected | no defensible assumed print condition |
| Lab content | PoC-supported subset | D50/range policy only |
| Separation | PoC-supported subset | one Type 2 tint function and supported alternate space only |
| DeviceN/NChannel | rejected | multidimensional tint/functions and ink semantics unproved |
| Radial shading | PoC-supported subset | one Type 2 function only |
| Mesh/multi-function shading | rejected | unproved functions and color interpolation |
| Field regeneration through pypdf | PoC-supported | all nine N/R/D states remained gray after reprocessing |
| Proprietary/external regeneration | blocked | no independently controlled automation/evidence |
| Signed/encrypted/XFA/JavaScript | rejected | integrity, secret path, and dynamic-appearance policies unchanged |

## Stage 3B readiness criteria

Stage 3B should not start production integration. Its entry gate should require:

1. Resolve the PDFium logical-order Arabic failure using a standards-conformant independent fixture and actual search/copy behavior in Chromium PDF viewer, PDF.js, PDFium, and at least one desktop reader. Do not accept visual-order normalization or text reversal in the product.
2. Approve or replace the exact direct pikepdf/Pillow/Linux wheel chain, close the incomplete pikepdf SBOM issue, and resolve Pillow's libimagequant GPL inventory finding.
3. Execute the exact CPython 3.11 wheels inside the production non-root, read-only-root, bounded-tmpfs worker with hard CPU/RAM/time/process limits and Ghostscript absence verification.
4. Run a larger natural-image JPEG corpus covering quality levels, subsampling, ICC/no-ICC RGB, masks, malformed streams, decompression attacks, metadata, and repeated decode/re-encode quality; ratify or revise the proposed thresholds.
5. Keep JPX, JBIG2, CCITT, DeviceN, unprofiled CMYK, complex masks, uncolored patterns, mesh/multi-function shadings, XFA, signed, encrypted, and dynamic appearances fail-closed until separate gates pass.
6. Add real-reader appearance editing/regeneration evidence without changing field identity/type/value or losing custom appearances.
7. Expand fuzzing, shared-object bombs, object streams, incremental updates, malformed resources, metadata/outlines/optional-content preservation, and cancellation/cleanup tests.

Until those criteria pass and an explicit production Change Request is approved, Grayscale remains a **CAPABILITY/PoC BLOCKER**, **LICENSING GATE**, and **ENVIRONMENT-GATED TEST** item.
