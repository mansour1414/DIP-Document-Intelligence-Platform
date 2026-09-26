# Grayscale PDF independent technical PoC

## Status

This PoC is experimental evidence only. It does not register or expose a Grayscale tool and does not approve a production dependency. Phase 1 remains incomplete.

## Confirmed root cause

MuPDF 1.28.2 recolors page content, nested page Form XObjects, images, patterns, shadings, and some annotation appearances, but it does not consistently recolor every AcroForm appearance or the form color defaults. In the fixture, `/AP/N` and `/AP/R`, `/MK/BG`, `/MK/BC`, and `/DA` retained color after `Document.recolor(1)`. A conforming viewer therefore continued to render a colored widget even though the page content itself was grayscale.

## Experimental approach

The isolated PoC used:

- PyMuPDF/MuPDF 1.28.2 for semantic recoloring, rendering, text extraction, and reopen validation.
- pikepdf 10.13.0.post1 for structural traversal and replacement of widget `/AP/N`, `/AP/R`, and `/AP/D`, including appearance-state dictionaries.
- The pikepdf wheel's embedded libqpdf 12.3.2. This is not the production system qpdf executable, which remains pinned at Debian `qpdf=11.3.0-1+deb12u1`.
- Pillow 12.3.0, lxml 6.1.3, and packaging 26.3 as the direct Python dependencies resolved by pikepdf for the Windows PoC.

The page was first recolored normally. Each remaining widget appearance Form XObject was then copied into a temporary carrier PDF page, recolored by MuPDF, copied back through pikepdf, and replaced at its original appearance key. The experiment handled direct streams and `/AP/N` appearance-state dictionaries. `/MK/BG` and `/MK/BC` arrays were converted to one-component gray values, and RGB/CMYK color operators in `/DA` were replaced with gray operators. Unsupported `/DA` color operators fail closed in the prototype.

## Fixture coverage

The one-page synthetic fixture contained searchable English and Arabic text, RGB text and vectors, a CMYK vector, an RGB image with an sRGB ICC profile, transparency, an axial RGB shading, a colored tiling pattern, nested Form XObjects with their own resource dictionaries, a URI link, a text annotation, a text field, and a checkbox with `/Off` and `/Yes` appearance states. Both widgets supplied normal, rollover, and down appearances.

The prototype also generated malformed, encrypted, and structural signature-marker inputs for fail-closed checks. The signature marker verifies preflight detection of `/Sig` and `/ByteRange`; it is not a substitute for a corpus of cryptographically signed PDFs.

## Measured result

| Measurement | Source | MuPDF page recolor only | Page plus appearance processing | After editing text field |
| --- | ---: | ---: | ---: | ---: |
| Visible colored pixels | 148,405 | 29,187 | 0 | 0 |
| Maximum RGB channel delta | 255 | 217 | 1 | 1 |
| RGB content operators | 18 | 9 | 0 | 0 |
| CMYK content operators | 1 | 0 | 0 | 0 |
| Gray content operators | 2 | 12 | 24 | 22 |
| ICC RGB profiles | 1 | 0 | 0 | 0 |
| ICC Gray profiles | 0 | 1 | 1 | 1 |

Every generated PDF reopened and passed pikepdf `check_pdf_syntax()` with no reported issues. Page count, outline, title metadata, extracted English and Arabic text, URI link, annotation content, widget names/types/values, image count, drawing count, geometry, rotation, and measured drawing opacity were unchanged between the source and final output.

All tested widget appearances became grayscale:

- Text `/AP/N`: 25,245 colored pixels to 0.
- Text `/AP/R`: 29,025 colored pixels to 0.
- Text `/AP/D`: already recolored by the initial MuPDF pass and remained at 0.
- Checkbox `/AP/N/Yes`: 19,998 colored pixels to 0.
- Checkbox `/AP/R`: 29,025 colored pixels to 0.
- Checkbox `/AP/D`: 29,025 colored pixels to 0.

The text field value was changed from `Original value` to `Changed value` and its appearance regenerated. `/MK` remained one-component gray, `/DA` remained a gray `g` operator, `/AP/N`, `/AP/R`, and `/AP/D` remained present, and the rendered result still contained zero colored pixels. This verifies the tested PyMuPDF regeneration path only; it does not prove identical behavior in every external PDF viewer/editor.

Unauthorized encrypted input failed without a password, the truncated malformed input failed to open, and the structural signature marker was rejected by preflight.

## Supported only by this PoC

The experiment provides positive evidence for RGB and CMYK page operators, RGB ICC-based images converted to a gray ICC profile, ordinary embedded images, searchable text, vectors, simple transparency, axial shading, colored tiling patterns, nested Form XObjects, direct widget appearances, appearance-state dictionaries, text annotations, URI links, text fields, and checkboxes.

These are PoC-supported cases, not a production support declaration. The corpus is synthetic and single-page; it is not yet the required hostile and real-world golden corpus.

## Not yet proven or intentionally unsupported

- XFA and dynamic forms.
- JavaScript actions or calculations that generate a new colored appearance at view time.
- Cryptographically signed PDFs and incremental-signature revisions beyond structural preflight detection. Production behavior must reject them before rewriting.
- Authorized encrypted-PDF processing and secret transport for this non-secret tool. The current PoC only proves rejection without credentials.
- DeviceN, Separation/spot colors, Lab, CalRGB/CalGray, NChannel, complex soft masks, blend modes, overprint, optional-content groups, Type 3 font color behavior, RichMedia, 3D, and unusual annotation subtypes.
- Malformed or cyclic resource graphs, shared-appearance deduplication, appearance-count bombs, decompression bombs, and production CPU/RAM/time limits.
- Image XObjects embedded specifically inside widget appearances; images were tested in page content and nested vector Forms.
- Cross-viewer appearance regeneration in Acrobat, browser PDF.js, Preview, and other editors.
- Production Linux image execution under UID/GID 10001, read-only root, bounded tmpfs, and the current worker limits.

Any unrecognized color space, appearance shape, dynamic form, signature, or unsupported resource graph must fail closed rather than return apparent success.

## Licensing and dependency findings

pikepdf 10.13.0.post1 is MPL-2.0. The direct dependencies resolved in the PoC are Pillow 12.3.0, lxml 6.1.3, and packaging 26.3. Binary wheels also bundle native qpdf and libjpeg-turbo; platform-specific wheels bundle additional runtime components and redistribute their license mapping under the wheel's `dist-info/licenses` directory. The tested Windows wheel contained libqpdf 12.3.2, the Microsoft C++ runtime, OpenSSL, and zlib notices. Linux wheels use bundled libqpdf, libjpeg, and zlib with qpdf native crypto.

MPL-2.0 permits commercial and closed-source combination and applies file-level source obligations when covered executable/source code is distributed outside the organization. Providing server functionality over the web is not itself distribution under Mozilla's FAQ. Notices and sources for any modified MPL-covered files must still be handled correctly. This is an engineering assessment, not legal advice.

OCRmyPDF 17.10.0 declares `pikepdf>=10`, and the production Dockerfile installs OCRmyPDF, so pikepdf is necessarily present as an indirect dependency. A clean resolver run on 2026-09-26 selected pikepdf 10.13.0.post1. The production verifier does not currently print or pin pikepdf, and the Debian-only qpdf SBOM does not prove the exact installed Python wheel. Therefore the exact pikepdf version in the already-built production image remains unverified. Indirect presence does not approve direct Grayscale use.

The actual color conversion still depends on PyMuPDF/MuPDF 1.28.2, which is AGPL-3.0 or Artifex commercial. The existing proprietary hosted-product gate remains open. pikepdf solves structural discovery and replacement; qpdf/pikepdf alone did not provide the semantic recoloring engine.

## Security and operational findings

Both MuPDF and pikepdf/libqpdf are native in-process parsers. A production implementation would need the existing non-root/read-only/tmpfs worker controls plus explicit page, object, appearance, nesting-depth, decoded-byte, temporary-byte, CPU, RAM, and wall-time limits. Shared objects must be deduplicated by object identity and resource traversal must have cycle detection. Temporary carrier files require private directories and cleanup in `finally`. Output must be reopened, syntax-checked, rendered, and scanned for residual color before persistence.

No Ghostscript, rasterized-page reconstruction, AI, shell command construction, or production dependency change was used in this PoC.

## Change Request required before production implementation

Production work requires an approved Change Request that:

1. Approves and procures a commercial Artifex MuPDF/PyMuPDF license, or selects another commercially approved semantic recoloring engine that passes the same appearance corpus.
2. Approves pikepdf as a direct production dependency, pins its exact version, records Pillow/lxml/packaging and the bundled native library inventory, and updates the worker SBOM and vulnerability gates.
3. Explicitly acknowledges that pikepdf 10.13.0.post1 uses embedded libqpdf 12.3.2 while the controlled qpdf CLI remains 11.3.0-1+deb12u1; the two paths must be tested and documented separately.
4. Defines the fail-closed supported subset for XFA, signatures, encryption, dynamic JavaScript appearances, uncommon color spaces, resource cycles, and unsupported annotations.
5. Requires a production Linux PoC under the actual worker sandbox plus real-world Arabic/English, signed, malformed, hostile, forms, pattern, shading, ICC, and multi-viewer corpora before registration.

Until those gates pass, Grayscale remains a capability, licensing, and production-environment blocker and Phase 1 remains incomplete.
