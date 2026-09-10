# Runtime dependency and license registry

Reviewed 2026-09-10. Versions are installed/lockfile versions; host executables must be verified in the immutable production image. This is engineering analysis, not legal advice.

| Component | Version | Relationship | License/source | SaaS status and obligations | Gate |
| --- | --- | --- | --- | --- | --- |
| pdf-lib | 1.17.1 | direct | MIT, package metadata | retain copyright/license notice | cleared |
| pdfjs-dist | 6.3.289 | direct | Apache-2.0, package metadata | retain license/notices; document modifications | cleared |
| @napi-rs/canvas | 1.0.9 | direct/native | MIT, package metadata | retain notice; verify shipped native artifact inventory | image verification |
| @fontsource/noto-sans-arabic | 5.3.0 | direct/font | OFL-1.1, package metadata | retain OFL and reserved-name terms | cleared |
| Prisma client/CLI | 7.10.0 | direct | Apache-2.0, package metadata | retain notices | cleared |
| BullMQ | 6.3.4 | direct | MIT, package metadata | retain notice | cleared |
| ioredis | 5.11.1 | direct | MIT, package metadata | retain notice | cleared |
| @aws-sdk/client-s3 | 3.1128.0 | direct | Apache-2.0, package metadata | retain notices | cleared |
| JSZip | 3.10.2 | direct | MIT OR GPL-3.0-or-later | project selects MIT terms and retains notice | cleared |
| @sentry/nextjs | 10.74.0 | direct/runtime+build | MIT, package metadata | secret-only DSN/auth; production account DPA/retention review | code cleared; account gate |
| LibreOffice | CI/host | subprocess | MPL-2.0 plus bundled notices, official inventory | preserve exact distribution notices and image manifest | subprocess cleared; image verification |
| OCRmyPDF | 17.10.0 | direct subprocess orchestrator | MPL-2.0, [official project metadata](https://github.com/ocrmypdf/OCRmyPDF/blob/v17.10.0/pyproject.toml) | suitable for the approved SaaS subprocess path; retain license/notices and distribute source for any modified MPL-covered files | cleared for approved path |
| Tesseract OCR | host package; exact version emitted by image build | direct subprocess OCR engine | Apache-2.0, [official project](https://github.com/tesseract-ocr/tesseract) | suitable for commercial SaaS use; retain license/notices and freeze the production image manifest | cleared; image version verification |
| Tesseract `eng`/`ara` data | host language packs; exact package versions in image manifest | direct runtime data | Apache-2.0, [official tessdata project](https://github.com/tesseract-ocr/tessdata) | retain data license/notices; CI verifies both language identifiers | cleared; image version verification |
| pypdfium2 / PDFium | 5.13.0 | direct Python/native rasterizer dependency | Apache-2.0 OR BSD-3-Clause for pypdfium2; PDFium BSD-style plus bundled dependency licenses, [official licensing](https://pypdfium2.readthedocs.io/en/stable/readme.html#licensing) | suitable for the approved SaaS path; ship the wheel's PDFium and third-party license inventory with any binary distribution | cleared for pinned wheel |
| Python | 3.12 in CI/runtime policy | direct interpreter | PSF License, [Python license](https://docs.python.org/3/license.html) | preserve applicable notices when distributing an interpreter image | cleared; image verification |
| OCRmyPDF Python runtime dependencies | resolved by the pinned 17.10.0 wheel and frozen in the production image manifest | transitive Python packages, including pikepdf, fpdf2, uharfbuzz and Pillow | per-package licenses/notices; [official OCRmyPDF dependency metadata](https://github.com/ocrmypdf/OCRmyPDF/blob/v17.10.0/pyproject.toml) | retain bundled notices, vulnerability/license scan the frozen image, and review any dependency-set change | cleared subject to immutable image inventory |
| Ghostscript | not installed | excluded optional subprocess | AGPL-3.0 or Artifex commercial, [official Artifex licensing](https://www.ghostscript.com/licensing/) | **NOT APPROVED FOR DIP COMMERCIAL OCR PRODUCTION PATH**; current path avoids it. Future use requires a separate Change Request and Licensing Gate | prohibited in approved OCR runtime |
| Gemini REST | configured provider | external service | Google service/data terms | account, region, processing and retention controls | provider account gate |

## OCR/Ghostscript conclusion

The implemented command fixes `--output-type pdf --optimize 0 --rasterizer pypdfium --ocr-engine tesseract`. OCRmyPDF v17 documents Ghostscript as optional when pypdfium2 performs PDF rasterization; standard PDF output avoids the PDF/A conversion path. Heavy CI pins OCRmyPDF and pypdfium2, verifies Tesseract plus `ara`/`eng`, and fails if `gs` resolves. Trade-offs: no PDF/A claim and no Ghostscript optimization. Production image builds must run the same verifier and preserve their package/license manifest.

**LICENSING GATE STATUS: CLOSED.** On 2026-09-10 the Product Owner approved the Ghostscript-free OCR production path. Ghostscript is not installed, approved, or indirectly callable in that runtime. Adding it later for PDF/A, optimization, rasterization, conversion, or repair requires a separate Change Request and Licensing Gate. This registry is engineering documentation, not legal advice.
