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
| OCRmyPDF | CI/host | subprocess | core MPL-2.0, official project license | preserve notices; freeze wheel/plugins | component cleared; chain-dependent |
| Tesseract | CI/host | subprocess OCR engine | Apache-2.0, upstream distribution | retain engine/language-data notices | image verification |
| pypdfium2/PDFium | CI/host | OCR transitive/native | bundled Apache/BSD-style inventory varies by wheel | retain bundled notices; freeze/scan wheel | image verification |
| Ghostscript | excluded from selected path | optional subprocess | AGPL-3.0 or Artifex commercial | not approved for closed-source SaaS assumptions without legal/commercial resolution | blocked if introduced |
| Gemini REST | configured provider | external service | Google service/data terms | account, region, processing and retention controls | provider account gate |

## OCR/Ghostscript conclusion

The implemented command fixes `--output-type pdf --optimize 0`. Official OCRmyPDF documentation describes Ghostscript as optional when pypdfium2 handles rasterization; standard PDF output avoids PDF/A conversion. Heavy CI installs OCRmyPDF+pypdfium2 and fails if `gs` is present. Trade-offs: no PDF/A claim and no Ghostscript optimization. Production must repeat binary/version evidence.

**LICENSING GATE STATUS: Blocked pending Product Owner decision.** The Ghostscript-free path is technically defined, but launch requires approval to freeze Option B, or selection of A commercial Ghostscript, C a replacement engine, or D temporary OCR launch disablement. Recommendation: approve Option B after CI evidence and legal/image-manifest review; do not introduce Ghostscript.
