# Runtime dependency and license registry

Reviewed 2026-09-10. Package versions are the installed lockfile versions. This inventory is engineering input, not legal advice.

| Component | Version/path | License | Gate |
| --- | --- | --- | --- |
| pdf-lib | 1.17.1 | MIT | clear |
| pdfjs-dist | 6.3.289 | Apache-2.0 | clear |
| @napi-rs/canvas | 1.0.9 | MIT | review native transitive binaries in release image |
| @fontsource/noto-sans-arabic | 5.3.0 | OFL-1.1 | preserve font notices |
| Prisma client/CLI | 7.10.0 | Apache-2.0 | clear |
| BullMQ | 6.3.4 | MIT | clear |
| ioredis | 5.11.1 | MIT | clear |
| AWS S3 client | 3.1128.0 | Apache-2.0 | clear |
| JSZip | 3.10.2 | MIT OR GPL-3.0-or-later | select/comply with MIT terms |
| LibreOffice subprocess | host-provided | MPL-2.0 with varied bundled third-party notices | review exact production distribution/image |
| OCRmyPDF | host-provided | core MPL-2.0; docs/tests differ | licensing gate remains open for complete runtime chain |
| Tesseract | host-provided | Apache-2.0 (verify exact distribution) | verify language packs/image |
| Ghostscript | optional host dependency | AGPL or commercial | **blocking commercial licensing gate if used** |

The current Windows host has no `soffice`, `ocrmypdf`, or Ghostscript executable on PATH, so Office/OCR host smoke tests cannot run here. OCRmyPDF documentation now describes configurations where Ghostscript may be optional, but the selected production OCR execution path and all subprocess dependencies must be frozen and reviewed before commercial approval.

