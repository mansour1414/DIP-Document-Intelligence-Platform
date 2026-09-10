# Phase 6 generated corpus

The automated tests create small synthetic PDFs in memory (normal, multi-page, Arabic/English text, rotated and mixed-size variants). No customer document or personal data belongs here.

Office and OCR smoke tests are host-capability tests: heavy CI enables them after installing LibreOffice and the approved OCRmyPDF/Tesseract/pypdfium2 runtime. The Product Owner closed the OCR licensing gate on 2026-09-10 for this Ghostscript-free path only; `gs` is prohibited in that OCR runtime.

Safe adversarial cases cover invalid magic bytes, malformed PDFs, MIME/container mismatch, configured page/output limits, and oversized declarations. This corpus must never contain malware.
