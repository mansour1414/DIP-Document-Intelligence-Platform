# Phase 6 generated corpus

The automated tests create small synthetic PDFs in memory (normal, multi-page, Arabic/English text, rotated and mixed-size variants). No customer document or personal data belongs here.

Office and OCR smoke tests are host-capability tests: they run only when LibreOffice/OCRmyPDF and their approved language/runtime dependencies are installed. The licensing gate for OCRmyPDF/Ghostscript remains open; dependency presence is not commercial approval.

Safe adversarial cases cover invalid magic bytes, malformed PDFs, MIME/container mismatch, configured page/output limits, and oversized declarations. This corpus must never contain malware.

