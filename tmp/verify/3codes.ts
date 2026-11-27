import { isPublicErrorCode } from "../../src/lib/jobs/error-boundary";
for (const code of ["QPDF_PROCESSING_FAILED", "ENCRYPTED_PDF_REPAIR_UNSUPPORTED", "SIGNED_PDF_REPAIR_UNSAFE", "PDF_PASSWORD_INVALID"]) {
  console.log(`${code}: ${isPublicErrorCode(code) ? "preserved" : "WOULD COLLAPSE"}`);
}
