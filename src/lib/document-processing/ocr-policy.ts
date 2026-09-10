export const APPROVED_OCR_EXECUTABLE = "ocrmypdf" as const;

export function approvedOcrArguments(language: string, inputPath: string, outputPath: string) {
  return [
    "--skip-text",
    "--rotate-pages",
    "--deskew",
    "--output-type",
    "pdf",
    "--optimize",
    "0",
    "--rasterizer",
    "pypdfium",
    "--ocr-engine",
    "tesseract",
    "--language",
    language,
    inputPath,
    outputPath,
  ] as const;
}
