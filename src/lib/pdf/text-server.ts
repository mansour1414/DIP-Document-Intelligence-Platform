export type PdfTextPage = { page: number; text: string };

/** Text-only PDF parsing for Node workers; it does not initialize Canvas or a browser worker. */
export async function extractPdfTextServer(bytes: Uint8Array): Promise<PdfTextPage[]> {
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs");
  const loadingTask = pdfjs.getDocument({ data: bytes.slice(), isEvalSupported: false, useSystemFonts: true } as DocumentInitParameters);
  const document = await loadingTask.promise;
  try {
    const pages: PdfTextPage[] = [];
    for (let pageNumber = 1; pageNumber <= document.numPages; pageNumber += 1) {
      const page = await document.getPage(pageNumber); const content = await page.getTextContent();
      pages.push({ page: pageNumber, text: content.items.map((item) => "str" in item ? item.str : "").join(" ").replace(/\s+/g, " ").trim() });
      page.cleanup();
    }
    return pages;
  } finally { await loadingTask.destroy(); }
}

export function serializePdfPages(pages: PdfTextPage[]) {
  return pages.map(({ page, text }) => `[PAGE ${page}]\n${text}\n[/PAGE ${page}]`).join("\n\n");
}
import type { DocumentInitParameters } from "pdfjs-dist/types/src/display/api";
