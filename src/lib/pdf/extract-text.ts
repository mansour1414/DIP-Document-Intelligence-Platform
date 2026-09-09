export async function extractPdfText(file: File, onProgress?: (current: number, total: number) => void) {
  if (file.size > 100 * 1024 * 1024) throw new Error("FILE_LIMIT: Choose a PDF no larger than 100 MB.");
  const pdfjs = await import("pdfjs-dist");
  pdfjs.GlobalWorkerOptions.workerSrc = new URL("pdfjs-dist/build/pdf.worker.min.mjs", import.meta.url).toString();
  const task = pdfjs.getDocument({ data: new Uint8Array(await file.arrayBuffer()) });
  const document = await task.promise;
  if (document.numPages > 500) throw new Error("PAGE_LIMIT: This PDF exceeds the 500-page limit.");
  try {
    const pages: string[] = [];
    for (let number = 1; number <= document.numPages; number += 1) {
      const page = await document.getPage(number);
      const content = await page.getTextContent();
      pages.push(content.items.map((item) => "str" in item ? item.str : "").join(" "));
      page.cleanup(); onProgress?.(number, document.numPages);
    }
    return pages.join("\n\n");
  } finally { await task.destroy(); }
}
