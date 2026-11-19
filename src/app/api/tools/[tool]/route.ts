export const runtime = "nodejs";

const serverTools = new Set(["word-to-pdf", "pdf-to-word", "excel-to-pdf", "powerpoint-to-pdf", "ocr-pdf"]);

/**
 * PR-0: synchronous Office/OCR execution was removed. These tools now run
 * only through the unified async job pipeline (POST /api/jobs/[tool]),
 * which enforces validateUpload -> requireCleanUpload -> storage.put
 * before enqueueing to the BullMQ document worker.
 */
export async function POST(_request: Request, { params }: { params: Promise<{ tool: string }> }) {
  const { tool } = await params;
  if (!serverTools.has(tool)) return Response.json({ code: "NOT_FOUND", message: "Unknown processing tool." }, { status: 404 });
  return Response.json({ code: "SYNC_PROCESSING_DISABLED", message: `Synchronous processing is disabled for ${tool}. Upload the file to /api/jobs/${tool} and poll /api/jobs/status/[jobId]; the document worker processes it asynchronously.` }, { status: 409 });
}
