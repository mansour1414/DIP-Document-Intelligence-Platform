import { NextRequest } from "next/server";
import { DocumentProcessingError, processServerDocument, type ServerToolId } from "@/lib/document-processing/server";

export const runtime = "nodejs";
export const maxDuration = 130;

const serverTools = new Set<ServerToolId>(["word-to-pdf", "pdf-to-word", "excel-to-pdf", "powerpoint-to-pdf", "ocr-pdf"]);

export async function POST(request: NextRequest, { params }: { params: Promise<{ tool: string }> }) {
  const { tool } = await params;
  if (!serverTools.has(tool as ServerToolId)) return Response.json({ code: "NOT_FOUND", message: "Unknown processing tool." }, { status: 404 });
  try {
    const form = await request.formData();
    const file = form.get("file");
    const language = form.get("language");
    if (!(file instanceof File)) return Response.json({ code: "MISSING_FILE", message: "Upload one document to continue." }, { status: 400 });
    if (typeof language === "string" && !["ara", "eng", "ara+eng"].includes(language)) return Response.json({ code: "INVALID_LANGUAGE", message: "Choose a supported OCR language." }, { status: 400 });
    const result = await processServerDocument(tool as ServerToolId, file, typeof language === "string" ? language : "ara+eng");
    return new Response(result.bytes, { headers: { "Content-Type": result.contentType, "Content-Disposition": `attachment; filename="${result.filename}"`, "Cache-Control": "no-store" } });
  } catch (error) {
    const known = error instanceof DocumentProcessingError;
    return Response.json({ code: known ? error.code : "INTERNAL_ERROR", message: known ? error.message : "The document could not be processed." }, { status: known && error.code === "ENGINE_UNAVAILABLE" ? 503 : 422 });
  }
}
