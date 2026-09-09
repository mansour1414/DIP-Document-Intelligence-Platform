import { NextRequest } from "next/server";
import { DocumentProcessingError, processServerDocument, type ServerToolId } from "@/lib/document-processing/server";
import { requireUser } from "@/lib/auth/user";
import { CreditError } from "@/lib/billing/credits";
import { beginJob, finishJob } from "@/lib/jobs/history";

export const runtime = "nodejs";
export const maxDuration = 130;

const serverTools = new Set<ServerToolId>(["word-to-pdf", "pdf-to-word", "excel-to-pdf", "powerpoint-to-pdf", "ocr-pdf"]);

export async function POST(request: NextRequest, { params }: { params: Promise<{ tool: string }> }) {
  const { tool } = await params;
  if (!serverTools.has(tool as ServerToolId)) return Response.json({ code: "NOT_FOUND", message: "Unknown processing tool." }, { status: 404 });
  let jobId: string | undefined;
  try {
    const user = await requireUser();
    const form = await request.formData();
    const file = form.get("file");
    const language = form.get("language");
    if (!(file instanceof File)) return Response.json({ code: "MISSING_FILE", message: "Upload one document to continue." }, { status: 400 });
    if (typeof language === "string" && !["ara", "eng", "ara+eng"].includes(language)) return Response.json({ code: "INVALID_LANGUAGE", message: "Choose a supported OCR language." }, { status: 400 });
    jobId = (await beginJob({ userId: user.id, toolId: tool, filename: file.name, size: file.size, mimeType: file.type })).id;
    const result = await processServerDocument(tool as ServerToolId, file, typeof language === "string" ? language : "ara+eng");
    await finishJob(jobId, true);
    return new Response(result.bytes, { headers: { "Content-Type": result.contentType, "Content-Disposition": `attachment; filename="${result.filename}"`, "Cache-Control": "no-store" } });
  } catch (error) {
    if (jobId) await finishJob(jobId, false, error instanceof Error ? error.message : "Processing failed");
    const known = error instanceof DocumentProcessingError;
    const credit = error instanceof CreditError;
    const auth = error instanceof Error && error.message === "AUTH_REQUIRED";
    return Response.json({ code: auth ? "AUTH_REQUIRED" : credit ? "INSUFFICIENT_CREDITS" : known ? error.code : "INTERNAL_ERROR", message: auth ? "Sign in to process documents." : credit ? "You do not have enough credits for this tool." : known ? error.message : "The document could not be processed." }, { status: auth ? 401 : credit ? 402 : known && error.code === "ENGINE_UNAVAILABLE" ? 503 : 422 });
  }
}
