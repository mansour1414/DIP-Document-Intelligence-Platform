import { AiProcessingError, runAiTool, type AiTool } from "@/lib/ai/gemini";
import { requireUser } from "@/lib/auth/user";
import { CreditError } from "@/lib/billing/credits";
import { beginJob, finishJob } from "@/lib/jobs/history";

const tools = new Set<AiTool>(["summarize-pdf", "chat-with-pdf", "extract-data"]);

export async function POST(request: Request, { params }: { params: Promise<{ tool: string }> }) {
  const { tool } = await params;
  if (!tools.has(tool as AiTool)) return Response.json({ code: "NOT_FOUND", message: "Unknown AI tool." }, { status: 404 });
  let jobId: string | undefined;
  try {
    const user = await requireUser();
    const body = await request.json() as { text?: unknown; question?: unknown; locale?: unknown };
    if (typeof body.text !== "string" || body.text.length > 200_000) return Response.json({ code: "INVALID_DOCUMENT", message: "The extracted document text is invalid or too large." }, { status: 400 });
    if (body.question !== undefined && typeof body.question !== "string") return Response.json({ code: "INVALID_QUESTION", message: "The question must be text." }, { status: 400 });
    const locale = body.locale === "ar" ? "ar" : "en";
    jobId = (await beginJob({ userId: user.id, toolId: tool, filename: "AI document analysis", size: body.text.length, mimeType: "text/plain" })).id;
    const result = await runAiTool({ tool: tool as AiTool, text: body.text, question: body.question, locale });
    await finishJob(jobId, true); return Response.json(result);
  } catch (error) {
    if (jobId) await finishJob(jobId, false, error instanceof Error ? error.message : "AI request failed");
    const known = error instanceof AiProcessingError;
    const credit = error instanceof CreditError; const auth = error instanceof Error && error.message === "AUTH_REQUIRED";
    return Response.json({ code: auth ? "AUTH_REQUIRED" : credit ? "INSUFFICIENT_CREDITS" : known ? error.code : "INTERNAL_ERROR", message: auth ? "Sign in to use AI tools." : credit ? "You do not have enough credits for this tool." : known ? error.message : "The AI request could not be completed." }, { status: auth ? 401 : credit ? 402 : known ? 422 : 500 });
  }
}
