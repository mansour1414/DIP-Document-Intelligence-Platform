import { AiProcessingError, runAiTool, type AiTool } from "@/lib/ai/gemini";

const tools = new Set<AiTool>(["summarize-pdf", "chat-with-pdf", "extract-data"]);

export async function POST(request: Request, { params }: { params: Promise<{ tool: string }> }) {
  const { tool } = await params;
  if (!tools.has(tool as AiTool)) return Response.json({ code: "NOT_FOUND", message: "Unknown AI tool." }, { status: 404 });
  try {
    const body = await request.json() as { text?: unknown; question?: unknown; locale?: unknown };
    if (typeof body.text !== "string" || body.text.length > 200_000) return Response.json({ code: "INVALID_DOCUMENT", message: "The extracted document text is invalid or too large." }, { status: 400 });
    if (body.question !== undefined && typeof body.question !== "string") return Response.json({ code: "INVALID_QUESTION", message: "The question must be text." }, { status: 400 });
    const locale = body.locale === "ar" ? "ar" : "en";
    return Response.json(await runAiTool({ tool: tool as AiTool, text: body.text, question: body.question, locale }));
  } catch (error) {
    const known = error instanceof AiProcessingError;
    return Response.json({ code: known ? error.code : "INTERNAL_ERROR", message: known ? error.message : "The AI request could not be completed." }, { status: known ? 422 : 500 });
  }
}
