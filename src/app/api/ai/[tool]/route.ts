export async function POST(_request: Request, { params }: { params: Promise<{ tool: string }> }) {
  const { tool } = await params;
  if (!["summarize-pdf", "chat-with-pdf", "extract-data"].includes(tool)) return Response.json({ code: "NOT_FOUND", message: "Unknown AI tool." }, { status: 404 });
  return Response.json({ code: "ASYNC_JOB_REQUIRED", message: `Upload the scoped PDF to /api/jobs/${tool}; AI tools run only through the unified worker.` }, { status: 409 });
}
