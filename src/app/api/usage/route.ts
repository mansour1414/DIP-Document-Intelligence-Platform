import { requireUser } from "@/lib/auth/user";
import { beginJob, finishJob } from "@/lib/jobs/history";
import { CreditError } from "@/lib/billing/credits";

export async function POST(request: Request) {
  try {
    const body = await request.json() as { toolId?: unknown; filename?: unknown; size?: unknown; mimeType?: unknown };
    if (typeof body.toolId !== "string" || typeof body.filename !== "string" || typeof body.size !== "number") return Response.json({ code: "INVALID_INPUT", message: "Invalid processing request." }, { status: 400 });
    const user = await requireUser(); const job = await beginJob({ userId: user.id, toolId: body.toolId, filename: body.filename, size: body.size, mimeType: typeof body.mimeType === "string" ? body.mimeType : undefined });
    return Response.json({ jobId: job.id });
  } catch (error) { const auth = error instanceof Error && error.message === "AUTH_REQUIRED"; const credit = error instanceof CreditError; return Response.json({ code: auth ? "AUTH_REQUIRED" : credit ? "INSUFFICIENT_CREDITS" : "USAGE_ERROR", message: auth ? "Sign in to process documents." : credit ? "You do not have enough credits for this tool." : "Unable to authorize processing." }, { status: auth ? 401 : credit ? 402 : 500 }); }
}

export async function PATCH(request: Request) {
  const body = await request.json() as { jobId?: unknown; success?: unknown; error?: unknown };
  if (typeof body.jobId !== "string" || typeof body.success !== "boolean") return Response.json({ code: "INVALID_INPUT" }, { status: 400 });
  const user = await requireUser();
  const job = await (await import("@/lib/db")).db.job.findFirst({ where: { id: body.jobId, requesterId: user.id }, select: { id: true } });
  if (!job) return Response.json({ code: "NOT_FOUND" }, { status: 404 });
  await finishJob(job.id, body.success, typeof body.error === "string" ? body.error : undefined); return Response.json({ ok: true });
}
