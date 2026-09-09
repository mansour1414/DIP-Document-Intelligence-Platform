import { requireUser } from "@/lib/auth/user";
import { db } from "@/lib/db";

export async function GET(_: Request, { params }: { params: Promise<{ jobId: string }> }) {
  try { const user = await requireUser(); const { jobId } = await params; const job = await db.job.findFirst({ where: { id: jobId, requesterId: user.id }, select: { id: true, status: true, result: true, errorCode: true, error: true, correlationId: true } }); if (!job) return Response.json({ code: "NOT_FOUND" }, { status: 404 }); return Response.json({ ...job, status: job.status.toLowerCase() }); }
  catch (error) { return Response.json({ code: error instanceof Error && error.message === "AUTH_REQUIRED" ? "AUTH_REQUIRED" : "INTERNAL_ERROR" }, { status: error instanceof Error && error.message === "AUTH_REQUIRED" ? 401 : 500 }); }
}
