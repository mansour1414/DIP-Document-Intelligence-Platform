import { requireUser } from "@/lib/auth/user";
import { findJobForUser } from "@/lib/jobs/access";
import { jobPollBudgetMs } from "@/lib/runtime/config";

export async function GET(_: Request, { params }: { params: Promise<{ jobId: string }> }) {
  try {
    const user = await requireUser(); const { jobId } = await params;
    const job = await findJobForUser(user.id, jobId);
    if (!job) return Response.json({ code: "NOT_FOUND" }, { status: 404 });
    // `pollBudgetMs` is derived from the configurable worker timeouts so the
    // browser never invents its own deadline for a still-running job.
    return Response.json({ ...job, status: job.status.toLowerCase(), pollBudgetMs: jobPollBudgetMs(job.toolId) });
  } catch (error) {
    return Response.json({ code: error instanceof Error && error.message === "AUTH_REQUIRED" ? "AUTH_REQUIRED" : "INTERNAL_ERROR" }, { status: error instanceof Error && error.message === "AUTH_REQUIRED" ? 401 : 500 });
  }
}
