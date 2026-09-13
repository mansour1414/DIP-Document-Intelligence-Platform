import { requireUser } from "@/lib/auth/user";
import { getAgentRun } from "@/lib/agent/runtime";
export async function GET(_: Request, { params }: { params: Promise<{ runId: string }> }) { try { const user = await requireUser(); const run = await getAgentRun(user.id, (await params).runId); return run ? Response.json({ run }) : Response.json({ code: "NOT_FOUND" }, { status: 404 }); } catch (error) { const auth = error instanceof Error && error.message === "AUTH_REQUIRED"; return Response.json({ code: auth ? "AUTH_REQUIRED" : "AGENT_FAILED" }, { status: auth ? 401 : 422 }); } }
