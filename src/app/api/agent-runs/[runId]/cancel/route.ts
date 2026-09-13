import { requireUser } from "@/lib/auth/user";
import { cancelAgentRun } from "@/lib/agent/runtime";
export async function POST(_: Request, { params }: { params: Promise<{ runId: string }> }) { try { const user = await requireUser(); return Response.json({ run: await cancelAgentRun(user.id, (await params).runId) }); } catch (error) { const auth = error instanceof Error && error.message === "AUTH_REQUIRED"; return Response.json({ code: auth ? "AUTH_REQUIRED" : "AGENT_CANCEL_FAILED" }, { status: auth ? 401 : 422 }); } }
