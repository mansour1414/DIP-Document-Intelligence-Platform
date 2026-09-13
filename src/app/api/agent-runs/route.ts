import { randomUUID } from "crypto";
import { requireUser } from "@/lib/auth/user";
import { createAgentRun } from "@/lib/agent/runtime";
import { AgentError } from "@/lib/agent/errors";
export const runtime = "nodejs";
export async function POST(request: Request) { try { const user = await requireUser(); const run = await createAgentRun(user.id, await request.json(), request.headers.get("idempotency-key") ?? randomUUID(), request.headers.get("x-correlation-id") ?? randomUUID()); return Response.json({ run }, { status: 202 }); } catch (error) { const auth = error instanceof Error && error.message === "AUTH_REQUIRED"; const code = error instanceof AgentError ? error.code : auth ? "AUTH_REQUIRED" : "AGENT_FAILED"; return Response.json({ code, message: error instanceof Error ? error.message : "Agent request failed." }, { status: auth ? 401 : 422 }); } }
