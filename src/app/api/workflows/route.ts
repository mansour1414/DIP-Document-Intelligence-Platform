import { requireUser } from "@/lib/auth/user";
import { createWorkflow, listWorkflows } from "@/lib/workflows/service";
const problem = (error: unknown) => { const code = typeof error === "object" && error && "code" in error ? String(error.code) : error instanceof Error ? error.message : "INTERNAL_ERROR"; return Response.json({ code, issues: typeof error === "object" && error && "issues" in error ? error.issues : undefined }, { status: code === "AUTH_REQUIRED" ? 401 : code === "WORKFLOW_INVALID" ? 422 : 400 }); };
export async function GET() { try { const user = await requireUser(); return Response.json({ workflows: await listWorkflows(user.id) }); } catch (error) { return problem(error); } }
export async function POST(request: Request) { try { const user = await requireUser(); const body = await request.json(); return Response.json({ workflow: await createWorkflow(user.id, body) }, { status: 201 }); } catch (error) { return problem(error); } }
