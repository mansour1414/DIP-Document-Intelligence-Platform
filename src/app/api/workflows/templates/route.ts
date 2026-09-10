import { requireUser } from "@/lib/auth/user";
import { workflowTemplates } from "@/lib/workflows/templates";
export async function GET() { try { await requireUser(); return Response.json({ templates: workflowTemplates }); } catch { return Response.json({ code: "AUTH_REQUIRED" }, { status: 401 }); } }
