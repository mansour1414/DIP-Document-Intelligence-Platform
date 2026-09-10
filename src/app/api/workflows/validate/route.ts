import { requireUser } from "@/lib/auth/user";
import { validateForUser } from "@/lib/workflows/service";
export async function POST(request: Request) { try { const user = await requireUser(); return Response.json(await validateForUser(user.id, await request.json())); } catch (error) { const auth = error instanceof Error && error.message === "AUTH_REQUIRED"; return Response.json({ code: auth ? "AUTH_REQUIRED" : "INVALID_REQUEST" }, { status: auth ? 401 : 400 }); } }
