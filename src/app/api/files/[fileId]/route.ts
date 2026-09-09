import { requireUser } from "@/lib/auth/user";
import { db } from "@/lib/db";
import { getStorage } from "@/lib/storage";

export async function GET(_: Request, { params }: { params: Promise<{ fileId: string }> }) {
  try {
    const user = await requireUser(); const { fileId } = await params;
    const file = await db.file.findFirst({ where: { id: fileId, document: { userId: user.id } }, select: { originalName: true, mimeType: true, storageKey: true } });
    if (!file) return Response.json({ code: "NOT_FOUND" }, { status: 404 });
    const bytes = await getStorage().get(file.storageKey); const filename = file.originalName.replace(/["\\\r\n]/g, "_");
    return new Response(bytes as BodyInit, { headers: { "Content-Type": file.mimeType, "Content-Disposition": `attachment; filename="${filename}"`, "Cache-Control": "private, no-store" } });
  } catch (error) { const auth = error instanceof Error && error.message === "AUTH_REQUIRED"; return Response.json({ code: auth ? "AUTH_REQUIRED" : "INTERNAL_ERROR" }, { status: auth ? 401 : 500 }); }
}
