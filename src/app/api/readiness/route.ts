import { checkReadiness } from "@/lib/health/readiness";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const result = await checkReadiness(); if (!result.ready) throw new Error("NOT_READY");
    return Response.json({ status: "ready", service: "dip" });
  } catch {
    return Response.json({ status: "not_ready", service: "dip", code: "DEPENDENCY_UNAVAILABLE" }, { status: 503 });
  }
}
