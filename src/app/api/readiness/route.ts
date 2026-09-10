import { getQueueConnection } from "@/lib/queue";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    await getQueueConnection().ping();
    return Response.json({ status: "ready", service: "dip" });
  } catch {
    return Response.json({ status: "not_ready", service: "dip", code: "DEPENDENCY_UNAVAILABLE" }, { status: 503 });
  }
}

