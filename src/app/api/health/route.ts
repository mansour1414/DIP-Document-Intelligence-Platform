import { NextResponse } from "next/server";
import { readEnvironment } from "@/lib/env";

export const dynamic = "force-dynamic";

export async function GET() {
  const env = readEnvironment();
  return NextResponse.json({ status: "ok", service: "dip", environment: env.environment, timestamp: new Date().toISOString() });
}
