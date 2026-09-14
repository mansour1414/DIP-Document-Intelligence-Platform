import { handlePublicApi } from "@/lib/public-api/request";
import { getPublicJobResult } from "@/lib/public-api/jobs";
export async function GET(request: Request, { params }: { params: Promise<{ jobId: string }> }) { return handlePublicApi(request, "/v1/jobs/:jobId/result", "jobs:read", async ({ principal }) => Response.json({ data: await getPublicJobResult(principal, (await params).jobId) })); }
