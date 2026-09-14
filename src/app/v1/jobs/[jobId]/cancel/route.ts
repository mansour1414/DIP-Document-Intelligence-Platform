import { handlePublicApi } from "@/lib/public-api/request";
import { cancelPublicJob } from "@/lib/public-api/jobs";
export async function POST(request: Request, { params }: { params: Promise<{ jobId: string }> }) { return handlePublicApi(request, "/v1/jobs/:jobId/cancel", "jobs:cancel", async ({ principal }) => Response.json({ data: await cancelPublicJob(principal, (await params).jobId) })); }
