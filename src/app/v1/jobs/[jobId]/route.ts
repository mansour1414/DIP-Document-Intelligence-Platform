import { handlePublicApi } from "@/lib/public-api/request";
import { getPublicJob } from "@/lib/public-api/jobs";
import { PublicApiError } from "@/lib/public-api/errors";
export async function GET(request: Request, { params }: { params: Promise<{ jobId: string }> }) { return handlePublicApi(request, "/v1/jobs/:jobId", "jobs:read", async ({ principal }) => { const job = await getPublicJob(principal, (await params).jobId); if (!job) throw new PublicApiError("NOT_FOUND", "The requested job was not found.", 404); return Response.json({ data: job }); }); }
