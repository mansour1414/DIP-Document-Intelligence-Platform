import { handlePublicApi } from "@/lib/public-api/request";
import { getPublicTool } from "@/lib/public-api/tools";
export async function GET(request: Request, { params }: { params: Promise<{ toolId: string }> }) { return handlePublicApi(request, "/v1/tools/:toolId", "tools:read", async ({ principal }) => Response.json({ data: await getPublicTool(principal, (await params).toolId) })); }
