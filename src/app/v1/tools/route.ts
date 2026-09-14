import { handlePublicApi } from "@/lib/public-api/request";
import { listPublicTools } from "@/lib/public-api/tools";
export async function GET(request: Request) { return handlePublicApi(request, "/v1/tools", "tools:read", async ({ principal }) => Response.json({ data: await listPublicTools(principal) })); }
