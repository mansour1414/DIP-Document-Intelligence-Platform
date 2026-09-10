import { ServerToolWorkspace } from "@/components/tools/server-tool-workspace";
import { getTool } from "@/config";
import { privateMetadata } from "@/lib/seo/metadata";
export const metadata = privateMetadata;
export default function Page() { return <ServerToolWorkspace tool={getTool("powerpoint-to-pdf")!} />; }
