import { PdfToolWorkspace } from "@/components/tools/pdf-tool-workspace";
import { getTool } from "@/config";
import { privateMetadata } from "@/lib/seo/metadata";
export const metadata = privateMetadata;

export default function MergePDFPage() {
  const tool = getTool("merge-pdf");
  if (!tool) return null;
  return <PdfToolWorkspace tool={tool} />;
}
