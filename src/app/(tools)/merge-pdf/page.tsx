import { PdfToolWorkspace } from "@/components/tools/pdf-tool-workspace";
import { getTool } from "@/config";

export default function MergePDFPage() {
  const tool = getTool("merge-pdf");
  if (!tool) return null;
  return <PdfToolWorkspace tool={tool} />;
}
