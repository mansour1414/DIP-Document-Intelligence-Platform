import { notFound } from "next/navigation";
import { PdfToolWorkspace } from "@/components/tools/pdf-tool-workspace";
import { getTool } from "@/config";
import type { PdfOperation } from "@/lib/pdf/client";

const phaseOneTools = new Set<PdfOperation>([
  "merge-pdf", "split-pdf", "compress-pdf", "organize-pdf", "rotate-pdf",
  "delete-pages", "extract-pages", "jpg-to-pdf", "pdf-to-jpg", "watermark-pdf",
]);

export default async function PdfToolPage({ params }: { params: Promise<{ tool: string }> }) {
  const { tool: toolId } = await params;
  if (!phaseOneTools.has(toolId as PdfOperation)) notFound();
  const tool = getTool(toolId);
  if (!tool) notFound();
  return <PdfToolWorkspace tool={tool} />;
}
