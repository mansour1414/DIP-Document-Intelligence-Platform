import { notFound } from "next/navigation";
import { PdfToolWorkspace } from "@/components/tools/pdf-tool-workspace";
import { ServerToolWorkspace } from "@/components/tools/server-tool-workspace";
import { AiToolWorkspace } from "@/components/tools/ai-tool-workspace";
import { getTool } from "@/config";
import type { PdfOperation } from "@/lib/pdf/client";

const phaseOneTools = new Set<PdfOperation>([
  "merge-pdf", "split-pdf", "compress-pdf", "organize-pdf", "rotate-pdf",
  "delete-pages", "extract-pages", "jpg-to-pdf", "pdf-to-jpg", "watermark-pdf",
]);
const phaseTwoTools = new Set(["word-to-pdf", "pdf-to-word", "excel-to-pdf", "powerpoint-to-pdf", "ocr-pdf"]);
const phaseThreeTools = new Set(["summarize-pdf", "chat-with-pdf", "extract-data"]);

export default async function PdfToolPage({ params }: { params: Promise<{ tool: string }> }) {
  const { tool: toolId } = await params;
  if (!phaseOneTools.has(toolId as PdfOperation) && !phaseTwoTools.has(toolId) && !phaseThreeTools.has(toolId)) notFound();
  const tool = getTool(toolId);
  if (!tool) notFound();
  if (phaseThreeTools.has(toolId)) return <AiToolWorkspace tool={tool} />;
  return phaseTwoTools.has(toolId) ? <ServerToolWorkspace tool={tool} /> : <PdfToolWorkspace tool={tool} />;
}
