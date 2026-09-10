import type { WorkflowDefinition } from "./types";
const chain = (first: string, second: string): WorkflowDefinition => ({ schemaVersion: 1, nodes: [
  { id: "prepare", toolId: first, toolVersion: "1", dependsOn: [], inputs: [{ source: "workflow", input: "documents" }] },
  { id: "compress", toolId: second, toolVersion: "1", dependsOn: ["prepare"], inputs: [{ source: "node", nodeId: "prepare", output: 0 }] },
] });
export const workflowTemplates = [
  { id: "merge-compress", name: "Merge PDF → Compress PDF", nameAr: "دمج PDF ← ضغط PDF", definition: chain("merge-pdf", "compress-pdf") },
  { id: "ocr-summarize", name: "OCR PDF → Summarize PDF", nameAr: "OCR PDF ← تلخيص PDF", definition: chain("ocr-pdf", "summarize-pdf") },
  { id: "word-compress", name: "Word to PDF → Compress PDF", nameAr: "Word إلى PDF ← ضغط PDF", definition: chain("word-to-pdf", "compress-pdf") },
  { id: "excel-compress", name: "Excel to PDF → Compress PDF", nameAr: "Excel إلى PDF ← ضغط PDF", definition: chain("excel-to-pdf", "compress-pdf") },
] as const;
