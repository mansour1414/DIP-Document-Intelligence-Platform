import { ArrowDownUp, Bookmark, Combine, Crop, Database, Droplets, Eraser, FileDown, FileImage, FileOutput, FileText, FlipHorizontal2, Grid2X2, Images, ListOrdered, MessageSquare, Minimize2, PanelsTopBottom, Presentation, RotateCw, Scaling, ScanText, Scissors, Search, Shuffle, Sparkles, TableProperties, Trash2 } from "lucide-react";
import { toolsConfig } from "@/config";
import type { MvpToolId } from "@/lib/seo/tool-content";
export type ToolGroupId = "all" | "organize" | "optimize" | "to-pdf" | "from-pdf" | "intelligence";
export const toolGroups: { id: ToolGroupId; en: string; ar: string; tools: MvpToolId[] }[] = [
  { id: "organize", en: "Organize PDF", ar: "تنظيم PDF", tools: ["merge-pdf", "split-pdf", "split-pdf-by-size", "split-pdf-by-bookmarks", "split-pdf-by-text", "organize-pdf", "rotate-pdf", "delete-pages", "extract-pages", "crop-pdf", "page-numbers", "header-footer", "resize-pages", "alternate-mix", "flip-pages", "n-up-pdf", "remove-annotations"] },
  { id: "optimize", en: "Optimize", ar: "تحسين", tools: ["compress-pdf", "watermark-pdf"] },
  { id: "to-pdf", en: "Convert to PDF", ar: "التحويل إلى PDF", tools: ["jpg-to-pdf", "word-to-pdf", "excel-to-pdf", "powerpoint-to-pdf"] },
  { id: "from-pdf", en: "Convert from PDF", ar: "التحويل من PDF", tools: ["pdf-to-jpg", "pdf-to-word"] },
  { id: "intelligence", en: "Document intelligence", ar: "ذكاء المستندات", tools: ["ocr-pdf", "summarize-pdf", "chat-with-pdf", "extract-data"] },
];
export const toolIcons = { "merge-pdf": Combine, "split-pdf": Scissors, "split-pdf-by-size": Scissors, "split-pdf-by-bookmarks": Bookmark, "split-pdf-by-text": Search, "n-up-pdf": Grid2X2, "remove-annotations": Eraser, "compress-pdf": Minimize2, "organize-pdf": ArrowDownUp, "rotate-pdf": RotateCw, "delete-pages": Trash2, "extract-pages": FileOutput, "jpg-to-pdf": Images, "pdf-to-jpg": FileImage, "watermark-pdf": Droplets, "crop-pdf": Crop, "page-numbers": ListOrdered, "header-footer": PanelsTopBottom, "resize-pages": Scaling, "alternate-mix": Shuffle, "flip-pages": FlipHorizontal2, "word-to-pdf": FileText, "pdf-to-word": FileDown, "ocr-pdf": ScanText, "summarize-pdf": Sparkles, "chat-with-pdf": MessageSquare, "extract-data": Database, "excel-to-pdf": TableProperties, "powerpoint-to-pdf": Presentation } as const;
export const catalogTools = toolsConfig.map((tool) => ({ ...tool, group: toolGroups.find((group) => group.tools.includes(tool.id as MvpToolId))!.id }));
