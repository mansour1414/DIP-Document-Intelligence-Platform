export type ToolId =
  | "merge-pdf"
  | "split-pdf"
  | "compress-pdf"
  | "organize-pdf"
  | "rotate-pdf"
  | "delete-pages"
  | "extract-pages"
  | "jpg-to-pdf"
  | "pdf-to-jpg"
  | "watermark-pdf"
  | "word-to-pdf"
  | "pdf-to-word"
  | "ocr-pdf"
  | "summarize-pdf"
  | "chat-with-pdf"
  | "extract-data";

export type ToolCategory = "core" | "convert" | "edit" | "ai";

export type ExecutionMode = "client" | "server" | "ai";

export interface ToolMetadata {
  id: ToolId;
  name: string;
  nameAr: string;
  description: string;
  descriptionAr: string;
  icon: string;
  category: ToolCategory;
  execution: ExecutionMode;
  href: string;
}

export interface UploadedFile {
  id: string;
  name: string;
  size: number;
  type: string;
  pageCount?: number;
  preview?: string;
}

export interface ToolResult {
  success: boolean;
  data?: Blob | string;
  error?: string;
  metadata?: Record<string, unknown>;
}

export interface AIResponse {
  content: string;
  model: string;
  tokensUsed: number;
  cost: number;
}
