export const siteConfig = {
  name: "DIP",
  title: "Document Intelligence Platform",
  description:
    "Global document processing platform combining PDF tools with AI, OCR, and workflow — with privacy-first approach and full Arabic/English support.",
  url: process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000",
  ogImage: "/images/og.png",
  links: {
    twitter: "",
    github: "",
  },
};

export type ExecutionMode = "client" | "server" | "ai";
export type SecurityClass = "standard" | "restricted" | "isolated";

export type ToolDefinition = {
  id: string;
  name: string;
  nameAr: string;
  description: string;
  descriptionAr: string;
  icon: string;
  category: "core" | "convert" | "edit" | "ai";
  execution: ExecutionMode;
  href: string;
  version: number;
  supportedMimeTypes: readonly string[];
  limits: { maxBytes: number; maxPages: number; maxFiles: number };
  capabilities: readonly string[];
  securityClass: SecurityClass;
  aiEnabled: boolean;
  locales: readonly ["en", "ar"];
};

const PDF = ["application/pdf"] as const;
const IMAGE = ["image/jpeg", "image/png"] as const;
const BASE_LIMITS = { maxBytes: 100 * 1024 * 1024, maxPages: 500, maxFiles: 20 } as const;

export const toolsConfig = [
  {
    id: "merge-pdf",
    name: "Merge PDF",
    nameAr: "دمج PDF",
    description: "Combine multiple PDF files into one",
    descriptionAr: "دمج ملفات PDF متعددة في ملف واحد",
    icon: "Merge",
    category: "core",
    execution: "client" as const,
    href: "/merge-pdf",
    version: 1, supportedMimeTypes: [...PDF, ...IMAGE], limits: BASE_LIMITS, capabilities: [], securityClass: "standard", aiEnabled: false, locales: ["en", "ar"],
  },
  {
    id: "split-pdf",
    name: "Split PDF",
    nameAr: "تقسيم PDF",
    description: "Split a PDF into multiple files",
    descriptionAr: "تقسيم ملف PDF إلى عدة ملفات",
    icon: "Split",
    category: "core",
    execution: "client" as const,
    href: "/split-pdf",
    version: 1, supportedMimeTypes: PDF, limits: BASE_LIMITS, capabilities: [], securityClass: "standard", aiEnabled: false, locales: ["en", "ar"],
  },
  {
    id: "compress-pdf",
    name: "Compress PDF",
    nameAr: "ضغط PDF",
    description: "Reduce PDF file size",
    descriptionAr: "تقليل حجم ملف PDF",
    icon: "Compress",
    category: "core",
    execution: "client" as const,
    href: "/compress-pdf",
    version: 1, supportedMimeTypes: PDF, limits: BASE_LIMITS, capabilities: ["pdf-renderer"], securityClass: "standard", aiEnabled: false, locales: ["en", "ar"],
  },
  {
    id: "organize-pdf",
    name: "Organize PDF",
    nameAr: "ترتيب PDF",
    description: "Reorder PDF pages by drag & drop",
    descriptionAr: "إعادة ترتيب صفحات PDF بالسحب والإفلات",
    icon: "ArrowUpDown",
    category: "core",
    execution: "client" as const,
    href: "/organize-pdf",
    version: 1, supportedMimeTypes: PDF, limits: BASE_LIMITS, capabilities: [], securityClass: "standard", aiEnabled: false, locales: ["en", "ar"],
  },
  {
    id: "rotate-pdf",
    name: "Rotate PDF",
    nameAr: "تدوير PDF",
    description: "Rotate PDF pages",
    descriptionAr: "تدوير صفحات PDF",
    icon: "RotateCw",
    category: "core",
    execution: "client" as const,
    href: "/rotate-pdf",
    version: 1, supportedMimeTypes: PDF, limits: BASE_LIMITS, capabilities: [], securityClass: "standard", aiEnabled: false, locales: ["en", "ar"],
  },
  {
    id: "delete-pages",
    name: "Delete Pages",
    nameAr: "حذف صفحات",
    description: "Remove pages from a PDF",
    descriptionAr: "حذف صفحات من ملف PDF",
    icon: "Trash2",
    category: "core",
    execution: "client" as const,
    href: "/delete-pages",
    version: 1, supportedMimeTypes: PDF, limits: BASE_LIMITS, capabilities: [], securityClass: "standard", aiEnabled: false, locales: ["en", "ar"],
  },
  {
    id: "extract-pages",
    name: "Extract Pages",
    nameAr: "استخراج صفحات",
    description: "Extract specific pages from a PDF",
    descriptionAr: "استخراج صفحات محددة من ملف PDF",
    icon: "FileOutput",
    category: "core",
    execution: "client" as const,
    href: "/extract-pages",
    version: 1, supportedMimeTypes: PDF, limits: BASE_LIMITS, capabilities: [], securityClass: "standard", aiEnabled: false, locales: ["en", "ar"],
  },
  {
    id: "jpg-to-pdf",
    name: "JPG to PDF",
    nameAr: "صور إلى PDF",
    description: "Convert images to PDF",
    descriptionAr: "تحويل الصور إلى PDF",
    icon: "Image",
    category: "convert",
    execution: "client" as const,
    href: "/jpg-to-pdf",
    version: 1, supportedMimeTypes: IMAGE, limits: BASE_LIMITS, capabilities: [], securityClass: "standard", aiEnabled: false, locales: ["en", "ar"],
  },
  {
    id: "pdf-to-jpg",
    name: "PDF to JPG",
    nameAr: "PDF إلى صور",
    description: "Convert PDF pages to images",
    descriptionAr: "تحويل صفحات PDF إلى صور",
    icon: "FileImage",
    category: "convert",
    execution: "client" as const,
    href: "/pdf-to-jpg",
    version: 1, supportedMimeTypes: PDF, limits: BASE_LIMITS, capabilities: ["pdf-renderer"], securityClass: "standard", aiEnabled: false, locales: ["en", "ar"],
  },
  {
    id: "watermark-pdf",
    name: "Watermark PDF",
    nameAr: "علامة مائية",
    description: "Add watermark to PDF pages",
    descriptionAr: "إضافة علامة مائية لصفحات PDF",
    icon: "Droplets",
    category: "edit",
    execution: "client" as const,
    href: "/watermark-pdf",
    version: 1, supportedMimeTypes: PDF, limits: BASE_LIMITS, capabilities: [], securityClass: "standard", aiEnabled: false, locales: ["en", "ar"],
  },
  {
    id: "word-to-pdf",
    name: "Word to PDF",
    nameAr: "Word إلى PDF",
    description: "Convert Word documents to PDF",
    descriptionAr: "تحويل مستندات Word إلى PDF",
    icon: "FileText",
    category: "convert",
    execution: "server" as const,
    href: "/word-to-pdf",
    version: 1, supportedMimeTypes: ["application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/msword"], limits: BASE_LIMITS, capabilities: ["libreoffice"], securityClass: "isolated", aiEnabled: false, locales: ["en", "ar"],
  },
  {
    id: "pdf-to-word",
    name: "PDF to Word",
    nameAr: "PDF إلى Word",
    description: "Convert PDF to Word document",
    descriptionAr: "تحويل PDF إلى مستند Word",
    icon: "FileDown",
    category: "convert",
    execution: "server" as const,
    href: "/pdf-to-word",
    version: 1, supportedMimeTypes: PDF, limits: BASE_LIMITS, capabilities: ["libreoffice"], securityClass: "isolated", aiEnabled: false, locales: ["en", "ar"],
  },
  {
    id: "excel-to-pdf",
    name: "Excel to PDF",
    nameAr: "Excel إلى PDF",
    description: "Convert Excel spreadsheets to PDF",
    descriptionAr: "تحويل جداول Excel إلى PDF",
    icon: "TableProperties",
    category: "convert",
    execution: "server" as const,
    href: "/excel-to-pdf",
    version: 1, supportedMimeTypes: ["application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"], limits: BASE_LIMITS, capabilities: ["libreoffice"], securityClass: "isolated", aiEnabled: false, locales: ["en", "ar"],
  },
  {
    id: "powerpoint-to-pdf",
    name: "PowerPoint to PDF",
    nameAr: "PowerPoint إلى PDF",
    description: "Convert PowerPoint presentations to PDF",
    descriptionAr: "تحويل عروض PowerPoint إلى PDF",
    icon: "Presentation",
    category: "convert",
    execution: "server" as const,
    href: "/powerpoint-to-pdf",
    version: 1, supportedMimeTypes: ["application/vnd.ms-powerpoint", "application/vnd.openxmlformats-officedocument.presentationml.presentation"], limits: BASE_LIMITS, capabilities: ["libreoffice"], securityClass: "isolated", aiEnabled: false, locales: ["en", "ar"],
  },
  {
    id: "ocr-pdf",
    name: "OCR PDF",
    nameAr: "OCR PDF",
    description: "Make scanned PDFs searchable",
    descriptionAr: "جعل ملفات PDF الممسوحة قابلة للبحث",
    icon: "ScanText",
    category: "ai",
    execution: "server" as const,
    href: "/ocr-pdf",
    version: 1, supportedMimeTypes: [...PDF, ...IMAGE], limits: BASE_LIMITS, capabilities: ["ocrmypdf"], securityClass: "isolated", aiEnabled: false, locales: ["en", "ar"],
  },
  {
    id: "summarize-pdf",
    name: "Summarize PDF",
    nameAr: "تلخيص PDF",
    description: "AI-powered document summarization",
    descriptionAr: "تلخيص المستند بالذكاء الاصطناعي",
    icon: "Sparkles",
    category: "ai",
    execution: "ai" as const,
    href: "/summarize-pdf",
    version: 1, supportedMimeTypes: PDF, limits: BASE_LIMITS, capabilities: ["ai-gateway"], securityClass: "restricted", aiEnabled: true, locales: ["en", "ar"],
  },
  {
    id: "chat-with-pdf",
    name: "Chat with PDF",
    nameAr: "محادثة مع PDF",
    description: "Ask questions about your document",
    descriptionAr: "اسأل أسئلة حول مستندك",
    icon: "MessageSquare",
    category: "ai",
    execution: "ai" as const,
    href: "/chat-with-pdf",
    version: 1, supportedMimeTypes: PDF, limits: BASE_LIMITS, capabilities: ["ai-gateway"], securityClass: "restricted", aiEnabled: true, locales: ["en", "ar"],
  },
  {
    id: "extract-data",
    name: "Extract Data",
    nameAr: "استخراج بيانات",
    description: "Extract structured data from documents",
    descriptionAr: "استخراج بيانات منظمة من المستندات",
    icon: "Database",
    category: "ai",
    execution: "ai" as const,
    href: "/extract-data",
    version: 1, supportedMimeTypes: PDF, limits: BASE_LIMITS, capabilities: ["ai-gateway"], securityClass: "restricted", aiEnabled: true, locales: ["en", "ar"],
  },
] as const satisfies readonly ToolDefinition[];

export const toolRegistry = new Map<string, ToolDefinition>(
  toolsConfig.map((tool) => [tool.id, tool]),
);

export function getTool(toolId: string): ToolDefinition | undefined {
  return toolRegistry.get(toolId);
}
