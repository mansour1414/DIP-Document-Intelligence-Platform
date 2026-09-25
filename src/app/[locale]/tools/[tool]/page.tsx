import { notFound } from "next/navigation";
import type { Metadata } from "next";
import { getTool } from "@/config";
import { AiToolWorkspace } from "@/components/tools/ai-tool-workspace";
import { PdfToolWorkspace } from "@/components/tools/pdf-tool-workspace";
import { ServerToolWorkspace } from "@/components/tools/server-tool-workspace";
import { ToolSeoPage } from "@/components/seo/tool-seo-page";
import { LocaleProvider } from "@/components/i18n/locale-provider";
import { getToolSeo, isMvpTool, locales, mvpToolIds, type Locale } from "@/lib/seo/tool-content";
import { toolMetadata } from "@/lib/seo/metadata";

type Params = Promise<{ locale: string; tool: string }>;
export function generateStaticParams() { return locales.flatMap((locale) => mvpToolIds.map((tool) => ({ locale, tool }))); }
export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> { const { locale, tool } = await params; if (!locales.includes(locale as Locale) || !isMvpTool(tool)) return {}; return toolMetadata(getToolSeo(tool, locale as Locale)); }
export default async function Page({ params }: { params: Params }) { const { locale, tool: id } = await params; if (!locales.includes(locale as Locale) || !isMvpTool(id)) notFound(); const tool = getTool(id)!; const content = getToolSeo(id, locale as Locale); const documentWorkerTools = new Set(["word-to-pdf", "pdf-to-word", "excel-to-pdf", "powerpoint-to-pdf", "ocr-pdf"]); const workspace = tool.execution === "ai" ? <AiToolWorkspace tool={tool} embedded /> : documentWorkerTools.has(id) ? <ServerToolWorkspace tool={tool} embedded /> : <PdfToolWorkspace tool={tool} embedded />; return <LocaleProvider initialLocale={locale as Locale}><ToolSeoPage content={content} workspace={workspace} /></LocaleProvider>; }
