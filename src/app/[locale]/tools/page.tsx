import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { SiteFooter } from "@/components/seo/site-footer";
import { SiteHeader } from "@/components/seo/site-header";
import { ToolGrid } from "@/components/tools/tool-grid";
import { publicMetadata } from "@/lib/seo/metadata";
import { locales, type Locale } from "@/lib/seo/tool-content";

type Params = Promise<{ locale: string }>;

export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> {
  const { locale } = await params;
  const ar = locale === "ar";
  return publicMetadata(locale as Locale, ar ? "أدوات PDF والمستندات | DIP" : "PDF & Document Tools | DIP", ar ? "استكشف 18 أداة لمعالجة وتحويل وفهم المستندات بالعربية والإنجليزية." : "Explore 18 tools to edit, convert, OCR, and understand documents in English and Arabic.", "/tools");
}

export default async function ToolsPage({ params }: { params: Params }) {
  const { locale } = await params;
  if (!locales.includes(locale as Locale)) notFound();
  const l = locale as Locale;
  const ar = l === "ar";
  return <><SiteHeader locale={l}/><main id="main-content" className="min-h-screen bg-muted/35 py-14"><header className="dip-container dip-page-header text-center"><p className="text-sm font-semibold uppercase tracking-[0.18em] text-primary">DIP</p><h1 className="mt-3 text-4xl font-bold tracking-tight sm:text-5xl">{ar ? "أدوات المستندات" : "Document tools"}</h1><p className="mt-4 text-lg leading-8 text-muted-foreground">{ar ? "اختر من أدوات DIP الثماني عشرة لتحرير ملفات PDF وتحويلها وفهمها." : "Choose from all 18 DIP tools to edit, convert, recognize, and understand documents."}</p></header><section aria-label={ar ? "دليل الأدوات" : "Tools directory"} className="dip-container mt-10"><ToolGrid locale={l}/></section></main><SiteFooter locale={l}/></>;
}

export function generateStaticParams() { return locales.map((locale) => ({ locale })); }
