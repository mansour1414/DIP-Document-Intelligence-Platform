import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowRight, BrainCircuit, Languages, LockKeyhole, Workflow } from "lucide-react";
import { HomeUploadLauncher } from "@/components/home/home-upload-launcher";
import { JsonLd } from "@/components/seo/json-ld";
import { SiteFooter } from "@/components/seo/site-footer";
import { SiteHeader } from "@/components/seo/site-header";
import { ToolGrid } from "@/components/tools/tool-grid";
import { Button } from "@/components/ui/button";
import { siteConfig } from "@/config";
import { absoluteUrl, publicMetadata } from "@/lib/seo/metadata";
import { locales, type Locale } from "@/lib/seo/tool-content";

type Params = Promise<{ locale: string }>;

export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> {
  const { locale } = await params;
  const ar = locale === "ar";
  return publicMetadata(locale as Locale, ar ? "DIP — منصة ذكاء المستندات" : "DIP — Document Intelligence Platform", ar ? "أدوات عملية لتحرير وتحويل وقراءة مستندات PDF بالعربية والإنجليزية." : "Practical tools to edit, convert, OCR, and understand PDF documents in English and Arabic.", "");
}

export default async function LocaleHome({ params }: { params: Params }) {
  const { locale } = await params;
  if (!locales.includes(locale as Locale)) notFound();
  const l = locale as Locale;
  const ar = l === "ar";
  const data = [
    { "@context": "https://schema.org", "@type": "WebSite", name: siteConfig.name, url: absoluteUrl(`/${l}`), inLanguage: l },
    { "@context": "https://schema.org", "@type": "Organization", name: siteConfig.name, url: absoluteUrl(`/${l}`) },
  ];
  const sections = ar ? [
    [Workflow, "مسارات قابلة لإعادة الاستخدام", "اجمع أدواتك في مسار واضح، وشغّله مجددًا مع الاحتفاظ بحالة كل خطوة."],
    [BrainCircuit, "ذكاء المستندات", "لخّص الملفات واسأل عنها واستخرج بيانات منظمة عبر بوابة الذكاء الاصطناعي المعتمدة."],
    [LockKeyhole, "معالجة خاصة وواضحة", "تعمل الأدوات المؤهلة داخل المتصفح، وتستخدم الأدوات الخادمية تخزينًا خاصًا وسياسات احتفاظ محددة."],
    [Languages, "العربية والإنجليزية أولاً", "واجهة RTL أصلية، ونص عربي مريح، ودعم OCR بالعربية والإنجليزية."],
  ] : [
    [Workflow, "Reusable workflows", "Combine tools into a clear workflow, run it again, and follow every step’s state."],
    [BrainCircuit, "Document intelligence", "Summarize, ask questions, and extract structured data through the approved AI Gateway."],
    [LockKeyhole, "Private, transparent processing", "Eligible tools run in-browser; server tools use private storage and defined retention controls."],
    [Languages, "Arabic and English first", "Native RTL layouts, comfortable Arabic typography, and bilingual OCR support."],
  ];
  return <>
    <JsonLd data={data} />
    <SiteHeader locale={l} />
    <main id="main-content" className="bg-background text-foreground">
      <section className="relative isolate overflow-hidden">
        <div aria-hidden="true" className="dip-grid-pattern absolute inset-0 -z-10" />
        <div className="dip-container pb-8 pt-14 text-center sm:pt-18">
          <p className="text-sm font-bold uppercase tracking-[0.16em] text-primary">DIP · Document Intelligence Platform</p>
          <h1 className="mx-auto mt-3 max-w-4xl text-4xl font-black tracking-tight text-balance sm:text-6xl">{ar ? "كل أدوات مستنداتك في مكان واحد" : "Every document tool, in one place"}</h1>
          <p className="mx-auto mt-4 max-w-2xl text-base leading-7 text-muted-foreground sm:text-lg">{ar ? "حرّر ملفات PDF وحوّلها واجعلها قابلة للبحث وافهم محتواها، بخطوات مباشرة ودعم عربي كامل." : "Edit, convert, search, and understand documents with direct tools and first-class Arabic support."}</p>
        </div>
      </section>
      <HomeUploadLauncher locale={l} />
      <section aria-labelledby="tools-heading" className="border-b pb-16">
        <div className="dip-container">
          <div className="mb-5 flex items-end justify-between gap-4"><div><h2 id="tools-heading" className="text-2xl font-black sm:text-3xl">{ar ? "اختر أداتك" : "Choose your tool"}</h2><p className="mt-1 text-sm text-muted-foreground">{ar ? "جميع أدوات DIP الرسمية الثماني عشرة." : "All 18 official DIP tools."}</p></div><Button asChild variant="ghost" className="hidden sm:inline-flex"><Link href={`/${l}/tools`}>{ar ? "دليل الأدوات" : "Tools directory"}<ArrowRight aria-hidden="true" className="rtl:rotate-180" /></Link></Button></div>
          <ToolGrid locale={l} />
        </div>
      </section>
      <section className="bg-muted/40 py-16"><div className="dip-container grid gap-4 md:grid-cols-2">{sections.map(([Icon, title, text], index) => <article key={String(title)} className="rounded-2xl border bg-card p-6 shadow-sm"><Icon aria-hidden="true" className="h-7 w-7 text-primary" /><h2 className="mt-5 text-xl font-bold">{String(title)}</h2><p className="mt-2 leading-7 text-muted-foreground">{String(text)}</p>{index === 0 && <Link className="mt-4 inline-flex font-semibold text-primary hover:underline" href={`/${l}/workflows`}>{ar ? "افتح مسارات العمل" : "Open workflows"}</Link>}</article>)}</div></section>
      <section className="border-t py-14"><div className="dip-container flex flex-col items-center justify-between gap-5 rounded-2xl bg-foreground px-6 py-10 text-center text-background sm:px-10 md:flex-row md:text-start"><div><h2 className="text-2xl font-black">{ar ? "ابدأ بالأدوات المجانية" : "Start with the free tools"}</h2><p className="mt-2 opacity-75">{ar ? "راجع الخطط والحدود الحالية بدون ادعاءات أو رسوم مخفية." : "Review current plans and limits with no invented claims or hidden checkout."}</p></div><Button asChild size="lg"><Link href={`/${l}/pricing`}>{ar ? "عرض الخطط" : "View plans"}</Link></Button></div></section>
    </main>
    <SiteFooter locale={l} />
  </>;
}
