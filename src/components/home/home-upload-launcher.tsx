import Link from "next/link";
import { ArrowRight, Upload } from "lucide-react";
import type { Locale } from "@/lib/seo/tool-content";

export function HomeUploadLauncher({ locale }: { locale: Locale }) {
  const ar = locale === "ar";
  return <section aria-label={ar ? "بدء معالجة مستند" : "Start processing a document"} className="relative pb-10">
    <div className="dip-container">
      <Link href={`/${locale}/tools/merge-pdf`} className="dip-glass dip-sweep group relative mx-auto flex min-h-48 max-w-4xl flex-col items-center justify-center overflow-hidden rounded-3xl border border-dashed border-info/30 px-6 py-8 text-center shadow-elevated transition-[transform,border-color,box-shadow] hover:-translate-y-1 hover:border-info/60 hover:shadow-[0_0_48px_-18px_rgb(34_211_238_/.65)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
        <span aria-hidden="true" className="absolute inset-0 bg-[radial-gradient(circle_at_50%_0%,rgb(34_211_238_/.12),transparent_58%)]" />
        <span className="relative grid h-16 w-16 place-items-center rounded-3xl border border-info/25 bg-info-surface text-info shadow-[0_0_28px_-12px_rgb(34_211_238_/.7)]"><Upload aria-hidden="true" className="h-7 w-7" /></span>
        <h2 className="relative mt-5 text-xl font-black sm:text-2xl">{ar ? "ارفع مستندك وابدأ" : "Upload a document and get started"}</h2>
        <p className="relative mt-2 max-w-xl text-sm leading-6 text-muted-foreground sm:text-base">{ar ? "افتح مساحة دمج PDF الحقيقية لاختيار ملفاتك، أو اختر أداة أخرى من القائمة أدناه." : "Open the real Merge PDF workspace to choose files, or select another tool from the catalog below."}</p>
        <span className="relative mt-5 inline-flex min-h-11 items-center rounded-xl bg-primary px-5 py-2.5 text-sm font-bold text-primary-foreground shadow-[0_0_24px_-10px_rgb(34_211_238_/.7)]">{ar ? "اختيار ملفات PDF" : "Choose PDF files"}<ArrowRight aria-hidden="true" className="ms-2 h-4 w-4 rtl:rotate-180" /></span>
      </Link>
    </div>
  </section>;
}
