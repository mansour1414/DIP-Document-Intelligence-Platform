import { notFound } from "next/navigation";
import { locales } from "@/lib/seo/tool-content";
export function generateStaticParams() { return locales.map((locale) => ({ locale })); }
export default async function LocaleLayout({ children, params }: { children: React.ReactNode; params: Promise<{ locale: string }> }) { const { locale } = await params; if (!locales.includes(locale as "en" | "ar")) notFound(); return <div lang={locale} dir={locale === "ar" ? "rtl" : "ltr"}>{children}</div>; }

