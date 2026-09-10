"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Languages, Menu } from "lucide-react";
import type { Locale } from "@/lib/seo/tool-content";
import { BrandMark } from "@/components/brand/brand-mark";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { cn } from "@/lib/utils";

export function SiteHeader({ locale }: { locale: Locale }) {
  const ar = locale === "ar"; const pathname = usePathname();
  const links = [{ href: `/${locale}/tools`, label: ar ? "الأدوات" : "Tools" }, { href: `/${locale}/workflows`, label: ar ? "مسارات العمل" : "Workflows" }, { href: `/${locale}/pricing`, label: ar ? "الخطط" : "Pricing" }];
  const nav = (mobile = false) => <nav aria-label={ar ? "التنقل الرئيسي" : "Main navigation"} className={cn(mobile ? "grid gap-1" : "hidden items-center gap-1 md:flex")}>{links.map((link) => { const active = pathname === link.href || pathname.startsWith(`${link.href}/`); return <Link key={link.href} href={link.href} aria-current={active ? "page" : undefined} className={cn("rounded-lg px-3 py-2 text-sm font-semibold transition-colors focus-visible:ring-2 focus-visible:ring-ring", active ? "bg-secondary text-secondary-foreground" : "text-muted-foreground hover:bg-accent hover:text-accent-foreground", mobile && "min-h-11 text-base")}>{link.label}</Link>; })}</nav>;
  return <header className="sticky top-0 z-40 border-b border-border/80 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/85"><div className="dip-container flex min-h-16 items-center gap-4"><BrandMark href={`/${locale}`} />{nav()}<div className="ms-auto hidden items-center gap-2 md:flex"><Button asChild variant="ghost" size="sm"><Link href={ar ? "/en" : "/ar"} hrefLang={ar ? "en" : "ar"} lang={ar ? "en" : "ar"}><Languages aria-hidden="true" />{ar ? "English" : "العربية"}</Link></Button><Button asChild size="sm"><Link href="/login">{ar ? "تسجيل الدخول" : "Sign in"}</Link></Button></div><Sheet><SheetTrigger asChild><Button className="ms-auto md:hidden" variant="outline" size="icon" aria-label={ar ? "فتح القائمة" : "Open menu"}><Menu aria-hidden="true" /></Button></SheetTrigger><SheetContent side="end"><SheetTitle className="text-xl font-semibold">{ar ? "التنقل" : "Navigation"}</SheetTitle><SheetDescription className="text-sm text-muted-foreground">{ar ? "انتقل إلى أدوات DIP ومسارات العمل والخطط." : "Go to DIP tools, workflows, and plans."}</SheetDescription>{nav(true)}<div className="mt-auto grid gap-2"><Button asChild variant="outline"><Link href={ar ? "/en" : "/ar"} hrefLang={ar ? "en" : "ar"} lang={ar ? "en" : "ar"}><Languages aria-hidden="true" />{ar ? "English" : "العربية"}</Link></Button><Button asChild><Link href="/login">{ar ? "تسجيل الدخول" : "Sign in"}</Link></Button></div></SheetContent></Sheet></div></header>;
}
