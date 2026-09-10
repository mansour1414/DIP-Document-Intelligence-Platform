"use client";
import { useEffect } from "react";
import Link from "next/link";
import { track } from "@/lib/analytics";
export function PricingAnalytics({ locale }: { locale: "en" | "ar" }) {
  useEffect(() => { track({ name: "pricing_view", language: locale, page_path: window.location.pathname }); }, [locale]);
  return <Link href="/signup" onClick={() => track({ name: "upgrade_intent", language: locale, page_path: window.location.pathname })} className="inline-flex min-h-11 items-center rounded-lg bg-primary px-5 font-semibold text-primary-foreground shadow-sm transition-colors hover:bg-primary-hover focus-visible:ring-2 focus-visible:ring-ring">{locale === "ar" ? "سجّل اهتمامك بخطة Pro" : "Register interest in Pro"}</Link>;
}
