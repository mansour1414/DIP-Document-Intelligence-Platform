"use client";
import { useEffect } from "react";
import Link from "next/link";
import { track } from "@/lib/analytics";
export function PricingAnalytics({ locale }: { locale: "en" | "ar" }) {
  useEffect(() => { track({ name: "pricing_view", language: locale, page_path: window.location.pathname }); }, [locale]);
  return <Link href="/signup" onClick={() => track({ name: "upgrade_intent", language: locale, page_path: window.location.pathname })} className="inline-flex min-h-11 items-center rounded-lg bg-blue-700 px-5 font-semibold text-white hover:bg-blue-800">{locale === "ar" ? "سجّل اهتمامك بخطة Pro" : "Register interest in Pro"}</Link>;
}
