"use client";

import { createContext, useContext, useEffect, useState } from "react";
import { Languages } from "lucide-react";

type Locale = "en" | "ar";
const LocaleContext = createContext<{ locale: Locale; toggleLocale: () => void }>({ locale: "en", toggleLocale: () => undefined });

export function LocaleProvider({ children }: { children: React.ReactNode }) {
  const [locale, setLocale] = useState<Locale>("en");
  useEffect(() => {
    document.documentElement.lang = locale;
    document.documentElement.dir = locale === "ar" ? "rtl" : "ltr";
    window.localStorage.setItem("dip-locale", locale);
  }, [locale]);
  return <LocaleContext.Provider value={{ locale, toggleLocale: () => setLocale((value) => value === "en" ? "ar" : "en") }}>{children}</LocaleContext.Provider>;
}

export function useLocale() { return useContext(LocaleContext); }

export function LanguageToggle() {
  const { locale, toggleLocale } = useLocale();
  const next = locale === "en" ? "العربية" : "English";
  return <button type="button" onClick={toggleLocale} aria-label={`Switch language to ${next}`} className="inline-flex min-h-10 items-center gap-1.5 rounded-lg border border-slate-300 px-3 text-sm font-semibold text-slate-700 transition-colors hover:border-blue-500 hover:bg-blue-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-600" aria-pressed={locale === "ar"}><Languages aria-hidden="true" className="h-4 w-4" />{next}</button>;
}
