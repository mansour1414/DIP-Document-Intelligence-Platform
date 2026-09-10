"use client";

import { createContext, useContext, useEffect, useState } from "react";
import { Languages } from "lucide-react";
import { Button } from "@/components/ui/button";

type Locale = "en" | "ar";
const LocaleContext = createContext<{ locale: Locale; toggleLocale: () => void }>({ locale: "en", toggleLocale: () => undefined });

export function LocaleProvider({ children, initialLocale = "en" }: { children: React.ReactNode; initialLocale?: Locale }) {
  const [locale, setLocale] = useState<Locale>(initialLocale);
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
  return <Button type="button" variant="outline" onClick={toggleLocale} aria-label={`Switch language to ${next}`} aria-pressed={locale === "ar"}><Languages aria-hidden="true" />{next}</Button>;
}
