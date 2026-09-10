import type { Metadata } from "next";
import { siteConfig } from "@/config";
import type { Locale, ToolSeoContent } from "./tool-content";

export const absoluteUrl = (path: string) => new URL(path, siteConfig.url).toString();
export function toolMetadata(content: ToolSeoContent): Metadata {
  const path = `/${content.locale}/tools/${content.slug}`;
  return { title: content.title, description: content.description, alternates: { canonical: path, languages: { en: `/en/tools/${content.slug}`, ar: `/ar/tools/${content.slug}`, "x-default": `/en/tools/${content.slug}` } }, robots: { index: true, follow: true }, openGraph: { type: "website", url: path, title: content.title, description: content.description, siteName: siteConfig.name, locale: content.locale === "ar" ? "ar_SA" : "en_US" }, twitter: { card: "summary", title: content.title, description: content.description } };
}
export function publicMetadata(locale: Locale, title: string, description: string, path: string): Metadata {
  return { title, description, alternates: { canonical: `/${locale}${path}`, languages: { en: `/en${path}`, ar: `/ar${path}`, "x-default": `/en${path}` } } };
}
export const privateMetadata: Metadata = { robots: { index: false, follow: false, noarchive: true } };

