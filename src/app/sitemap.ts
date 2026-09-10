import type { MetadataRoute } from "next";
import { siteConfig } from "@/config";
import { locales, mvpToolIds } from "@/lib/seo/tool-content";
export default function sitemap(): MetadataRoute.Sitemap { const now = new Date(); const paths = locales.flatMap((locale) => [ `/${locale}`, `/${locale}/tools`, `/${locale}/pricing`, ...mvpToolIds.map((tool) => `/${locale}/tools/${tool}`) ]); return paths.map((path) => ({ url: new URL(path, siteConfig.url).toString(), lastModified: now, changeFrequency: path.includes("/tools/") ? "monthly" : "weekly", priority: path.endsWith("/tools") ? 0.9 : path.split("/").length === 4 ? 0.8 : 0.7 })); }

