import type { MetadataRoute } from "next";
import { siteConfig } from "@/config";
export default function robots(): MetadataRoute.Robots { return { rules: { userAgent: "*", allow: ["/en/", "/ar/"], disallow: ["/dashboard", "/api/", "/private/", "/files/", "/jobs/", "/login", "/signup"] }, sitemap: new URL("/sitemap.xml", siteConfig.url).toString() }; }

