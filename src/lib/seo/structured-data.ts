import { getTool } from "@/config";
import { absoluteUrl } from "./metadata";
import type { ToolSeoContent } from "./tool-content";

export function toolStructuredData(content: ToolSeoContent) {
  const tool = getTool(content.toolId)!; const base = `/${content.locale}`; const url = absoluteUrl(`${base}/tools/${content.slug}`);
  return [
    { "@context": "https://schema.org", "@type": "SoftwareApplication", name: content.h1, description: content.description, url, applicationCategory: "UtilitiesApplication", operatingSystem: "Any", inLanguage: content.locale, offers: { "@type": "Offer", price: "0", priceCurrency: "USD" }, featureList: tool.capabilities.length ? [...tool.capabilities] : content.benefits },
    { "@context": "https://schema.org", "@type": "FAQPage", mainEntity: content.faq.map((item) => ({ "@type": "Question", name: item.question, acceptedAnswer: { "@type": "Answer", text: item.answer } })) },
    { "@context": "https://schema.org", "@type": "BreadcrumbList", itemListElement: [{ "@type": "ListItem", position: 1, name: content.locale === "ar" ? "الرئيسية" : "Home", item: absoluteUrl(base) }, { "@type": "ListItem", position: 2, name: content.locale === "ar" ? "الأدوات" : "Tools", item: absoluteUrl(`${base}/tools`) }, { "@type": "ListItem", position: 3, name: content.h1, item: url }] },
  ];
}
