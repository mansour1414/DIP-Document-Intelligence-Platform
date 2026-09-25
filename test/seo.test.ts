import test from "node:test";
import assert from "node:assert/strict";
import sitemap from "../src/app/sitemap";
import robots from "../src/app/robots";
import { getToolSeo, locales, mvpToolIds, toolSeoContent } from "../src/lib/seo/tool-content";
import { toolMetadata } from "../src/lib/seo/metadata";
import { toolStructuredData } from "../src/lib/seo/structured-data";

test("all MVP tools have complete English and Arabic SEO content", () => {
  assert.ok(mvpToolIds.length >= 24);
  for (const id of mvpToolIds) for (const locale of locales) { const page = getToolSeo(id, locale); assert.ok(page); assert.ok(page.description); assert.ok(page.faq.length >= 3); assert.equal(page.locale, locale); assert.equal(page.slug, id); }
});
test("titles are unique per locale and related IDs resolve", () => {
  for (const locale of locales) { const pages = mvpToolIds.map((id) => getToolSeo(id, locale)); assert.equal(new Set(pages.map((p) => p.title)).size, mvpToolIds.length); for (const page of pages) for (const id of page.relatedTools) assert.ok(mvpToolIds.includes(id)); }
});
test("canonical and hreflang are locale-correct and reciprocal", () => {
  for (const id of mvpToolIds) for (const locale of locales) { const metadata = toolMetadata(getToolSeo(id, locale)); assert.equal(metadata.alternates?.canonical, `/${locale}/tools/${id}`); assert.equal(metadata.alternates?.languages?.en, `/en/tools/${id}`); assert.equal(metadata.alternates?.languages?.ar, `/ar/tools/${id}`); }
});
test("sitemap contains every localized MVP tool page and excludes private routes", () => {
  const urls = sitemap().map((item) => item.url); const toolUrls = urls.filter((url) => /\/(en|ar)\/tools\/[^/]+$/.test(url)); assert.equal(toolUrls.length, mvpToolIds.length * locales.length); for (const id of mvpToolIds) for (const locale of locales) assert.ok(urls.some((url) => url.endsWith(`/${locale}/tools/${id}`))); for (const value of ["dashboard", "/api/", "/jobs/"]) assert.ok(urls.every((url) => !url.includes(value)));
});
test("robots allows public locales and blocks private surfaces", () => { const rules = robots().rules as { allow: string[]; disallow: string[] }; assert.ok(rules.allow.includes("/en/")); assert.ok(rules.allow.includes("/ar/")); for (const path of ["/dashboard", "/api/", "/private/", "/files/", "/jobs/"]) assert.ok(rules.disallow.includes(path)); });
test("visible FAQ and structured FAQ share the registry data", () => { for (const page of Object.values(toolSeoContent)) { const json = toolStructuredData(page); const faq = json[1] as { mainEntity: Array<{ name: string }> }; assert.deepEqual(faq.mainEntity.map((x) => x.name), page.faq.map((x) => x.question)); JSON.stringify(json); } });
test("breadcrumbs are valid and PDF to Word is beta", () => { for (const page of Object.values(toolSeoContent)) { const crumbs = toolStructuredData(page)[2] as { itemListElement: Array<{ position: number }> }; assert.deepEqual(crumbs.itemListElement.map((x) => x.position), [1,2,3]); } for (const locale of locales) assert.equal(getToolSeo("pdf-to-word", locale).status, "beta"); });
test("Arabic routes are explicit and AI privacy never claims local-only", () => { for (const id of mvpToolIds) assert.equal(getToolSeo(id, "ar").locale, "ar"); for (const id of ["summarize-pdf", "chat-with-pdf", "extract-data"] as const) { const note = getToolSeo(id, "en").privacyNote.toLowerCase(); assert.ok(note.includes("ai provider")); assert.ok(!note.includes("never leaves")); } });
test("Office spreadsheet and presentation pages are official and describe server processing realistically", () => { for (const id of ["excel-to-pdf", "powerpoint-to-pdf"] as const) for (const locale of locales) { const page = getToolSeo(id, locale); assert.equal(page.indexability, "index"); assert.match(page.privacyNote, /LibreOffice/); assert.ok(page.privacyNote.includes(locale === "ar" ? "خادمي" : "server-side")); assert.ok(!/perfect|100%|never leaves|محلي فقط/i.test(`${page.intro} ${page.benefits.join(" ")} ${page.privacyNote}`)); } });
