import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { createHmac } from "node:crypto";

const phase1Remaining = ["split-pdf-by-size", "split-pdf-by-bookmarks", "split-pdf-by-text", "n-up-pdf", "remove-annotations"];
const publicPages = ["/en", "/en/tools", "/en/tools/merge-pdf", "/en/tools/crop-pdf", "/en/tools/page-numbers", "/en/tools/header-footer", "/en/tools/resize-pages", "/en/tools/alternate-mix", "/en/tools/flip-pages", ...phase1Remaining.map((tool) => `/en/tools/${tool}`), "/en/tools/ocr-pdf", "/en/tools/summarize-pdf", "/en/login", "/ar", "/ar/tools", "/ar/tools/merge-pdf", "/ar/tools/crop-pdf", "/ar/tools/page-numbers", "/ar/tools/header-footer", "/ar/tools/resize-pages", "/ar/tools/alternate-mix", "/ar/tools/flip-pages", ...phase1Remaining.map((tool) => `/ar/tools/${tool}`), "/ar/tools/ocr-pdf", "/ar/tools/summarize-pdf", "/ar/login"];

for (const path of publicPages) {
  test(`${path} renders responsively without serious accessibility violations`, async ({ page }) => {
    await page.goto(path);
    await expect(page.locator("h1").first()).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
    if (path.startsWith("/ar")) await expect(page.locator('[dir="rtl"]').first()).toBeVisible();
    const results = await new AxeBuilder({ page }).analyze();
    expect(results.violations.filter((item) => ["critical", "serious"].includes(item.impact ?? ""))).toEqual([]);
  });
}

test("public navigation and keyboard focus remain usable", async ({ page }) => {
  await page.goto("/en");
  await page.keyboard.press("Tab");
  const focused = page.locator(":focus");
  await expect(focused).toBeVisible();
  expect(await focused.evaluate((element) => ["A", "BUTTON", "INPUT"].includes(element.tagName))).toBe(true);
  const styles = await focused.evaluate((element) => { const value = getComputedStyle(element); return { outline: value.outlineStyle, shadow: value.boxShadow }; });
  expect(styles.outline !== "none" || styles.shadow !== "none").toBe(true);
  await page.goto("/en/tools");
  await page.getByRole("link", { name: /merge pdf/i }).first().click();
  await expect(page).toHaveURL(/\/en\/tools\/merge-pdf$/);
});

test.describe("authenticated product surfaces", () => {
  test.skip(process.env.AUTH_BROWSER_E2E !== "1", "Requires the CI-seeded browser user");
  test.beforeEach(async ({ context }) => {
    const payload = Buffer.from(JSON.stringify({ sub: "b0000000-0000-4000-8000-000000000001", exp: Math.floor(Date.now() / 1000) + 3600 })).toString("base64url");
    const signature = createHmac("sha256", process.env.AUTH_SECRET ?? "release-b-browser-secret").update(payload).digest("base64url");
    await context.addCookies([{ name: "dip_session", value: `${payload}.${signature}`, domain: "127.0.0.1", path: "/", httpOnly: true, sameSite: "Lax" }]);
  });
  for (const locale of ["en", "ar"] as const) {
    for (const route of ["dashboard", "workflows", "agent"] as const) {
      test(`${locale} ${route} uses real authenticated application rendering`, async ({ page }) => {
        await page.goto(`/${locale}/${route}`);
        await expect(page).toHaveURL(new RegExp(`/${locale}/${route}$`));
        await expect(page.locator("h1").first()).toBeVisible();
        if (locale === "ar") await expect(page.locator('[dir="rtl"]').first()).toBeVisible();
        const results = await new AxeBuilder({ page }).analyze();
        expect(results.violations.filter((item) => ["critical", "serious"].includes(item.impact ?? ""))).toEqual([]);
      });
    }
  }
});
