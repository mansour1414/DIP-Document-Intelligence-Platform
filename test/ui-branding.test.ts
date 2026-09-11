import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

test("semantic coral brand tokens keep brand and destructive actions distinct in both themes", () => {
  const css = read("src/app/globals.css");
  assert.match(css, /--primary:\s*#d83d31/);
  assert.match(css, /--destructive:\s*#b91c1c/);
  assert.match(css, /\.dark\s*\{/);
  assert.notEqual(css.match(/--primary:\s*(#[0-9a-f]+)/i)?.[1], css.match(/--destructive:\s*(#[0-9a-f]+)/i)?.[1]);
  for (const token of ["background", "foreground", "card", "popover", "secondary", "muted", "accent", "border", "input", "ring"]) {
    assert.match(css, new RegExp(`--${token}:`));
  }
});

test("Arabic typography and reduced motion are explicit", () => {
  const css = read("src/app/globals.css");
  assert.match(css, /noto-sans-arabic/);
  assert.match(css, /\[dir="rtl"\]/);
  assert.match(css, /prefers-reduced-motion:\s*reduce/);
});

test("navigation exposes localized primary routes and a mobile sheet", () => {
  const header = read("src/components/seo/site-header.tsx");
  for (const route of ["tools", "workflows", "pricing"]) assert.match(header, new RegExp(route));
  assert.match(header, /SheetContent/);
  assert.match(header, /All PDF tools/);
  assert.match(header, /ThemeToggle/);
});

test("theme defaults to system, persists preference, and initializes before hydration", () => {
  const provider = read("src/components/theme/theme-provider.tsx");
  const layout = read("src/app/layout.tsx");
  assert.match(provider, /"light" \| "dark" \| "system"/);
  assert.match(provider, /localStorage\.setItem\("dip-theme"/);
  assert.match(provider, /prefers-color-scheme: dark/);
  assert.match(layout, /suppressHydrationWarning/);
  assert.match(layout, /localStorage\.getItem\('dip-theme'\)\|\|'system'/);
});

test("homepage catalog contains exactly the 18 official localized tools", async () => {
  const { mvpToolIds } = await import("../src/lib/seo/tool-content");
  const { toolGroups } = await import("../src/components/tools/tool-catalog");
  assert.equal(mvpToolIds.length, 18);
  assert.equal(new Set(toolGroups.flatMap((group) => group.tools)).size, 18);
  assert.deepEqual(new Set(toolGroups.flatMap((group) => group.tools)), new Set(mvpToolIds));
  const card = read("src/components/tools/tool-card.tsx");
  assert.match(card, /`\/\$\{locale\}\/tools\/\$\{toolId\}`/);
  assert.match(card, /nameAr/);
});

test("workflow motion is reduced-motion aware and preserves API execution boundary", () => {
  const manager = read("src/components/workflows/workflow-manager.tsx");
  assert.match(manager, /from "motion\/react"/);
  assert.match(manager, /useReducedMotion/);
  assert.match(manager, /\/api\/workflows/);
  assert.doesNotMatch(manager, /worker|executeTool|shell/i);
});

test("disallowed animation and UI kits were not added", () => {
  const pkg = JSON.parse(read("package.json")) as { dependencies?: Record<string, string> };
  for (const name of ["gsap", "lenis", "@formkit/auto-animate", "@headlessui/react", "magic-ui", "aceternity-ui"]) {
    assert.equal(pkg.dependencies?.[name], undefined);
  }
  assert.equal(pkg.dependencies?.motion, "13.2.0");
});
