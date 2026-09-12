import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

test("official DIP blue, indigo, cyan and violet tokens keep brand distinct from destructive actions", () => {
  const css = read("src/app/globals.css");
  assert.match(css, /--dip-neon-cyan:\s*#00f5ff/);
  assert.match(css, /--dip-electric-blue:\s*#0ea5e9/);
  assert.match(css, /--dip-cyber-indigo:\s*#4f46e5/);
  assert.match(css, /--dip-violet:\s*#7c3aed/);
  assert.match(css, /--primary:\s*#2563eb/);
  assert.match(css, /--destructive:\s*#b91c1c/);
  assert.match(css, /\.dark\s*\{/);
  assert.notEqual(css.match(/--primary:\s*(#[0-9a-f]+)/i)?.[1], css.match(/--destructive:\s*(#[0-9a-f]+)/i)?.[1]);
  for (const token of ["background", "foreground", "card", "popover", "secondary", "muted", "accent", "border", "input", "ring"]) {
    assert.match(css, new RegExp(`--${token}:`));
  }
});

test("official SVG logo asset is used by the shared brand component", () => {
  const logo = read("src/components/brand/brand-mark.tsx");
  const asset = read("public/brand/dip-logo.svg");
  assert.match(logo, /\/brand\/dip-logo\.svg/);
  assert.match(asset, /viewBox="0 0 176\.8 94"/);
  assert.match(asset, /#23D2ED/i);
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
