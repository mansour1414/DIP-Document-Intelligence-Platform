import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

test("semantic brand tokens keep brand and destructive actions distinct", () => {
  const css = read("src/app/globals.css");
  assert.match(css, /--primary:\s*#6f1938/);
  assert.match(css, /--destructive:\s*#b42318/);
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
  assert.match(header, /aria-current/);
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
