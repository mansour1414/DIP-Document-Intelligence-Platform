#!/usr/bin/env node
// Independent Chromium fixture generator and PDF.js text reader for Stage 3A.
// This file is QA-only and is not imported by the DIP application or worker.

import fs from "node:fs/promises";
import path from "node:path";

function clamp(value) {
  return Math.max(0, Math.min(1, value));
}

function linear(value) {
  value = clamp(value / 255);
  return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
}

function encode(value) {
  value = clamp(value);
  return value <= 0.0031308 ? 12.92 * value : 1.055 * value ** (1 / 2.4) - 0.055;
}

function gray(red, green, blue) {
  return Math.round(255 * encode(0.2126 * linear(red) + 0.7152 * linear(green) + 0.0722 * linear(blue)));
}

function html(grayscale) {
  const colors = [
    [215, 35, 65],
    [25, 120, 220],
    [20, 155, 90],
  ].map(([r, g, b]) => {
    if (!grayscale) return `rgb(${r},${g},${b})`;
    const value = gray(r, g, b);
    return `rgb(${value},${value},${value})`;
  });
  return `<!doctype html>
<html lang="ar" dir="rtl"><head><meta charset="utf-8">
<style>
@page { size: A4; margin: 18mm; }
body { font-family: "Arial", "Noto Sans Arabic", sans-serif; margin: 0; color: ${colors[0]}; }
h1 { color: ${colors[1]}; font-size: 25px; margin: 0 0 18px; }
p { font-size: 18px; line-height: 1.8; margin: 12px 0; }
.panel { border: 3px solid ${colors[0]}; background: ${colors[2]}; color: white; padding: 18px; border-radius: 8px; }
a { color: ${colors[1]}; }
</style></head><body>
<h1>اختبار الترتيب المنطقي للنص العربي</h1>
<p id="primary">مرحلة المحرك البنيوي الثالثة تحافظ على النص العربي القابل للبحث والنسخ.</p>
<p>الرقم 12345، والبريد test@example.com، والعبارة الإنجليزية Stage 3A تبقى في مواضعها.</p>
<div class="panel">نص عربي مستقل مولد بواسطة Chromium للتحقق متعدد القارئات.</div>
<p><a href="https://example.com/stage3a">رابط اختبار البنية</a></p>
</body></html>`;
}

async function generate(directory) {
  await fs.mkdir(directory, { recursive: true });
  const fixtureDirectory = process.env.DIP_STAGE3A_FIXTURE_DIR;
  if (fixtureDirectory) {
    for (const name of ["arabic-logical-source.pdf", "arabic-logical-expected.pdf"]) {
      await fs.copyFile(path.join(fixtureDirectory, name), path.join(directory, name));
    }
    return;
  }
  const { chromium } = await import("playwright");
  const browser = await chromium.launch({ headless: true });
  try {
    for (const [name, grayscale] of [["arabic-logical-source.pdf", false], ["arabic-logical-expected.pdf", true]]) {
      const page = await browser.newPage({ locale: "ar-SA" });
      await page.setContent(html(grayscale), { waitUntil: "load" });
      await page.pdf({
        path: path.join(directory, name),
        format: "A4",
        printBackground: true,
        preferCSSPageSize: true,
        tagged: true,
      });
      await page.close();
    }
  } finally {
    await browser.close();
  }
}

function widgetHtml(value, grayscale) {
  const color = grayscale ? gray(194, 26, 89) : null;
  const cssColor = grayscale ? `rgb(${color},${color},${color})` : "rgb(194,26,89)";
  return `<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<style>
@page { size: 500px 70px; margin: 0; }
html, body { width: 500px; height: 70px; margin: 0; overflow: hidden; }
body { box-sizing: border-box; padding: 18px 12px; color: ${cssColor};
  font: 16px/1.5 "Noto Sans Arabic", "Arial", sans-serif; white-space: nowrap; }
</style></head><body>${value}</body></html>`;
}

async function generateStage3cWidgets(directory) {
  await fs.mkdir(directory, { recursive: true });
  const original = [
    "قيمة عربية قابلة للتحرير والبحث",
    "DIP 3C قيمة مختلطة 12345 test@example.com",
  ];
  const edited = [
    "تم تعديل القيمة العربية بأمان",
    "Edited آمن 67890 grayscale@example.com",
  ];
  const groups = [
    ["source", original, false],
    ["expected", original, true],
    ["edited-gray", edited, true],
    ["edited-color", edited, false],
  ];
  const { chromium } = await import("playwright");
  const browser = await chromium.launch({ headless: true });
  try {
    for (const [variant, values, grayscale] of groups) {
      for (const [index, value] of values.entries()) {
        const page = await browser.newPage({ locale: "ar-SA" });
        await page.setContent(widgetHtml(value, grayscale), { waitUntil: "load" });
        await page.pdf({
          path: path.join(directory, `${variant}-${index}.pdf`),
          width: "500px",
          height: "70px",
          printBackground: true,
          tagged: true,
        });
        await page.close();
      }
    }
  } finally {
    await browser.close();
  }
}

async function extract(pdfPath) {
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs");
  const data = new Uint8Array(await fs.readFile(pdfPath));
  const loadingTask = pdfjs.getDocument({ data, disableWorker: true });
  const document = await loadingTask.promise;
  const pages = [];
  try {
    for (let pageNumber = 1; pageNumber <= document.numPages; pageNumber += 1) {
      const page = await document.getPage(pageNumber);
      const content = await page.getTextContent();
      pages.push(content.items.map((item) => item.str).join(" "));
    }
  } finally {
    await loadingTask.destroy();
  }
  process.stdout.write(JSON.stringify({ pages, text: pages.join("\n") }));
}

const [command, target] = process.argv.slice(2);
if (command === "generate" && target) {
  await generate(path.resolve(target));
} else if (command === "generate-stage3c-widgets" && target) {
  await generateStage3cWidgets(path.resolve(target));
} else if (command === "extract" && target) {
  await extract(path.resolve(target));
} else {
  throw new Error("usage: structural-grayscale-stage3a-browser.mjs generate <dir> | generate-stage3c-widgets <dir> | extract <pdf>");
}
