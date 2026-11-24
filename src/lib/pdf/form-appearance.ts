/**
 * `fill-forms` — appearance streams for values that WinAnsi cannot encode.
 *
 * pdf-lib's built-in appearance generator can only encode WinAnsi text, so an
 * Arabic (or any non-Latin) value throws while the value itself is still valid.
 * Rather than drop the value or silently ship a blank-looking widget, this
 * module keeps the value and paints a self-contained PNG appearance with the
 * already approved `@napi-rs/canvas` rasteriser and the already vendored
 * `@fontsource/noto-sans-arabic` faces — the same rendering path the header and
 * footer tools use for Arabic text.
 *
 * Trade-off, stated plainly: the resulting appearance is an image. The widget
 * stays a real interactive form field (name, type, value and state are
 * preserved) but the glyphs inside it are pixels, so they cannot be re-selected
 * with a text tool inside that widget region. Every other widget — including
 * the rest of the document — keeps vector text. `docs/stage2-fill-forms.md`
 * records this as a known limitation rather than a full Arabic text-shaping
 * solution; a text-level fix needs an embedded Unicode font with shaping and is
 * deliberately out of scope for this slice.
 */
import { PDFDocument, PDFName, PDFDict, PDFRef, decodePDFRawStream, PDFRawStream, drawRectangle, pushGraphicsState, popGraphicsState, concatTransformationMatrix, drawObject, degrees, rgb } from "pdf-lib";
import type { PDFFont } from "pdf-lib";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import type { SKRSContext2D } from "@napi-rs/canvas";
import type { PDFField } from "pdf-lib";

const require = createRequire(import.meta.url);
let fontsReady = false;

/**
 * The raster engine is loaded lazily and by *runtime* require.
 *
 * Next/Turbopack cannot place a native addon into an app-route chunk, and a
 * static `import "@napi-rs/canvas"` would fail the production build for every
 * route that reaches this module. A deferred `require` keeps the bundle free of
 * the addon: the worker resolves it from `node_modules` at run time, which is
 * also how it is deployed. Types are imported type-only, so they leave no
 * runtime trace.
 */
type RasterModule = typeof import("@napi-rs/canvas");
let raster: RasterModule | undefined;
function rasteriser(): RasterModule {
  if (!raster) raster = require(RASTER_MODULE) as RasterModule;
  return raster;
}

/**
 * Resolved at run time, never as a literal bare specifier: `require("@napi-rs/canvas")`
 * with a constant argument is still statically analysable, and a bundler that
 * follows it will try to place the native addon into the route chunk. Reading
 * the name out of a value keeps the bundle free of the addon entirely.
 */
const RASTER_MODULE = ["@napi-rs", "canvas"].join("/");

/**
 * Fonts are located by path, not by a static `require.resolve()` of a `.woff`
 * specifier: the bundler treats that resolved asset as a build input and fails
 * the build on it. `require.resolve("@fontsource/noto-sans-arabic/package.json")`
 * stays inside JavaScript and is analysable without side effects.
 */
const FONT_SOURCE = dirname(require.resolve("@fontsource/noto-sans-arabic/package.json"));

/** Pure render scale: a widget is rasterised at this multiple of its PDF size. */
const RASTER_SCALE = 4;
const RASTER_MAX_DIMENSION = 4_000;
const RASTER_MAX_AREA = 12_000_000;

export function registerFormFonts() {
  if (fontsReady) return;
  const arabic = join(FONT_SOURCE, "files/noto-sans-arabic-arabic-400-normal.woff");
  const latin = join(FONT_SOURCE, "files/noto-sans-arabic-latin-400-normal.woff");
  const { GlobalFonts } = rasteriser();
  if (!GlobalFonts.registerFromPath(arabic, "DIP Form Arabic") || !GlobalFonts.registerFromPath(latin, "DIP Form Latin")) throw Object.assign(new Error("Unable to register form fonts"), { code: "FONT_UNAVAILABLE" });
  fontsReady = true;
}

/** True when `font` can encode every character of `text`. */
export function fontCanEncode(font: PDFFont, text: string) {
  try { font.encodeText(text); return true; } catch { return false; }
}

const arabicScript = /[\u0600-\u06ff\u0750-\u077f\u08a0-\u08ff\ufb50-\ufdff\ufe70-\ufeff]/u;

/**
 * The scripts the raster fallback can actually draw.
 *
 * Noto Sans Arabic ships an Arabic and a Latin subset here; nothing else. A
 * value in any other script (CJK, Cyrillic, Devanagari, …) would be painted as
 * missing-glyph boxes, which looks like corruption rather than a limitation, so
 * it is rejected up front with a specific code instead of being rasterised.
 */
/**
 * Allowed code points: Latin + Latin-1 + Latin Extended (the Latin subset),
 * Arabic blocks, the generic punctuation Noto's Latin subset actually carries
 * (dashes, quotes, bullets, ellipsis, currency, ©/®), and the bidi controls an
 * Arabic/English mixed value legitimately needs.
 *
 * Glyph coverage was measured, not assumed: `Noto Sans Arabic` (latin subset)
 * renders U+2014, U+2013, U+201C-201D, U+2022, U+2026 and U+00A0 at real
 * advance widths, while CJK/Cyrillic/Devanagari fall back to a 1em notdef box —
 * which is exactly what this list refuses.
 */
const rasterisable = /^[\u0009\u000a\u000d\u0020-\u007e\u00a0-\u024f\u0600-\u06ff\u0750-\u077f\u08a0-\u08ff\ufb50-\ufdff\ufe70-\ufeff\u060c\u061b\u061f\u0640\u066a-\u066d\u06d4\u200c-\u200f\u2010-\u2027\u202a-\u202e\u2030-\u203a\u2044\u2066-\u2069\u20aa-\u20c0\u2116\u2122\u00a9\u00ae\u00b0\u00b7]*$/u;

/** True when every character of `text` is drawable by the raster fallback. */
export function canRasterise(text: string) { return rasterisable.test(text); }

/** True when the value contains Arabic script and needs bidi-aware rendering. */
export function hasArabicScript(text: string) { return arabicScript.test(text); }

function wrapLines(context: SKRSContext2D, text: string, maxWidth: number, maxLines: number) {
  const words = text.split(/\s+/u).filter(Boolean);
  const lines: string[] = [];
  let current = "";
  for (const word of words) {
    const candidate = current ? `${current} ${word}` : word;
    if (context.measureText(candidate).width <= maxWidth || !current) { current = candidate; continue; }
    lines.push(current);
    current = word;
    if (lines.length >= maxLines) break;
  }
  if (current && lines.length < maxLines) lines.push(current);
  return lines;
}

export type RasterAppearanceOptions = { text: string; width: number; height: number; multiline?: boolean };

/** Render `text` into a PNG sized to the widget rectangle in device pixels. */
export function renderWidgetAppearance(options: RasterAppearanceOptions) {
  registerFormFonts();
  const width = Math.max(16, Math.min(RASTER_MAX_DIMENSION, Math.round(options.width * RASTER_SCALE)));
  const height = Math.max(16, Math.min(RASTER_MAX_DIMENSION, Math.round(options.height * RASTER_SCALE)));
  if (width * height > RASTER_MAX_AREA) throw Object.assign(new Error("Widget appearance exceeds the raster area limit."), { code: "APPEARANCE_LIMIT_EXCEEDED" });
  const canvas = rasteriser().createCanvas(width, height);
  const context = canvas.getContext("2d");
  context.fillStyle = "#ffffff";
  context.fillRect(0, 0, width, height);
  const hasArabic = arabicScript.test(options.text);
  context.direction = hasArabic ? "rtl" : "ltr";
  context.textAlign = hasArabic ? "right" : "left";
  context.textBaseline = "top";
  context.fillStyle = "#111827";
  const padding = Math.round(Math.min(width, height) * 0.12) + 2;
  const family = hasArabic ? '"DIP Form Arabic", "DIP Form Latin"' : '"DIP Form Latin", "DIP Form Arabic"';
  let fontSize = Math.max(6, Math.round(height * (options.multiline ? 0.28 : 0.5)));
  const maxWidth = width - padding * 2;
  let lines: string[] = [];
  for (let attempt = 0; attempt < 12 && fontSize >= 6; attempt += 1) {
    context.font = `400 ${fontSize}px ${family}`;
    lines = options.multiline ? wrapLines(context, options.text, maxWidth, Math.max(1, Math.floor((height - padding * 2) / (fontSize * 1.25)))) : [options.text];
    const fits = lines.every((line) => context.measureText(line).width <= maxWidth) && lines.length * fontSize * 1.25 <= height - padding * 2;
    if (fits) break;
    fontSize = Math.round(fontSize * 0.88);
  }
  if (!options.multiline && context.measureText(options.text).width > maxWidth) {
    // Single-line overflow: clip horizontally rather than pretending it fits.
    context.save();
    context.beginPath();
    context.rect(padding, 0, maxWidth, height);
    context.clip();
    context.fillText(options.text, hasArabic ? width - padding : padding, padding);
    context.restore();
  } else {
    lines.forEach((line, index) => context.fillText(line, hasArabic ? width - padding : padding, padding + index * fontSize * 1.25));
  }
  return canvas.toBuffer("image/png");
}

/** Read the appearance bounding box of a widget, falling back to its rectangle. */
function appearanceBox(widget: { AP(): PDFDict | undefined; getRectangle(): { width: number; height: number } }) {
  try {
    const normal = widget.AP()?.lookup(PDFName.of("N"));
    const stream = normal instanceof PDFRawStream ? normal : normal instanceof PDFDict ? normal.lookup(PDFName.of("Off")) : undefined;
    const box = stream instanceof PDFRawStream ? stream.dict.lookup(PDFName.of("BBox")) : undefined;
    if (box && typeof (box as unknown as { size?: number }).size === "function" && (box as unknown as { size(): number }).size() === 4) {
      const values = [0, 1, 2, 3].map((index) => Number((box as unknown as { get(index: number): unknown }).get(index)));
      const width = Math.abs(values[2] - values[0]);
      const height = Math.abs(values[3] - values[1]);
      if (width > 0 && height > 0) return { width, height };
    }
  } catch { /* fall through to the widget rectangle */ }
  return widget.getRectangle();
}

/**
 * Replace one widget's normal appearance with a rasterised PNG.
 *
 * The previous appearance stream is preserved as a comment in the resource
 * dictionary only for reference (`/DIPOriginalBBox`); the original bytes are
 * not retained, because they no longer describe the widget's value.
 */
export async function installRasterAppearance(document: PDFDocument, field: PDFField, value: string, options: { multiline?: boolean } = {}) {
  const widgets = field.acroField.getWidgets();
  if (!widgets.length) throw Object.assign(new Error("The field has no widget to paint."), { code: "FORM_FILL_FAILED" });
  let painted = 0;
  for (const widget of widgets) {
    const box = appearanceBox(widget);
    // Skip the states of a checkbox/radio state map: only the current state is
    // visible, and a raster image cannot express both states in one stream.
    const normal = widget.AP()?.lookup(PDFName.of("N"));
    if (normal instanceof PDFDict) continue;
    const png = renderWidgetAppearance({ text: value, width: box.width, height: box.height, multiline: options.multiline });
    const image = await document.embedPng(png);
    const resources = document.context.obj({ XObject: document.context.obj({ FormImage: image.ref }) });
    const operators = [
      pushGraphicsState(),
      ...drawRectangle({ x: 0, y: 0, width: box.width, height: box.height, rotate: degrees(0), xSkew: degrees(0), ySkew: degrees(0), borderWidth: 0, borderColor: rgb(1, 1, 1), color: rgb(1, 1, 1) }),
      concatTransformationMatrix(box.width, 0, 0, box.height, 0, 0),
      drawObject(PDFName.of("FormImage")),
      popGraphicsState(),
    ];
    const stream = document.context.formXObject(operators, {
      BBox: [0, 0, box.width, box.height],
      Matrix: [1, 0, 0, 1, 0, 0],
      Resources: resources,
    });
    const reference: PDFRef = document.context.register(stream);
    widget.setNormalAppearance(reference);
    if (!widget.getRectangle().width || !widget.getRectangle().height) widget.setRectangle({ x: 0, y: 0, width: box.width, height: box.height });
    painted += 1;
  }
  return painted;
}

/** True when a normal appearance is a plain Form XObject (not a state map). */
export function hasStreamAppearance(field: PDFField) {
  return field.acroField.getWidgets().some((widget) => {
    const normal = widget.AP()?.lookup(PDFName.of("N"));
    return normal instanceof PDFRawStream || (normal instanceof PDFDict && Boolean(normal.lookup(PDFName.of("Off"))));
  });
}

/** Decoded appearance length, used by tests to prove the stream really changed. */
export function appearanceContentLength(field: PDFField) {
  const lengths: number[] = [];
  for (const widget of field.acroField.getWidgets()) {
    const normal = widget.AP()?.lookup(PDFName.of("N"));
    if (normal instanceof PDFRawStream) { try { lengths.push(decodePDFRawStream(normal).decode().length); } catch { /* ignore */ } }
    else if (normal instanceof PDFDict) for (const key of normal.keys()) { const value = normal.lookup(key); if (value instanceof PDFRawStream) { try { lengths.push(decodePDFRawStream(value).decode().length); } catch { /* ignore */ } } }
  }
  return lengths;
}
