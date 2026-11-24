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
 * Fonts are resolved **lazily, once, on first use** (FF-01).
 *
 * The previous version did this at module scope. In a production build Turbopack
 * rewrites `require.resolve` to return a numeric module id for a bundled
 * dependency, so `dirname(7)` threw during page-data collection and the build
 * failed for every route that imported this module — including the read-only
 * inspect route, which never renders anything.
 *
 * Doing it here means:
 *   - nothing is resolved while a route module is evaluated,
 *   - the cost is paid once, by the worker, when a value actually needs raster
 *     text,
 *   - and a resolution failure becomes a `FORM_UNSUPPORTED` at render time
 *     (no partial output) rather than a build failure.
 */
let fontSource: string | undefined;
function fontDirectory(): string {
  if (fontSource === undefined) {
    const modulePath = require.resolve("@fontsource/noto-sans-arabic/package.json");
    // Fail loudly and legibly if a bundler ever hands back a non-path again,
    // instead of producing `dirname(7)` somewhere deep inside the call.
    if (typeof modulePath !== "string" || !/[\\/]package\.json$/u.test(modulePath)) throw Object.assign(new Error("Form fonts could not be located"), { code: "FONT_UNAVAILABLE" });
    fontSource = dirname(modulePath);
  }
  return fontSource;
}

/** Pure render scale: a widget is rasterised at this multiple of its PDF size. */
const RASTER_SCALE = 4;
const RASTER_MAX_DIMENSION = 4_000;
const RASTER_MAX_AREA = 12_000_000;

export function registerFormFonts() {
  if (fontsReady) return;
  const arabic = join(fontDirectory(), "files/noto-sans-arabic-arabic-400-normal.woff");
  const latin = join(fontDirectory(), "files/noto-sans-arabic-latin-400-normal.woff");
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

/**
 * Wrap one paragraph into `maxWidth`.
 *
 * FF-07: an explicit line break in the submitted value is a *typo-invisible*
 * defect when it disappears. The previous implementation split the whole value
 * on whitespace, so `"أحمد\nمحمد"` was laid out as `"أحمد محمد"` — a different
 * string on the page from the one in the field. Breaks are now structural:
 * `wrapTextBlock` splits on them first and wraps each paragraph independently.
 */
function wrapParagraph(context: SKRSContext2D, text: string, maxWidth: number) {
  const words = text.split(/[ \t]+/u).filter(Boolean);
  const lines: string[] = [];
  let current = "";
  for (const word of words) {
    const candidate = current ? `${current} ${word}` : word;
    if (context.measureText(candidate).width <= maxWidth || !current) { current = candidate; continue; }
    lines.push(current);
    current = word;
  }
  if (current) lines.push(current);
  return lines;
}

/** Layout a whole value, honouring explicit line breaks and a line budget. */
function wrapLines(context: SKRSContext2D, text: string, maxWidth: number, maxLines: number) {
  const paragraphs = text.split(/\r\n|\r|\n/u);
  const lines: string[] = [];
  for (const paragraph of paragraphs) {
    for (const line of wrapParagraph(context, paragraph, maxWidth)) {
      if (lines.length >= maxLines) return lines;
      lines.push(line);
    }
  }
  return lines;
}

export type RasterAppearanceOptions = { text: string; width: number; height: number; multiline?: boolean };

/** Render `text` into a PNG sized to the widget rectangle in device pixels. */
/**
 * Smallest value height that stays legible, in PDF points (FF-07).
 *
 * The review produced an 18x7 pt widget in which 6 px text is unreadable. A
 * value that cannot be drawn legibly is *rejected* — with no partial output —
 * rather than shrunk until it fits. 8 pt is the usual minimum readable size for
 * a printed form value; below it the tool refuses and says why.
 */
const MIN_LEGIBLE_VALUE_HEIGHT_PT = 8;
/** Smallest width that can hold a few glyphs plus padding at that height. */
const MIN_LEGIBLE_VALUE_WIDTH_PT = 16;

export class AppearanceLegibilityError extends Error {
  constructor(readonly reason: "WIDGET_TOO_SMALL" | "VALUE_OVERFLOWS_WIDGET" | "VALUE_NEEDS_MORE_LINES") {
    super(reason);
  }
}

export function renderWidgetAppearance(options: RasterAppearanceOptions) {
  registerFormFonts();
  // FF-07: refuse geometry that cannot render a legible value, instead of
  // producing a widget with microscopic or clipped text.
  //
  // Measured on the rectangle *as reported*, which already includes the widget's
  // border/padding (~1 pt each side in practice): the review's 18x7 pt widget
  // arrives here as 19x8, so a threshold compared against the requested size
  // would let it through. The floor is therefore the legible text height plus the
  // padding the renderer itself adds below.
  if (options.height < MIN_LEGIBLE_VALUE_HEIGHT_PT + 2 || options.width < MIN_LEGIBLE_VALUE_WIDTH_PT) throw new AppearanceLegibilityError("WIDGET_TOO_SMALL");
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
  // FF-07: never clip. The review found a 209-character value silently cut off
  // inside a 90 pt widget: the field *value* was correct and the visible output
  // was not. Overflow is now an explicit rejection with no partial output, so the
  // caller learns the value does not fit instead of shipping a document that
  // hides part of it.
  if (!options.multiline) {
    if (context.measureText(options.text).width > maxWidth) throw new AppearanceLegibilityError("VALUE_OVERFLOWS_WIDGET");
  } else if (lines.join("").length < options.text.replace(/[ \t\r\n]+/gu, "").length) {
    // `wrapLines` stopped at the line budget: some of the value would be lost.
    throw new AppearanceLegibilityError("VALUE_NEEDS_MORE_LINES");
  }
  lines.forEach((line, index) => context.fillText(line, hasArabic ? width - padding : padding, padding + index * fontSize * 1.25));
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
