import {
  degrees,
  PDFArray,
  PDFDict,
  PDFDocument,
  PDFHexString,
  PDFName,
  PDFRef,
  PDFString,
} from "pdf-lib";
import { PdfToolError } from "@/lib/pdf/client";
import { extractPdfTextServer } from "@/lib/pdf/text-server";
import { runtimeLimits } from "@/lib/runtime/config";

export type Phase1Output = { name: string; mimeType: "application/pdf"; bytes: Uint8Array };

async function selected(source: PDFDocument, indexes: number[], name: string): Promise<Phase1Output> {
  const output = await PDFDocument.create();
  const pages = await output.copyPages(source, indexes);
  pages.forEach((page) => output.addPage(page));
  return { name, mimeType: "application/pdf", bytes: await output.save({ useObjectStreams: true }) };
}

function boundedParts(parts: Phase1Output[]) {
  if (parts.length > runtimeLimits.maxOutputFiles) throw new PdfToolError("VALIDATION_ERROR", "The requested split would create too many output files.");
  return parts;
}

export function assertSplitOutputCount(count: number) {
  if (count > runtimeLimits.maxOutputFiles) throw new PdfToolError("VALIDATION_ERROR", "The requested split would create too many output files.");
}

export async function splitPdfBySize(bytes: Uint8Array, targetSizeMb: number) {
  const targetBytes = Math.floor(targetSizeMb * 1024 * 1024);
  const source = await PDFDocument.load(bytes, { ignoreEncryption: false });
  const groups: number[][] = [];
  let current: number[] = [];
  for (const index of source.getPageIndices()) {
    const candidate = [...current, index];
    const serialized = await selected(source, candidate, "candidate.pdf");
    if (current.length && serialized.bytes.byteLength > targetBytes) {
      groups.push(current);
      current = [index];
    } else current = candidate;
    if (groups.length >= runtimeLimits.maxOutputFiles) throw new PdfToolError("VALIDATION_ERROR", "The requested target size would create too many output files.");
  }
  if (current.length) groups.push(current);
  return boundedParts(await Promise.all(groups.map((group, index) => selected(source, group, `size-part-${index + 1}.pdf`))));
}

function directInternalDestination(dict: PDFDict) {
  const actionValue = dict.get(PDFName.of("A"));
  if (actionValue) {
    const action = dict.context.lookup(actionValue, PDFDict);
    const kind = action.get(PDFName.of("S"));
    if (!(kind instanceof PDFName) || kind.toString() !== "/GoTo") throw new PdfToolError("VALIDATION_ERROR", "Remote or external bookmark destinations are not supported.");
    return action.get(PDFName.of("D"));
  }
  return dict.get(PDFName.of("Dest"));
}

function outlineBoundaries(source: PDFDocument) {
  const outlinesValue = source.catalog.get(PDFName.of("Outlines"));
  if (!outlinesValue) throw new PdfToolError("VALIDATION_ERROR", "This PDF does not contain bookmarks.");
  const outlines = source.context.lookup(outlinesValue, PDFDict);
  const pageByRef = new Map(source.getPages().map((page, index) => [page.ref.toString(), index]));
  const boundaries: number[] = [];
  const visited = new Set<string>();
  const walk = (value: unknown) => {
    let cursor = value;
    while (cursor) {
      const key = cursor instanceof PDFRef ? cursor.toString() : `direct:${visited.size}`;
      if (visited.has(key)) throw new PdfToolError("VALIDATION_ERROR", "The bookmark tree contains a cycle.");
      visited.add(key);
      const item = source.context.lookup(cursor as never, PDFDict);
      const title = item.get(PDFName.of("Title"));
      if (!(title instanceof PDFString || title instanceof PDFHexString)) throw new PdfToolError("VALIDATION_ERROR", "A bookmark has no valid Unicode title.");
      title.decodeText();
      const destinationValue = directInternalDestination(item);
      if (!destinationValue) throw new PdfToolError("VALIDATION_ERROR", "A bookmark has no destination.");
      const destination = source.context.lookup(destinationValue, PDFArray);
      if (!(destination instanceof PDFArray) || destination.size() < 1) throw new PdfToolError("VALIDATION_ERROR", "Named or malformed bookmark destinations are not supported safely.");
      const pageObject = destination.get(0);
      if (!(pageObject instanceof PDFRef)) throw new PdfToolError("VALIDATION_ERROR", "A bookmark does not point to an internal page.");
      const pageIndex = pageByRef.get(pageObject.toString());
      if (pageIndex === undefined) throw new PdfToolError("VALIDATION_ERROR", "A bookmark points outside this document.");
      boundaries.push(pageIndex);
      const first = item.get(PDFName.of("First"));
      if (first) walk(first);
      cursor = item.get(PDFName.of("Next"));
    }
  };
  const first = outlines.get(PDFName.of("First"));
  if (!first) throw new PdfToolError("VALIDATION_ERROR", "This PDF does not contain usable bookmarks.");
  walk(first);
  return [...new Set([0, ...boundaries])].sort((a, b) => a - b);
}

export async function splitPdfByBookmarks(bytes: Uint8Array) {
  const source = await PDFDocument.load(bytes, { ignoreEncryption: false });
  const starts = outlineBoundaries(source);
  const groups = starts.map((start, index) => Array.from({ length: (starts[index + 1] ?? source.getPageCount()) - start }, (_, offset) => start + offset)).filter((group) => group.length);
  assertSplitOutputCount(groups.length);
  return boundedParts(await Promise.all(groups.map((group, index) => selected(source, group, `bookmark-part-${index + 1}.pdf`))));
}

export function findTextBoundaries(pages: Array<{ page: number; text: string }>, matchText: string, caseSensitive: boolean) {
  const needle = caseSensitive ? matchText : matchText.toLocaleLowerCase("und");
  return pages.filter((page) => (caseSensitive ? page.text : page.text.toLocaleLowerCase("und")).includes(needle)).map((page) => page.page - 1);
}

export async function splitPdfByText(bytes: Uint8Array, matchText: string, caseSensitive: boolean) {
  const pages = await extractPdfTextServer(bytes);
  const boundaries = findTextBoundaries(pages, matchText, caseSensitive);
  if (!boundaries.length) throw new PdfToolError("VALIDATION_ERROR", "The text was not found. Image-only PDFs require OCR before this deterministic tool can match text.");
  const source = await PDFDocument.load(bytes, { ignoreEncryption: false });
  const starts = [...new Set([0, ...boundaries])].sort((a, b) => a - b);
  const groups = starts.map((start, index) => Array.from({ length: (starts[index + 1] ?? source.getPageCount()) - start }, (_, offset) => start + offset)).filter((group) => group.length);
  assertSplitOutputCount(groups.length);
  return boundedParts(await Promise.all(groups.map((group, index) => selected(source, group, `text-part-${index + 1}.pdf`))));
}

const pageSizes = { a4: [595.28, 841.89], letter: [612, 792] } as const;

export async function nUpPdf(bytes: Uint8Array, options: { layout: number; orientation: string; pageSize: string; margin: number; order: string }) {
  const source = await PDFDocument.load(bytes, { ignoreEncryption: false });
  const output = await PDFDocument.create();
  const embedded = await output.embedPages(source.getPages());
  const [baseWidth, baseHeight] = pageSizes[options.pageSize as keyof typeof pageSizes] ?? pageSizes.a4;
  const sheetWidth = options.orientation === "landscape" ? baseHeight : baseWidth;
  const sheetHeight = options.orientation === "landscape" ? baseWidth : baseHeight;
  const columns = options.layout === 2 ? 2 : options.layout === 6 ? 3 : Math.sqrt(options.layout);
  const rows = Math.ceil(options.layout / columns);
  const cellWidth = (sheetWidth - options.margin * (columns + 1)) / columns;
  const cellHeight = (sheetHeight - options.margin * (rows + 1)) / rows;
  for (let offset = 0; offset < embedded.length; offset += options.layout) {
    const sheet = output.addPage([sheetWidth, sheetHeight]);
    for (let slot = 0; slot < options.layout && offset + slot < embedded.length; slot += 1) {
      const row = options.order === "column" ? slot % rows : Math.floor(slot / columns);
      const column = options.order === "column" ? Math.floor(slot / rows) : slot % columns;
      const sourcePage = source.getPage(offset + slot);
      const rotation = ((sourcePage.getRotation().angle % 360) + 360) % 360;
      const quarterTurn = rotation === 90 || rotation === 270;
      const visualWidth = quarterTurn ? embedded[offset + slot].height : embedded[offset + slot].width;
      const visualHeight = quarterTurn ? embedded[offset + slot].width : embedded[offset + slot].height;
      const scale = Math.min(cellWidth / visualWidth, cellHeight / visualHeight);
      const drawWidth = embedded[offset + slot].width * scale;
      const drawHeight = embedded[offset + slot].height * scale;
      let x = options.margin + column * (cellWidth + options.margin) + (cellWidth - visualWidth * scale) / 2;
      let y = sheetHeight - options.margin - (row + 1) * cellHeight - row * options.margin + (cellHeight - visualHeight * scale) / 2;
      if (rotation === 90) x += drawHeight;
      else if (rotation === 180) { x += drawWidth; y += drawHeight; }
      else if (rotation === 270) y += drawWidth;
      sheet.drawPage(embedded[offset + slot], { x, y, width: drawWidth, height: drawHeight, rotate: degrees(rotation) });
    }
  }
  return [{ name: `n-up-${options.layout}.pdf`, mimeType: "application/pdf" as const, bytes: await output.save({ useObjectStreams: true }) }];
}

const removableComments = new Set(["/Text", "/FreeText", "/Highlight", "/Underline", "/Squiggly", "/StrikeOut", "/Stamp", "/Ink", "/Popup", "/Caret", "/Circle", "/Square", "/Line", "/Polygon", "/PolyLine", "/FileAttachment", "/Sound"]);

export async function removePdfAnnotations(bytes: Uint8Array, includeLinks: boolean) {
  const sourceText = new TextDecoder("latin1").decode(bytes);
  if (/\/ByteRange\s*\[/i.test(sourceText) || /\/FT\s*\/Sig\b/i.test(sourceText)) throw new PdfToolError("VALIDATION_ERROR", "Annotations are not removed from signed PDFs because rewriting would invalidate signature integrity.");
  const output = await PDFDocument.load(bytes, { ignoreEncryption: false });
  let removed = 0;
  for (const page of output.getPages()) {
    const annotations = page.node.Annots();
    if (!annotations) continue;
    const keep: unknown[] = [];
    for (let index = 0; index < annotations.size(); index += 1) {
      const value = annotations.get(index);
      const dictionary = output.context.lookup(value, PDFDict);
      const subtype = dictionary.get(PDFName.of("Subtype"));
      const name = subtype instanceof PDFName ? subtype.toString() : "";
      const remove = removableComments.has(name) || (includeLinks && name === "/Link");
      if (remove) removed += 1; else keep.push(value);
    }
    if (keep.length) page.node.set(PDFName.of("Annots"), output.context.obj(keep as never));
    else page.node.delete(PDFName.of("Annots"));
  }
  const result = await output.save({ useObjectStreams: true });
  return [{ name: "annotations-removed.pdf", mimeType: "application/pdf" as const, bytes: result, removed }];
}
