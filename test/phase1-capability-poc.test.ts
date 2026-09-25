import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { PDFDocument, StandardFonts } from "pdf-lib";
import { extractPdfTextServer } from "@/lib/pdf/text-server";
import { renderPdfToJpegs } from "@/lib/pdf/server-canvas";

test("grayscale PoC proves the available raster route destroys searchable text semantics", async () => {
  const source = await PDFDocument.create(); const font = await source.embedFont(StandardFonts.Helvetica); const page = source.addPage([300, 200]); page.drawText("Searchable vector text", { x: 30, y: 100, size: 18, font });
  const sourceBytes = await source.save({ useObjectStreams: true }); assert.match((await extractPdfTextServer(sourceBytes))[0].text, /Searchable vector text/);
  const rendered = await renderPdfToJpegs(sourceBytes, 0.9); const raster = await PDFDocument.create(); const image = await raster.embedJpg(rendered[0].bytes); const rasterPage = raster.addPage([rendered[0].pageWidth, rendered[0].pageHeight]); rasterPage.drawImage(image, { x: 0, y: 0, width: rendered[0].pageWidth, height: rendered[0].pageHeight });
  const rasterBytes = await raster.save({ useObjectStreams: true }); assert.equal((await extractPdfTextServer(rasterBytes))[0].text, "");
});

test("Extract Images PoC records that display rendering is not byte-faithful original extraction", async () => {
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs");
  assert.equal(typeof pdfjs.getDocument, "function"); assert.equal("extractOriginalImages" in pdfjs, false);
  const audit = readFileSync(new URL("../docs/phase-1-capability-audit.md", import.meta.url), "utf8");
  assert.match(audit, /Page screenshots are explicitly not treated as image extraction/);
  assert.match(audit, /JPX, JBIG2, masks, ICC\/color spaces/);
});

test("qpdf is exactly pinned while Ghostscript remains prohibited and security tools remain unregistered", () => {
  const dockerfile = readFileSync(new URL("../Dockerfile.worker", import.meta.url), "utf8");
  assert.match(dockerfile, /QPDF_DEBIAN_VERSION=11\.3\.0-1\+deb12u1/); assert.match(dockerfile, /qpdf=\$\{QPDF_DEBIAN_VERSION\}/);
  assert.match(dockerfile, /test ! -e \/usr\/bin\/gs/); assert.doesNotMatch(dockerfile, /apt-get install[^\n]*ghostscript/i);
  const registry = readFileSync(new URL("../src/lib/tools/registry.ts", import.meta.url), "utf8");
  for (const tool of ["protect-pdf", "unlock-pdf", "pdf-permissions", "repair-pdf", "grayscale-pdf", "extract-images"]) assert.doesNotMatch(registry, new RegExp(`\\"${tool}\\"`));
});
