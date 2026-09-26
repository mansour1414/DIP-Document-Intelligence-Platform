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

test("Extract Images PoC keeps page screenshots out of the implementation", async () => {
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs");
  assert.equal(typeof pdfjs.getDocument, "function"); assert.equal("extractOriginalImages" in pdfjs, false);
  const implementation = readFileSync(new URL("../src/lib/pdf/extract-images.ts", import.meta.url), "utf8");
  assert.match(implementation, /paintImageXObject/); assert.doesNotMatch(implementation, /page\.render/);
});

test("qpdf is exactly pinned, production-gated, and Ghostscript remains prohibited", () => {
  const dockerfile = readFileSync(new URL("../Dockerfile.worker", import.meta.url), "utf8");
  assert.match(dockerfile, /QPDF_DEBIAN_VERSION=11\.3\.0-1\+deb12u1/); assert.match(dockerfile, /qpdf=\$\{QPDF_DEBIAN_VERSION\}/);
  assert.match(dockerfile, /dpkg-query -W -f='\$\{Version\}' qpdf/); assert.doesNotMatch(dockerfile, /\$\$\{Version\}/);
  assert.match(dockerfile, /test ! -e \/usr\/bin\/gs/); assert.doesNotMatch(dockerfile, /apt-get install[^\n]*ghostscript/i);
  const registry = readFileSync(new URL("../src/lib/tools/registry.ts", import.meta.url), "utf8");
  for (const tool of ["protect-pdf", "unlock-pdf", "pdf-permissions", "repair-pdf", "extract-images"]) assert.match(registry, new RegExp(`\\"${tool}\\"`)); assert.doesNotMatch(registry, /"grayscale-pdf"/);
});

test("CI S3-compatible storage uses the reviewed immutable Silo image", () => {
  const workflow = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
  const image = "docker.io/pgsty/silo:RELEASE.2026-09-16T00-00-00Z@sha256:635197cb9f36d01bee221d34d1c7d7960f6a95c48b0b6c01d99cd13bdae51a46";
  assert.equal(workflow.split(image).length - 1, 2);
  assert.doesNotMatch(workflow, /(?:minio\/minio|pgsty\/silo):latest/);
  assert.doesNotMatch(workflow, /quay\.io\/minio\/minio/);
  const licenses = readFileSync(new URL("../docs/license-registry.md", import.meta.url), "utf8");
  assert.match(licenses, /PGSTY Silo \(MinIO-compatible CI service\)/);
  assert.match(licenses, /AGPL-3\.0-or-later/);
  assert.ok(licenses.includes(image));
});
