# Phase 1 capability and security gates

This record applies to the remaining Page & Security tools and does not change the MASTER BASELINE.

## Completed with the approved JavaScript stack

- Split PDF by Size uses `pdf-lib` serialization to form deterministic page groups. The target is explicitly approximate; a single page may exceed it. Every part is reopened by the common output validator.
- Split PDF by Bookmarks accepts direct internal page destinations only. Nested items, duplicate titles, and Unicode titles are supported. Named, missing, invalid, cyclic, remote, and external destinations fail closed. Document-level data is not claimed to survive the split.
- Split PDF by Text uses PDF.js text extraction and literal substring matching only. A matching page starts a new part. Multiple matches on one page create one boundary; no match fails. Case sensitivity is explicit. No regex, AI, or implicit OCR is used.
- N-up PDF composes 2/4/6/9 pages with `pdf-lib`. It preserves visible page content and geometry but intentionally does not claim preservation of interactive links, forms, or annotations.
- Remove Annotations uses an explicit subtype allowlist. Form widgets are retained. Link removal requires the `comments-and-links` policy. PDFs containing signature fields or `ByteRange` signatures are rejected because rewriting may invalidate integrity.

## Grayscale quality PoC — CAPABILITY/PoC BLOCKER

The approved stack can rasterize pages, but reconstruction from rendered pixels removes searchable text, vector objects, links, forms, and other document semantics. `pdf-lib` 1.17.1 has no supported content-stream/color-space transformation API that can reliably convert arbitrary PDF color operators, embedded images, transparency groups, patterns, shadings, and ICC color spaces while preserving those semantics. Shipping rasterization as ordinary grayscale success would violate the approved quality requirement. No tool is registered or advertised.

## Extract Images PoC — CAPABILITY/PoC BLOCKER

PDF.js 6.3.289 exposes rendering operator/image data for display, not a stable API for byte-faithful extraction of every original image stream. That route cannot safely promise original JPEG/PNG-compatible bytes across inline images, JPX, JBIG2, masks, ICC/color spaces, and deduplicated XObjects. qpdf 11.3.0 is structural and does not provide the required general image-decoding/export surface. Page screenshots are explicitly not treated as image extraction. No tool is registered or advertised until an approved capability can enforce decompression, dimensions, output count, and total-byte limits without misleading output.

## qpdf security gate — SECURITY GATE / ENVIRONMENT-GATED TEST

- The worker package is pinned to Debian `qpdf=11.3.0-1+deb12u1`; the build checks the installed Debian package version.
- The established CI prints qpdf's runtime version and the existing verifier fails if qpdf is missing or Ghostscript resolves.
- This local host has neither qpdf nor Docker. The private CI logs are not accessible from this environment, so the current production image's successful output-password job-JSON behavior, AES-256 output, permission mappings, repair corpus, and password/open validation cannot be proven in this run.
- Protect, Unlock, PDF Permissions, and Repair remain unregistered and unavailable. No password is accepted, stored, logged, placed in `jobs.params`, frozen into an Agent plan, or passed in process arguments.
- Before enabling these tools, CI must exercise the pinned image with private mode-0600 job JSON/password material in a mode-0700 temporary directory, argument arrays only, cleanup in `finally`, correct/wrong Arabic/Unicode password cases, AES-256 inspection, permission mapping inspection, repair corpus classification, and a repeated Ghostscript-absence check.

## Architecture result

The existing output manifest already supports multiple `outputFileIds`; no contract redesign or ZIP dependency was required. No new package, AI path, qpdf call, or Ghostscript path was introduced.
