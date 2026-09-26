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

## Extract Images PoC — supported subset implemented

PDF.js 6.3.289 operator data supports a useful, bounded subset: decoded image XObjects exposed as 1-bit grayscale, RGB, or RGBA pixel buffers. DIP exports those objects as PNG, deduplicates identical decoded pixels, and emits an explicit JSON capability report. It does not claim byte-identical original streams and never substitutes rendered page screenshots. Inline images and objects that PDF.js does not expose as a bounded supported pixel buffer are counted as unsupported. Per-image dimensions/pixels, output count, and total bytes are bounded before persistence.

## qpdf security gate — implemented; production CI verification required

- The worker package is pinned to Debian `qpdf=11.3.0-1+deb12u1`; the build checks the installed Debian package version.
- The production-image CI gate runs qpdf as UID/GID 10001 under a read-only root filesystem and bounded `/tmp/dip` tmpfs. It verifies the exact executable/package version, AES-256/R6, correct and wrong credentials, Arabic/Unicode credentials, permission mappings, recoverable and unrecoverable repair cases, and Ghostscript absence.
- Passwords are AES-256-GCM encrypted in short-lived Redis records referenced by opaque IDs bound through authenticated additional data to tenant, job, and purpose. Retrieval is one-time. Success, failure, cancellation, and TTL expiration all remove or expire the record. Only the opaque reference is persisted; BullMQ continues to carry only job identity and routing metadata.
- qpdf receives one private mode-0600 argument file by `@file`; the process argument array never contains a password and `shell` is disabled. The private mode-0700 directory is removed in `finally`.
- Protect, Unlock, PDF Permissions, and Repair are registered for direct Web/Public API and the worker. The three secret-bearing tools are deliberately rejected by persisted Workflows and excluded from Agent plans. Repair requires no secret and remains available where policy permits.
- This local host has neither qpdf nor Docker. The gate is implemented but its production-image result remains environment-gated until the extended GitHub job runs successfully.

## Architecture result

The existing output manifest already supports multiple `outputFileIds`; no contract redesign or ZIP dependency was required. No new package, AI path, or Ghostscript path was introduced. qpdf is invoked only through the already approved pinned production package and the controlled argument-file wrapper.
