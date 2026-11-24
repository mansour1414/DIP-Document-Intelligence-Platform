#!/usr/bin/env node
/**
 * Execute the bounded PDF child *inside a built artifact*.
 *
 * ## Why this is separate from `verify-pdf-worker-artifact.mjs`
 *
 * That script proves the required files are **present**. Presence is necessary and not
 * sufficient: a file can be present and still fail to load (a missing transitive
 * import, an unresolved path alias, a native addon built for the wrong platform, a font
 * that is packaged but not resolvable at runtime). Each of those fails *inside the
 * child*, so the only way to know the artifact works is to start it and make it do the
 * work.
 *
 * This script runs in the artifact's own environment — the worker image, or a Next
 * standalone tree — and drives the real child through the real protocol. It imports
 * nothing from the repository: the code under test is whatever the artifact contains.
 *
 * ## Scenarios
 *
 *   1. inspect   — a one-page empty PDF is inspected in the child
 *   2. fill      — a real form is filled, and the reply's bytes are reopened
 *   3. flatten   — the same form filled with `flatten`, and the form is gone afterwards
 *   4. Arabic    — an Arabic value is written, which exercises the native canvas and
 *                  the bundled font (the parts that fail only at runtime)
 *   5. protocol  — a reply is framed and parsed by the artifact's own protocol module
 *
 * Every scenario asserts on **output**, not on exit status: a child that starts, does
 * nothing and exits zero must fail here.
 *
 * Usage:
 *   node scripts/smoke-pdf-worker-artifact.mjs [artifact-root]
 */
import { spawn } from "node:child_process";
import { existsSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";

/**
 * Where the child entry may live inside the artifact.
 *
 * Mirrors `childEntry()` in `form-worker.ts`. Kept as a literal rather than imported
 * because it must be resolvable before anything from the artifact has loaded.
 */
export const SEARCH_ROOTS = ["", "src/lib/pdf", ".next/standalone/src/lib/pdf", ".next/standalone"];

export function findEntry(root) {
  for (const prefix of SEARCH_ROOTS) {
    for (const name of ["form-worker-child.ts", "form-worker-child.js"]) {
      const candidate = join(root, prefix, name);
      if (existsSync(candidate)) return candidate;
    }
  }
  return undefined;
}

/**
 * A preload that teaches the child to resolve the `@/` alias without `tsconfig.json`.
 *
 * The child is launched with `tsx`, which reads `paths` from `tsconfig.json`. A Next
 * standalone tree does not contain that file — it is a build input, not build output —
 * so inside that artifact every `import "@/lib/..."` fails with MODULE_NOT_FOUND even
 * though the files are present. The worker image does ship `tsconfig.json`, and there
 * this preload is simply redundant.
 *
 * It is generated into a temp directory rather than committed: it exists only for the
 * duration of a smoke run and is not part of the shipped product.
 */
const u32 = (value) => { const buffer = Buffer.alloc(4); buffer.writeUInt32BE(value, 0); return buffer; };

/**
 * Run the child once and return its parsed reply.
 *
 * The framing is the production format: `[u32 controlLen][JSON][pdf]` in, and
 * `[u32 metaLen][JSON]` or `[u32 metaLen][JSON][u32 outLen][pdf]` out on fd 3. Using the
 * real framing is the point — a child that only works under a simplified harness is not
 * evidence about the artifact.
 */
function runChild(entry, control, pdf, root, timeoutMs = 120_000) {
  return new Promise((resolvePromise, rejectPromise) => {
    // `cwd` must be the artifact root this entry came from — not the entry's own
    // directory, and not wherever the script was invoked from. The child resolves
    // `--import tsx` and its `node_modules` relative to the working directory, so
    // inheriting the caller's would silently test a different installation, or in CI the
    // checkout instead of the built image.
    const child = spawn(process.execPath, ["--import", "tsx", entry], {
      cwd: root,
      shell: false,
      stdio: ["pipe", "pipe", "pipe", "pipe"],
      env: { PATH: process.env.PATH ?? "", NODE_ENV: "production" },
    });
    const out = [];
    const err = [];
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill("SIGKILL");
      rejectPromise(new Error(`the child did not finish within ${timeoutMs}ms: ${Buffer.concat(err).toString("utf8").slice(-800)}`));
    }, timeoutMs);
    child.stdio[3].on("data", (chunk) => out.push(chunk));
    child.stderr.on("data", (chunk) => err.push(chunk));
    child.on("error", (error) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      rejectPromise(new Error(`the child could not start: ${error.message}`));
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      const meta = Buffer.concat(out);
      if (meta.length < 4) {
        rejectPromise(new Error(`the child produced no reply (exit ${code}): ${Buffer.concat(err).toString("utf8").slice(-800)}`));
        return;
      }
      const metaLength = meta.readUInt32BE(0);
      const parsed = JSON.parse(meta.subarray(4, 4 + metaLength).toString("utf8"));
      const output = meta.length > 4 + metaLength ? meta.subarray(4 + metaLength + 4, 4 + metaLength + 4 + meta.readUInt32BE(4 + metaLength)) : undefined;
      resolvePromise({ meta: parsed, output, stderr: Buffer.concat(err).toString("utf8") });
    });
    const controlBytes = Buffer.from(JSON.stringify(control), "utf8");
    child.stdin.on("error", () => {});
    child.stdin.end(Buffer.concat([u32(controlBytes.length), controlBytes, pdf]));
  });
}

/**
 * A document builder that does not use the artifact's `pdf-lib`.
 *
 * The input generator must be independent of what is being tested, otherwise a broken
 * artifact that cannot load its dependencies would also be unable to build its own
 * fixture and the failure would look like a test-harness problem. These are minimal but
 * genuinely valid PDFs: a correct xref table, a correct trailer, and for the form cases
 * a real AcroForm with an interactive text field.
 */
export function buildPdf({ withField = false } = {}) {
  const objects = [];
  objects.push("<</Type/Catalog/Pages 2 0 R" + (withField ? "/AcroForm<</Fields[5 0 R]/DA(/Helv 0 Tf 0 g)/DR<</Font<</Helv 6 0 R>>>>>>>>" : "") + ">>");
  objects.push("<</Type/Pages/Kids[3 0 R]/Count 1>>");
  objects.push("<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]/Resources<</Font<</Helv 6 0 R>>>>/Contents 4 0 R" + (withField ? "/Annots[5 0 R]" : "") + ">>");
  const content = "BT /Helv 12 Tf 72 760 Td (Smoke) Tj ET";
  objects.push(`<</Length ${content.length}>>stream\n${content}\nendstream`);
  if (withField) {
    objects.push("<</Type/Annot/Subtype/Widget/FT/Tx/T(applicant.name)/V()/Rect[72 700 400 722]/P 3 0 R/F 4>>");
    objects.push("<</Type/Font/Subtype/Type1/BaseFont/Helvetica/Encoding/WinAnsiEncoding>>");
  }

  let body = "%PDF-1.7\n";
  const offsets = [];
  objects.forEach((object, index) => {
    offsets.push(body.length);
    body += `${index + 1} 0 obj\n${object}\nendobj\n`;
  });
  const xrefStart = body.length;
  body += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const offset of offsets) body += `${String(offset).padStart(10, "0")} 00000 n \n`;
  body += `trailer\n<</Size ${objects.length + 1}/Root 1 0 R>>\nstartxref\n${xrefStart}\n%%EOF\n`;
  return Buffer.from(body, "latin1");
}

/**
 * Page count via a raw scan, used only for *inputs* this file builds itself.
 *
 * Deliberately not used on outputs: pdf-lib writes object streams, so `/Type /Pages`
 * is inside a compressed `ObjStm` and a byte scan cannot see it. Counting an output
 * that way reports `NaN` and would look like a page-preservation failure in a document
 * that is perfectly correct. Outputs are counted by reopening them with pdf-lib, and
 * the child's own `pages` field (derived from the document it wrote) is the second
 * opinion.
 */
export function rawPageCount(pdf) {
  const text = pdf.toString("latin1");
  const match = /\/Type\s*\/Pages[\s\S]{0,400}?\/Count\s+(\d+)/u.exec(text);
  return match ? Number(match[1]) : NaN;
}

/**
 * A fillable form built with pdf-lib.
 *
 * Used for the fill/flatten scenarios instead of the hand-written document above. The
 * difference is not cosmetic: a hand-built widget has no `/AP` appearance stream, and
 * `flatten()` treats that as an error. More importantly, pdf-lib's own documents keep
 * the widget reference in `/Page /Annots` after flattening, which is precisely the case
 * the child's post-flatten pruning exists to handle. A fixture that behaves differently
 * from every document the product actually produces would test the fixture, not the
 * product.
 */
export async function buildFormPdf() {
  const { PDFDocument } = await import("pdf-lib");
  const document = await PDFDocument.create();
  const page = document.addPage([595, 842]);
  document.getForm().createTextField("applicant.name").addToPage(page, { x: 72, y: 700, width: 328, height: 22 });
  return Buffer.from(await document.save());
}

const scenarios = [];
const scenario = (name, run) => scenarios.push({ name, run });

scenario("inspect a document in the artifact's child", async ({ entry, root }) => {
  const { meta } = await runChild(entry, { v: 1, op: "inspect", maxInputBytes: 64 * 1024 * 1024 }, buildPdf(), root);
  if (meta.ok !== true) throw new Error(`inspect failed: ${JSON.stringify(meta)}`);
  if (meta.op !== "inspect") throw new Error(`inspect answered as ${meta.op}`);
  if (meta.pages !== 1) throw new Error(`expected 1 page, got ${meta.pages}`);
  if (!Array.isArray(meta.inventory?.fields)) throw new Error("the reply carried no inventory");
  return "inspect ok (1 page, inventory present)";
});

scenario("fill a form in the artifact's child and reopen the output", async ({ entry, root }) => {
  const input = await buildFormPdf();
  const { meta, output } = await runChild(entry, { v: 1, op: "fill", flatten: false, fields: { "applicant.name": "Smoke Test" }, maxInputBytes: 64 * 1024 * 1024 }, input, root);
  if (meta.ok !== true) throw new Error(`fill failed: ${JSON.stringify(meta)}`);
  if (!output?.length) throw new Error("fill returned no output bytes");
  // Reopened with the artifact's own pdf-lib, which is also part of the closure.
  const { PDFDocument } = await import("pdf-lib");
  const reopened = await PDFDocument.load(output);
  const value = reopened.getForm().getTextField("applicant.name").getText();
  if (value !== "Smoke Test") throw new Error(`the reopened output holds ${JSON.stringify(value)}`);
  // Two independent counts: the child's own `pages` (from the document it wrote) and a
  // reopen here. The raw byte scan cannot be used on an output — pdf-lib compresses the
  // page tree into an object stream, so a scan would report NaN for a correct document.
  if (meta.pages !== 1) throw new Error(`the child reported ${meta.pages} pages`);
  if (reopened.getPageCount() !== 1) throw new Error(`the reopened output has ${reopened.getPageCount()} pages`);
  return `fill ok (${output.length} bytes, value round-tripped, 1 page)`;
});

scenario("fill with flatten removes the form and preserves pages", async ({ entry, root }) => {
  const input = await buildFormPdf();
  const { meta, output } = await runChild(entry, { v: 1, op: "fill", flatten: true, fields: { "applicant.name": "Flattened" }, maxInputBytes: 64 * 1024 * 1024 }, input, root);
  if (meta.ok !== true) throw new Error(`flatten failed: ${JSON.stringify(meta)}`);
  const { PDFDocument } = await import("pdf-lib");
  const reopened = await PDFDocument.load(output);
  if (reopened.getForm().getFields().length !== 0) throw new Error("the form survived flattening");
  if (reopened.getPageCount() !== 1) throw new Error(`flattening changed the page count (${reopened.getPageCount()})`);
  if (meta.pages !== 1) throw new Error(`the child reported ${meta.pages} pages after flattening`);
  return "flatten ok (form removed, pages preserved)";
});

scenario("an Arabic value renders through the artifact's canvas and font", async ({ entry, root }) => {
  // This is the scenario that fails when `@napi-rs/canvas` is missing or built for the
  // wrong platform, or when the bundled Noto font is not resolvable. Nothing else in
  // this file exercises a native addon.
  const input = await buildFormPdf();
  const { meta, output } = await runChild(entry, { v: 1, op: "fill", flatten: false, fields: { "applicant.name": "نورة الحربي" }, maxInputBytes: 64 * 1024 * 1024 }, input, root);
  if (meta.ok !== true) throw new Error(`Arabic fill failed: ${JSON.stringify(meta)}`);
  const { PDFDocument } = await import("pdf-lib");
  const reopened = await PDFDocument.load(output);
  const value = reopened.getForm().getTextField("applicant.name").getText();
  if (value !== "نورة الحربي") throw new Error(`the Arabic value was not preserved: ${JSON.stringify(value)}`);
  return "Arabic ok (value preserved through the appearance path)";
});

scenario("the artifact's protocol module loads and round-trips a frame", async ({ root }) => {
  // Loaded in a subprocess because the alias environment must be in place before the
  // module graph loads. Nothing is injected: `tsconfig.json` is a *packaged* requirement
  // (see `outputFileTracingIncludes` in next.config.ts) and the child launcher reads it
  // from the working directory, so its presence here is part of what is being verified.
  const protocolPath = join(root, "src/lib/pdf/worker-protocol.ts");
  if (!existsSync(protocolPath)) throw new Error(`the protocol module is missing from ${root}`);
  if (!existsSync(join(root, "tsconfig.json"))) {
    throw new Error(`tsconfig.json is missing from ${root}; the child launcher cannot resolve '@/' aliases without it`);
  }
  const script = join(tmpdir(), `dip-smoke-protocol-${process.pid}-${Math.random().toString(36).slice(2)}.mjs`);
  // Built as an array of plain lines rather than a template literal: the body contains
  // backslashes and `${}` sequences that a template would interpret, and a corrupted
  // harness looks exactly like a broken artifact.
  writeFileSync(script, [
    `const protocol = await import(${JSON.stringify(pathToFileURL(protocolPath).href)});`,
    'const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n, 0); return b; };',
    'const encoded = protocol.encodeControl({ v: protocol.WORKER_PROTOCOL_VERSION, op: "inspect" }, Buffer.from("%PDF-1.7"), 1024);',
    'if (!Buffer.isBuffer(encoded) || encoded.length === 0) throw new Error("encodeControl produced nothing");',
    'const meta = { ok: true, op: "inspect", pages: 1, inventory: { fields: [], unsupported: [], pages: 1, hasXfa: false, needAppearances: false, duplicates: [] } };',
    'const json = Buffer.from(JSON.stringify(meta), "utf8");',
    'const decoded = protocol.decodeResult(Buffer.concat([u32(json.length), json]), 1024 * 1024, "inspect");',
    'if (decoded.meta.ok !== true || decoded.meta.pages !== 1) throw new Error("a valid frame did not decode");',
    'console.log("ok");',
  ].join("\n"));
  try {
    await new Promise((resolvePromise, rejectPromise) => {
      const child = spawn(process.execPath, ["--import", "tsx", script], {
        cwd: root,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
        env: { PATH: process.env.PATH ?? "", NODE_ENV: "production" },
      });
      const err = [];
      child.stdout.on("data", () => {});
      child.stderr.on("data", (chunk) => err.push(chunk));
      child.on("error", rejectPromise);
      child.on("close", (code) => {
        if (code === 0) resolvePromise(undefined);
        else rejectPromise(new Error(`the protocol module could not load (exit ${code}): ${Buffer.concat(err).toString("utf8").slice(0, 1200)}`));
      });
    });
  } finally {
    rmSync(script, { force: true });
  }
  return "protocol ok (encode + decode + packaged tsconfig)";
});

const root = resolve(process.argv[2] ?? process.cwd());

// The scenario list runs only when this file is executed directly. Importing it (a
// test, or a future caller) must not spawn children or exit the process.
const invokedDirectly = Boolean(process.argv[1]) && import.meta.url === `file://${resolve(process.argv[1])}`;
if (invokedDirectly) {
  const entry = findEntry(root);
  if (!entry) {
    console.error(`No PDF worker child entry found under ${root}. Searched: ${SEARCH_ROOTS.join(", ")}`);
    process.exit(1);
  }
  console.log(`Artifact root: ${root}`);
  console.log(`Child entry:   ${entry}`);

  const failures = [];
  for (const { name, run } of scenarios) {
    try {
      const detail = await run({ entry, root });
      console.log(`  PASS  ${name} — ${detail}`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.log(`  FAIL  ${name} — ${message}`);
      failures.push(name);
    }
  }

  if (failures.length) {
    console.error(`\n${failures.length} of ${scenarios.length} artifact smoke scenarios failed:`);
    for (const name of failures) console.error(`  - ${name}`);
    console.error("\nPresence of the files is not enough: the child could not do the work.");
    process.exit(1);
  }
  console.log(`\nAll ${scenarios.length} artifact smoke scenarios passed.`);
}
