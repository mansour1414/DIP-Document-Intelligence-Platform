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
import { cpSync, existsSync, mkdtempSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";

/**
 * Where the child entry may live inside the artifact.
 *
 * Mirrors `childEntry()` in `form-worker.ts`. Kept as a literal rather than imported
 * because it must be resolvable before anything from the artifact has loaded.
 */
export const SEARCH_ROOTS = ["", "src/lib/pdf", ".next/standalone/src/lib/pdf", ".next/standalone"];

/**
 * The shipped launcher-exercise module.
 *
 * It lives under `scripts/` at the artifact root in both layout shapes (standalone tree
 * and worker image `/app`), so one relative path works for all of them.
 */
export const RUNNER_MODULE = "scripts/pdf-worker-runner-smoke.ts";

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
 * Bounded, sanitized diagnostics.
 *
 * A failing child can print any amount of text, including absolute paths of the machine
 * that produced the artifact. CI logs are long-lived and widely readable, so the harness
 * reports a bounded excerpt with the artifact root collapsed to a placeholder — enough to
 * identify the failing import, not enough to leak the environment.
 */
export function sanitize(text, root, limit = 1200) {
  const collapsed = root ? text.split(root).join("<artifact>") : text;
  // Prefer the line that names the failure. A Node crash prints the offending frame and
  // its stack in that order, so taking the head of the output reports "package_json_reader"
  // and drops "Cannot find package 'tsx'", which is the entire finding.
  const lines = collapsed.split("\n").map((line) => line.trim()).filter(Boolean);
  // Ordered: the message node prints ("Cannot find package 'tsx' imported from …"), then a
  // bare ERR_ code, then anything error-shaped. A stack frame mentioning
  // `package_json_reader` matched first and told the reader nothing.
  const informative =
    lines.find((line) => /^Cannot find (package|module)/i.test(line)) ??
    lines.find((line) => /^(Error|error):/i.test(line)) ??
    lines.find((line) => /ERR_[A-Z_]+|EACCES|EROFS/i.test(line));
  const excerpt = informative && !collapsed.startsWith(informative) ? `${informative} | ${collapsed}` : collapsed;
  return excerpt.length > limit ? `${excerpt.slice(0, limit)}… (${excerpt.length} bytes)` : excerpt;
}

/**
 * Lead with the line that names a child failure, then a bounded tail for context.
 *
 * A Node crash prints the message before the stack, so taking a fixed slice of the output
 * routinely reports a stack frame and drops the actual cause.
 */
export function describeChildFailure(stderr, limit = 800) {
  const lines = stderr.split("\n").map((line) => line.trim()).filter(Boolean);
  const message = lines.find((line) => /^Cannot find (package|module)/i.test(line)) ??
    lines.find((line) => /^Error|^\w*Error:/i.test(line));
  const tail = stderr.slice(-limit).trim();
  return message && !tail.includes(message) ? `${message} | …${tail}` : tail;
}

/**
 * The child is launched with exactly the arguments the production launcher uses
 * (`childLaunch()` in `src/lib/pdf/form-worker.ts`): `--import ./scripts/node-platform-compat.mjs`
 * followed by `--import tsx`, and only `PATH`/`NODE_ENV` in the environment. Anything the
 * real launcher supplies must come from the artifact itself; nothing is injected here.
 * The alias resolution the preload would otherwise provide comes from the packaged
 * `tsconfig.json`, which is why its absence is a scenario failure rather than a repair.
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
    // Identical to `childLaunch()`. `node-platform-compat.mjs` is a production
    // preload (it repairs `geteuid` on locked-down Windows runners); omitting it here
    // would make the smoke test exercise a launch contract the product never uses.
    const child = spawn(process.execPath, ["--import", "./scripts/node-platform-compat.mjs", "--import", "tsx", entry], {
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
        // The tail is a stack trace; the line that names the failure comes first. Report
        // that line ahead of a bounded tail, or the caller sees "package_json_reader" and
        // not "Cannot find package 'tsx'".
        rejectPromise(new Error(`the child produced no reply (exit ${code}): ${describeChildFailure(Buffer.concat(err).toString("utf8"))}`));
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
  // Resolved by the *harness*, from wherever the harness runs — not from the artifact.
  // That is deliberate: the artifact's own `pdf-lib` is proven by the child scenarios
  // themselves, because the child imports it from the artifact and cannot start without
  // it. Using a separate copy here keeps fixture generation and output verification
  // independent of the thing under test, so a broken artifact cannot also break (and
  // thereby excuse) its own fixture.
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

scenario("the production runner executes the child inside the artifact", async ({ root }) => {
  // The strongest of the checks: it imports the artifact's **own** `form-worker.ts` and
  // calls `processPdfBounded()` / `fillPdfBounded()`, so the real `childEntry()`
  // resolution, the real `childLaunch()` argument list, the real framing and the real
  // decoder all run. A hand-rolled spawn could agree with production by coincidence;
  // this cannot.
  //
  // R6.4: the module being executed is **shipped**, not written at test time. The
  // previous version composed it into the artifact root, which worked in a checkout and
  // failed inside the production worker image with
  //
  //   EROFS: read-only file system, open '/app/dip-smoke-runner-….mjs'
  //
  // The image's read-only root filesystem is intentional security configuration, so the
  // harness adapts rather than the container. Nothing is written anywhere: the packaged
  // module is executed in place, from the artifact, under the same `--import` preloads
  // and the same working directory that production uses.
  const runner = join(root, RUNNER_MODULE);
  if (!existsSync(runner)) throw new Error(`${RUNNER_MODULE} is missing from ${root}; the launcher cannot be exercised`);
  const launcher = join(root, "src/lib/pdf/form-worker.ts");
  if (!existsSync(launcher)) throw new Error(`the production launcher is missing from ${root}`);

  // `cwd` = artifact root, exactly as production runs it: `childLaunch()` spawns the
  // child with `--import ./scripts/node-platform-compat.mjs`, a *relative* path resolved
  // against the working directory. A relocated copy has no ancestor `node_modules`, so
  // `tsx`, `esbuild`, `pdf-lib` and the canvas addon must all come from the artifact.
  await new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, ["--import", "./scripts/node-platform-compat.mjs", "--import", "tsx", runner], {
      cwd: root,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      env: { PATH: process.env.PATH ?? "", NODE_ENV: "production" },
    });
    const err = [];
    const out = [];
    child.stdout.on("data", (chunk) => out.push(chunk));
    child.stderr.on("data", (chunk) => err.push(chunk));
    child.on("error", rejectPromise);
    child.on("close", (code) => {
      if (code === 0 && Buffer.concat(out).toString("utf8").includes("ok")) return resolvePromise(undefined);
      const diagnostic = sanitize(Buffer.concat(err).toString("utf8"));
      rejectPromise(new Error(`the production runner could not execute the child (exit ${code}): ${diagnostic}`));
    });
  });
  return "runner ok (shipped module, real childEntry + childLaunch + decode; inspect and flatten fill)";
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
      const child = spawn(process.execPath, ["--import", "./scripts/node-platform-compat.mjs", "--import", "tsx", script], {
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

/**
 * Execute the artifact from a directory outside the checkout's dependency ancestry.
 *
 * ## Why this exists
 *
 * Node resolves a bare specifier by walking `node_modules` up the directory chain. A
 * Next standalone tree lives at `<repo>/.next/standalone`, so running it *in place* lets
 * every missing package be satisfied by `<repo>/node_modules` — the very installation
 * the artifact is supposed to replace. Verified directly: a file in
 * `<repo>/.next/probe/` resolves `tsx` from `<repo>/node_modules`, while the same file
 * in an unrelated temp directory fails with `ERR_MODULE_NOT_FOUND`.
 *
 * That makes an in-place smoke run unable to tell "the artifact is complete" from "the
 * checkout was complete". Copying the artifact to a temp directory outside the checkout
 * removes the fallback: nothing is added to the copy, so anything it cannot find is
 * genuinely missing from the artifact.
 *
 * The copy is byte-identical — no dependencies are installed into it, no configuration
 * is generated for it. It is the shipped artifact, moved.
 */
export function isolateArtifact(root) {
  const isolated = mkdtempSync(join(tmpdir(), "dip-artifact-"));
  cpSync(root, isolated, { recursive: true, verbatimSymlinks: true, dereference: false });
  return isolated;
}

/**
 * Fail if the relocated copy contains a symlink that leaves it.
 *
 * The point of relocating is that *nothing* the artifact needs may come from outside it.
 * A symlink to the checkout — pnpm-style `node_modules` layouts, or a stray link in a
 * traced tree — would silently restore that fallback: the scenarios would pass while the
 * shipped artifact was still incomplete. `verbatimSymlinks` copies links as links rather
 * than dereferencing them, so this check sees what the artifact actually ships.
 */
export function findEscapingSymlinks(root) {
  const escaping = [];
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const full = join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        const target = realpathSync(full);
        if (!target.startsWith(root + sep) && target !== root) escaping.push(`${full} -> ${target}`);
      } else if (entry.isDirectory()) {
        walk(full);
      }
    }
  };
  walk(root);
  return escaping;
}

const root = resolve(process.argv[2] ?? process.cwd());

/** Wall-clock ceiling for the whole suite, so a wedged child cannot hang CI. */
const SUITE_TIMEOUT_MS = Number(process.env.SMOKE_TIMEOUT_MS ?? 600_000);
const suiteTimer = setTimeout(() => {
  console.error(`\nArtifact smoke timed out after ${SUITE_TIMEOUT_MS}ms. A scenario did not return;`);
  console.error("the child it spawned may be wedged rather than slow.");
  process.exit(1);
}, SUITE_TIMEOUT_MS);
suiteTimer.unref();

// The scenario list runs only when this file is executed directly. Importing it (a
// test, or a future caller) must not spawn children or exit the process.
const invokedDirectly = Boolean(process.argv[1]) && import.meta.url === `file://${resolve(process.argv[1])}`;
if (invokedDirectly) {
  // Relocate before executing, so no scenario can be satisfied by the checkout's
  // `node_modules`. `--in-place` exists only for running against a tree that is already
  // outside the repository; it is not used by CI.
  const inPlace = process.argv.includes("--in-place");
  const artifactRoot = inPlace ? root : isolateArtifact(root);
  // The relocated copy is a full artifact (megabytes, sometimes hundreds of them). Leaving
  // it behind leaks disk on every CI run, so it is removed whether the suite passes or
  // fails; `--in-place` copies nothing and therefore cleans nothing.
  if (!inPlace) {
    process.on("exit", () => rmSync(artifactRoot, { recursive: true, force: true }));
  }
  if (!inPlace) {
    const escaping = findEscapingSymlinks(artifactRoot);
    if (escaping.length) {
      console.error("The artifact contains symlinks that resolve outside it, so the isolation");
      console.error("this run claims would be false. Missing packages would be satisfied from");
      console.error("their targets instead of from the artifact:");
      for (const link of escaping.slice(0, 10)) console.error(`  - ${link}`);
      process.exit(1);
    }
  }
  const entry = findEntry(artifactRoot);
  if (!entry) {
    console.error(`No PDF worker child entry found under ${artifactRoot}. Searched: ${SEARCH_ROOTS.join(", ")}`);
    process.exit(1);
  }
  console.log(`Artifact root: ${sanitize(root, null)}`);
  if (!inPlace) console.log(`Executing from: ${artifactRoot} (isolated from the checkout)`);
  console.log(`Child entry:   ${entry}`);

  const failures = [];
  for (const { name, run } of scenarios) {
    try {
      const detail = await run({ entry, root: artifactRoot });
      console.log(`  PASS  ${name} — ${detail}`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.log(`  FAIL  ${name} — ${sanitize(message, artifactRoot)}`);
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
  if (!inPlace) {
    console.log(`Executed from ${artifactRoot} with no access to the checkout's node_modules.`);
  }
}
