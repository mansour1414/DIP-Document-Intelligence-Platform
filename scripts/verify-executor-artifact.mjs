#!/usr/bin/env node
/**
 * Build-time verification of the executor artifact (R7D.1).
 *
 * ## Why this runs inside the build
 *
 * A runtime image that starts successfully proves very little. The failure this catches is the
 * one that only appears when a document is actually parsed: a font file excluded from the
 * closure, a native binary built for the wrong libc, an ESM/CJS interop error in a file that is
 * only imported on the fill path. The build fails here instead of the first document failing in
 * production.
 *
 * What it does **not** prove: that the container is isolated. Image build, layer contents and
 * every OS-level enforcement claim require Docker, which is unavailable in this environment, so
 * those are NOT TESTED and must not be inferred from this passing.
 *
 * Usage: node dist/verify-executor-artifact.mjs /app
 */

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";

const appRoot = process.argv[2] ?? "/app";
const failures = [];
const checks = [];

function check(label, fn) {
  try {
    const detail = fn();
    checks.push({ label, ok: true, detail });
  } catch (error) {
    checks.push({ label, ok: false, detail: error instanceof Error ? error.message : String(error) });
    failures.push(label);
  }
}

// ---------------------------------------------------------------------------------------
// 1. The entrypoint and its bundle exist and are non-trivial.
// ---------------------------------------------------------------------------------------

check("entrypoint bundle exists", () => {
  const path = join(appRoot, "dist", "executor-child.js");
  if (!existsSync(path)) throw new Error(`missing ${path}`);
  const size = statSync(path).size;
  // A bundle that is too small means the build "succeeded" without including the child.
  if (size < 8_192) throw new Error(`bundle is only ${size} bytes, which cannot contain the child`);
  return `${size} bytes`;
});

check("child answers the protocol version", () => {
  // Execute it rather than read it. A module that imports but crashes on load is exactly the
  // case a file-existence check misses.
  const out = execFileSync(process.execPath, [join(appRoot, "dist", "executor-child.js"), "--self-check"], {
    encoding: "utf8",
    timeout: 30_000,
    stdio: ["ignore", "pipe", "pipe"],
    env: { PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin" },
  });
  const parsed = JSON.parse(out);
  if (parsed.protocolVersion !== 2) throw new Error(`unexpected protocol version ${String(parsed.protocolVersion)}`);
  if (parsed.selfCheck !== true) throw new Error("self-check did not report success");
  return `protocol v${String(parsed.protocolVersion)}`;
});

// ---------------------------------------------------------------------------------------
// 2. The runtime dependency closure is exactly what was intended.
// ---------------------------------------------------------------------------------------

/**
 * The exact runtime closure, including pdf-lib's own dependencies.
 *
 * The first version listed only the five direct packages and passed while the image was
 * missing `@pdf-lib/standard-fonts` and `@pdf-lib/upng`. The check is "the closure is complete",
 * not "these names are present", so the transitive entries are enumerated rather than assumed.
 */
const EXPECTED_PACKAGES = [
  "pdf-lib",
  "@pdf-lib/standard-fonts",
  "@pdf-lib/upng",
  "@napi-rs/canvas",
  "@napi-rs/canvas-linux-x64-gnu",
  "@fontsource/noto-sans-arabic",
  "pako",
  "tslib",
];

check("runtime closure matches the declared set", () => {
  const modules = join(appRoot, "node_modules");
  if (!existsSync(modules)) throw new Error("no node_modules in the runtime image");
  const present = readdirSync(modules).filter((name) => !name.startsWith("."));
  const unexpected = present.flatMap((name) => {
    if (!name.startsWith("@")) return EXPECTED_PACKAGES.includes(name) ? [] : [name];
    // A scope directory is not a package. Expand it, so `@pdf-lib/upng` being absent is caught
    // rather than the scope merely existing.
    return readdirSync(join(modules, name)).map((child) => `${name}/${child}`)
      .filter((scoped) => !EXPECTED_PACKAGES.includes(scoped));
  });
  if (unexpected.length > 0) throw new Error(`unexpected packages: ${unexpected.join(", ")}`);
  for (const required of EXPECTED_PACKAGES) {
    if (!existsSync(join(modules, required))) throw new Error(`missing required package: ${required}`);
  }
  return EXPECTED_PACKAGES.join(", ");
});

check("no database, cache or cloud SDK reached the runtime image", () => {
  // The executor parses documents. It has no business holding a database client, a Redis client
  // or a cloud SDK, and a credential reaching this image is a much worse bug than a slow build.
  const forbidden = ["@prisma/client", "prisma", "ioredis", "bullmq", "@aws-sdk", "openai", "groq-sdk"];
  const modules = join(appRoot, "node_modules");
  const found = forbidden.filter((name) => existsSync(join(modules, name)));
  if (found.length > 0) throw new Error(`forbidden packages present: ${found.join(", ")}`);
  return "none present";
});

// ---------------------------------------------------------------------------------------
// 3. The native surface works, not merely exists.
// ---------------------------------------------------------------------------------------

check("font assets resolve through require.resolve", () => {
  // `require.resolve` is what pdf-lib's font embedding actually calls. A copied file passes an
  // existence check and fails here, which is why the closure keeps the package intact instead
  // of flattening the two woff files into place.
  const require = createRequire(join(appRoot, "dist", "executor-child.js"));
  const expected = [
    ["@fontsource/noto-sans-arabic/files/noto-sans-arabic-arabic-400-normal.woff", 79_084],
    ["@fontsource/noto-sans-arabic/files/noto-sans-arabic-latin-400-normal.woff", 13_620],
  ];
  for (const [specifier, size] of expected) {
    const resolved = require.resolve(specifier);
    const actual = statSync(resolved).size;
    // Exact byte sizes: a truncated or substituted font would otherwise embed and render
    // squares, which the structural checks in verify would not catch.
    if (actual !== size) throw new Error(`${specifier} is ${actual} bytes, expected ${size}`);
  }
  return "2 fonts, byte-exact";
});

check("the native canvas binding loads", () => {
  // A .node binary for the wrong libc or architecture throws here rather than at first use.
  const script = `
    const { createCanvas } = require(${JSON.stringify(join(appRoot, "node_modules", "@napi-rs", "canvas"))});
    const canvas = createCanvas(64, 64);
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#123456";
    ctx.fillRect(0, 0, 64, 64);
    const data = ctx.getImageData(4, 4, 1, 1).data;
    if (data[0] !== 0x12 || data[1] !== 0x34 || data[2] !== 0x56) throw new Error("canvas rendered the wrong pixel");
    console.log("ok");
  `;
  const out = execFileSync(process.execPath, ["-e", script], { encoding: "utf8", timeout: 30_000 });
  if (!out.includes("ok")) throw new Error("canvas did not render");
  return "canvas renders";
});

check("pdf-lib round-trips a document", () => {
  // Importing pdf-lib and never calling it would not exercise the code paths the executor uses.
  const script = `
    (async () => {
      const { PDFDocument } = require(${JSON.stringify(join(appRoot, "node_modules", "pdf-lib"))});
      const doc = await PDFDocument.create();
      doc.addPage([200, 400]);
      const bytes = await doc.save();
      const reopened = await PDFDocument.load(bytes);
      if (reopened.getPageCount() !== 1) throw new Error("page count changed");
      console.log("ok");
    })().catch((error) => { console.error(error); process.exit(1); });
  `;
  const out = execFileSync(process.execPath, ["-e", script], { encoding: "utf8", timeout: 30_000 });
  if (!out.includes("ok")) throw new Error("pdf-lib round-trip failed");
  return "round-trips";
});

// ---------------------------------------------------------------------------------------
// 4. The image does not carry content it must not have.
// ---------------------------------------------------------------------------------------

check("no document, credential or environment file is baked in", () => {
  const forbidden = [".env", ".env.local", "id_rsa", "id_ed25519", ".npmrc", "prisma/schema.prisma"];
  const found = [];
  for (const relative of forbidden) {
    if (existsSync(join(appRoot, relative))) found.push(relative);
  }
  // A stray PDF anywhere in the image would mean a fixture was copied by a broad ADD.
  const walk = (dir, depth) => {
    if (depth > 3) return;
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === "node_modules" || entry.name.startsWith(".")) continue;
      const path = join(dir, entry.name);
      if (entry.isDirectory()) walk(path, depth + 1);
      else if (entry.name.toLowerCase().endsWith(".pdf")) found.push(path.slice(appRoot.length + 1));
    }
  };
  walk(appRoot, 0);
  if (found.length > 0) throw new Error(`forbidden content: ${found.join(", ")}`);
  return "clean";
});

check("the entrypoint is not world-writable", () => {
  const path = join(appRoot, "dist", "executor-child.js");
  const mode = statSync(path).mode & 0o777;
  if ((mode & 0o002) !== 0) throw new Error(`entrypoint is world-writable (mode ${mode.toString(8)})`);
  return `mode ${mode.toString(8)}`;
});

// ---------------------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------------------

for (const entry of checks) {
  console.log(`${entry.ok ? "  ok" : "FAIL"}  ${entry.label}${entry.ok ? ` — ${entry.detail}` : `\n        ${entry.detail}`}`);
}
console.log(`\n${checks.length - failures.length}/${checks.length} artifact checks passed`);

if (failures.length > 0) {
  console.error(`\nartifact verification failed: ${failures.join("; ")}`);
  process.exit(1);
}
