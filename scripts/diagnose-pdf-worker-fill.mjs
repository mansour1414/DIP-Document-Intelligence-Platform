#!/usr/bin/env node
/**
 * Diagnose a Fill Forms failure inside a real artifact (R7C.1, Task B).
 *
 * ## Why this exists
 *
 * The ARM64 Alpine artifact refused `fill`, `flatten`, Arabic and the runner with
 * `{"ok":false,"code":"FORM_UNSUPPORTED","details":{"reason":"UNEXPECTED"}}`, while
 * `inspect` and the protocol check passed. `failureMeta()` deliberately collapses any
 * unexpected throw into `UNEXPECTED`, because a raw message could quote document bytes.
 * That is the right production behaviour and a useless diagnostic: every possible cause
 * — a missing font, an unloadable addon, a bad temp directory — looks identical.
 *
 * This script is the missing half. It runs the **real child entry**, as a spawned process
 * with the **real minimal environment**, against the same synthetic fixtures, and reports
 * where the failure actually occurs. It never runs in production and never changes what
 * production returns.
 *
 * ## What makes this faithful rather than a simulation
 *
 * The whole difficulty of the original investigation is that a direct in-process call
 * behaves differently from the spawned child (OpenCode's `fillFormPdf` call succeeded
 * while the child refused the same document). So this harness deliberately:
 *
 *   - spawns `src/lib/pdf/form-worker-child.ts` through the same `--import` prelude
 *     `childLaunch()` uses, over the same fd-3 protocol;
 *   - passes the same minimal environment (`PATH`, `NODE_ENV`) by default;
 *   - feeds the identical bytes through the real `encodeControl()`.
 *
 * Any divergence between this and the production child would be a bug in this script, so
 * it imports the production encoder and launcher inputs rather than re-implementing them.
 *
 * ## What it adds
 *
 * 1. **Per-stage probes inside the child** — because the child's own error is masked, the
 *    harness runs a second child that performs each stage of the appearance path
 *    individually (font resolve, font register, canvas create, text measure, full fill)
 *    and reports which stage throws and with what real error.
 * 2. **Environment differential** — repeats the fill under minimal env and with
 *    `TMPDIR`/`HOME` added, so an environment hypothesis can be confirmed or falsified
 *    rather than assumed. (It was falsified on glibc/x64: all variants succeeded.)
 * 3. **Font-file presence** — the artifact verifier only checks the font *package*, not
 *    the two `.woff` files `registerFormFonts()` actually opens. Missing files were
 *    confirmed to produce the exact observed refusal, so their presence is reported here.
 *
 * ## Usage
 *
 *   node scripts/diagnose-pdf-worker-fill.mjs [artifact-root]
 *
 * Exit status: 0 if every stage that should succeed did; 1 if any stage failed. It prints
 * a compact JSON report, which is safe to paste into a review (no document bytes, no
 * environment dump, no credentials).
 *
 * Run it **inside** the image you are diagnosing, for example:
 *
 *   docker run --rm --entrypoint node -v "$PWD:/diag:ro" dip-document-app:r7c1 \
 *     /app/scripts/diagnose-pdf-worker-fill.mjs /app
 */
import { spawn } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

const ARTIFACT_ROOT = resolve(process.argv[2] ?? process.cwd());

/** The child entry, found the way `form-worker.ts` finds it. */
function childEntry(root) {
  for (const candidate of [
    join(root, "src/lib/pdf/form-worker-child.ts"),
    join(root, "src/lib/pdf/form-worker-child.js"),
    join(root, ".next/standalone/src/lib/pdf/form-worker-child.ts"),
  ]) {
    if (existsSync(candidate)) return candidate;
  }
  return undefined;
}

/** The two font files `registerFormFonts()` opens, resolved as the child resolves them. */
const REQUIRED_FONTS = [
  "node_modules/@fontsource/noto-sans-arabic/files/noto-sans-arabic-arabic-400-normal.woff",
  "node_modules/@fontsource/noto-sans-arabic/files/noto-sans-arabic-latin-400-normal.woff",
];

function fontReport(root) {
  return REQUIRED_FONTS.map((relative) => {
    const path = join(root, relative);
    const present = existsSync(path);
    return {
      file: relative.split("/").pop(),
      present,
      ...(present ? { bytes: statSync(path).size } : {}),
    };
  });
}

/**
 * Ask a spawned child to run one diagnostic stage.
 *
 * The probe is a small ES module written to a temporary file inside the artifact's own
 * dependency scope, so it resolves `@napi-rs/canvas` and the font package exactly as the
 * production child would — a probe placed elsewhere would use a different resolution
 * chain and answer a different question.
 */
function runStage(entry, stage, { env }) {
  return new Promise((done) => {
    const script = `
      const stage = ${JSON.stringify(stage)};
      const out = (value) => { process.stdout.write("STAGE_RESULT:" + JSON.stringify(value)); };
      (async () => {
        try {
          if (stage === "font-resolve") {
            const { createRequire } = await import("node:module");
            const require = createRequire(import.meta.url);
            const pkg = require.resolve("@fontsource/noto-sans-arabic/package.json");
            out({ ok: true, resolved: typeof pkg === "string" && pkg.endsWith("package.json") });
          } else if (stage === "canvas-load") {
            const { createRequire } = await import("node:module");
            const require = createRequire(import.meta.url);
            const { createCanvas } = require("@napi-rs/canvas");
            const c = createCanvas(64, 64);
            const ctx = c.getContext("2d");
            ctx.fillStyle = "#fff"; ctx.fillRect(0, 0, 64, 64);
            out({ ok: true, pixels: Array.from(ctx.getImageData(0, 0, 1, 1).data) });
          } else if (stage === "font-register") {
            const mod = await import("./src/lib/pdf/form-appearance.ts");
            mod.registerFormFonts();
            out({ ok: true });
          } else if (stage === "text-measure") {
            const mod = await import("./src/lib/pdf/form-appearance.ts");
            mod.registerFormFonts();
            const { createRequire } = await import("node:module");
            const require = createRequire(import.meta.url);
            const { createCanvas } = require("@napi-rs/canvas");
            const ctx = createCanvas(400, 80).getContext("2d");
            ctx.font = '400 20px "DIP Form Latin", "DIP Form Arabic"';
            out({ ok: true, width: Math.round(ctx.measureText("Worker Filled").width) });
          }
        } catch (error) {
          // The REAL error, for diagnosis only. Production never emits this.
          out({ ok: false, name: error?.name, code: error?.code, message: String(error?.message ?? error).slice(0, 300) });
        }
      })();
    `;
    // `-e` with the artifact as cwd: the probe resolves from the artifact, not from here.
    const child = spawn(process.execPath, ["--import", "./scripts/node-platform-compat.mjs", "--import", "tsx", "-e", script], {
      cwd: ARTIFACT_ROOT,
      shell: false,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr = `${stderr}${chunk.toString()}`.slice(-800); });
    child.on("error", (error) => done({ ok: false, message: `spawn failed: ${error.code ?? error.message}` }));
    child.on("close", (code) => {
      const line = stdout.split("\n").find((entry) => entry.startsWith("STAGE_RESULT:"));
      if (line) return done(JSON.parse(line.slice("STAGE_RESULT:".length)));
      // No result line: the process died before reporting, so the exit status and the tail
      // of stderr are the diagnosis.
      done({ ok: false, message: `no result (exit ${code})`, stderr: stderr.split("\n").filter(Boolean).slice(-3).join(" | ") });
    });
  });
}

/**
 * Produce the exact request frame, using the artifact's own `encodeControl()`.
 *
 * Run in a `tsx` child because the protocol module is TypeScript with parameter
 * properties. The output is the frame bytes on stdout, base64-encoded so the pipe stays
 * binary-safe.
 */
async function buildFrame(root, arabic) {
  const script = `
    const { encodeControl } = await import("./src/lib/pdf/worker-protocol.ts");
    const { PDFDocument, StandardFonts } = await import("pdf-lib");
    const doc = await PDFDocument.create();
    const page = doc.addPage([300, 200]);
    const font = await doc.embedFont(StandardFonts.Helvetica);
    doc.getForm().createTextField("applicant.name").addToPage(page, { x: 20, y: 120, width: 240, height: 24, font });
    const pdf = await doc.save();
    const frame = encodeControl(
      { v: 1, op: "fill", flatten: false, fields: { "applicant.name": ${JSON.stringify(arabic ? "نورة الحربي" : "Worker Filled")} } },
      pdf,
      10_000_000,
    );
    process.stdout.write(frame.toString("base64"));
  `;
  return await new Promise((done, fail) => {
    const child = spawn(process.execPath, ["--import", "./scripts/node-platform-compat.mjs", "--import", "tsx", "-e", script], {
      cwd: root, shell: false, env: MINIMAL, stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
    child.on("close", (code) => {
      if (code !== 0) return fail(new Error(`frame build failed (${code}): ${stderr.slice(-300)}`));
      done(Buffer.from(stdout.trim(), "base64"));
    });
  });
}

/**
 * Run a full fill through the real protocol, under a chosen environment.
 *
 * The frame comes from the production encoder so the bytes are identical to a real job.
 */
async function runFill(entry, { env, arabic, root }) {
  // Build the frame with the artifact's OWN encoder under tsx, so the bytes are identical
  // to production. This script is plain ESM (it must run where only `node` exists), and
  // importing TypeScript directly would rely on Node's strip-only loader, which rejects
  // the parameter properties the protocol module uses.
  const frame = await buildFrame(root, arabic);
  return await new Promise((done) => {
    const child = spawn(process.execPath, ["--import", "./scripts/node-platform-compat.mjs", "--import", "tsx", "src/lib/pdf/form-worker-child.ts"], {
      cwd: root, shell: false, env, stdio: ["pipe", "pipe", "pipe", "pipe"],
    });
    const out = [];
    let stderr = "";
    child.stdio[3].on("data", (chunk) => out.push(chunk));
    child.stderr.on("data", (chunk) => { stderr = `${stderr}${chunk.toString()}`.slice(-800); });
    child.stdin.on("error", () => undefined);
    child.stdin.end(frame);
    child.on("close", (code) => {
      const buffer = Buffer.concat(out);
      if (!buffer.length) return done({ ok: false, message: `no reply (exit ${code})`, stderr: stderr.split("\n").filter(Boolean).slice(-3).join(" | ") });
      try {
        done(JSON.parse(buffer.subarray(4, 4 + buffer.readUInt32BE(0)).toString()));
      } catch (error) {
        done({ ok: false, message: `unreadable reply: ${String(error).slice(0, 120)}` });
      }
    });
  });
}

// The production environment, verbatim from `childLaunch()`.
const MINIMAL = { PATH: process.env.PATH ?? "", NODE_ENV: process.env.NODE_ENV ?? "production" };

const entry = childEntry(ARTIFACT_ROOT);
const report = { artifactRoot: ARTIFACT_ROOT, platform: `${process.platform}/${process.arch}`, childEntry: entry ?? "NOT FOUND", fonts: fontReport(ARTIFACT_ROOT) };

if (!entry) {
  console.log(JSON.stringify({ ...report, result: "BLOCKED: no child entry in this artifact" }, null, 2));
  process.exit(1);
}

report.stages = {};
for (const stage of ["font-resolve", "canvas-load", "font-register", "text-measure"]) {
  report.stages[stage] = await runStage(entry, stage, { env: MINIMAL });
}

// The environment differential: the TMPDIR hypothesis, tested rather than assumed.
report.fill = {
  minimalLatin: await runFill(entry, { env: MINIMAL, arabic: false, root: ARTIFACT_ROOT }),
  minimalArabic: await runFill(entry, { env: MINIMAL, arabic: true, root: ARTIFACT_ROOT }),
  withTmpdirArabic: await runFill(entry, { env: { ...MINIMAL, TMPDIR: "/tmp", HOME: "/tmp" }, arabic: true, root: ARTIFACT_ROOT }),
};

const failed = report.fonts.some((font) => !font.present)
  || Object.values(report.stages).some((stage) => stage.ok !== true)
  || !report.fill.minimalLatin.ok
  || !report.fill.minimalArabic.ok;

console.log(JSON.stringify({ ...report, result: failed ? "FAIL" : "PASS" }, null, 2));
process.exit(failed ? 1 : 0);
