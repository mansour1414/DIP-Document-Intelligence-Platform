/**
 * R7D.1 — the real executor child over the real fd 3 bridge (F02 executor evidence).
 *
 * ## Why this test spawns a process
 *
 * Every other suite exercises functions. This one runs the actual built bundle as a child
 * process, sends it a real control frame over stdin, and reads the result frame off file
 * descriptor 3 — the same three-way arrangement the supervisor will use. That is the only way
 * to establish the things that are properties of the *arrangement* rather than of any function:
 * that fd 3 is the result channel and stdout is not, that a short write is retried rather than
 * silently truncating a document, and that a closed pipe fails rather than spins.
 *
 * ## What this still does not prove
 *
 * No container, no namespace, no seccomp profile. Docker is unavailable, so isolation remains
 * NOT TESTED. This proves the child's I/O contract; it says nothing about the box it will run in.
 */

import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { PDFDocument, StandardFonts } from "pdf-lib";
import { decodeResultV2, encodeControlV2 } from "../src/lib/pdf/worker-protocol-v2";

const BUNDLE = join(process.cwd(), "dist", "executor-child.js");
/** The hard input ceiling, so the fixture is never silently clipped. */
const MAX_BODY = 512 * 1024 * 1024;

let workdir: string;

before(async () => {
  workdir = mkdtempSync(join(tmpdir(), "dip-executor-"));
  if (!existsSync(BUNDLE)) {
    // Build it here rather than requiring a prior step. CI runs `npm test`, which globs every
    // suite; a test that only passes when someone remembered to build first would either fail
    // CI or — worse, if it skipped instead — report green without running.
    //
    // The builder uses the esbuild already on disk as a locked transitive dependency of `tsx`.
    // No package is added and the lockfile is untouched.
    execFileSync(process.execPath, [join(process.cwd(), "scripts", "esbuild-executor.mjs")], {
      stdio: "pipe",
      timeout: 120_000,
    });
  }
  if (!existsSync(BUNDLE)) throw new Error(`the executor bundle could not be built at ${BUNDLE}`);
});

after(() => {
  rmSync(workdir, { recursive: true, force: true });
});

/** A small form with one text field and one checkbox, built in-process. */
async function fixturePdf(): Promise<Buffer> {
  const document = await PDFDocument.create();
  const page = document.addPage([300, 400]);
  const font = await document.embedFont(StandardFonts.Helvetica);
  page.drawText("Synthetic fixture", { x: 20, y: 360, size: 12, font });
  const form = document.getForm();
  const text = form.createTextField("applicant.name");
  text.addToPage(page, { x: 20, y: 320, width: 200, height: 20 });
  const check = form.createCheckBox("applicant.consent");
  check.addToPage(page, { x: 20, y: 290, width: 12, height: 12 });
  return Buffer.from(await document.save());
}

type ChildOutcome = {
  exitCode: number | null;
  fd3: Buffer;
  stdout: string;
  stderr: string;
};

/**
 * Run the child, write the frame to stdin, collect fd 3.
 *
 * `stdio[3]` is the whole point: the child writes results there and diagnostics to stdout and
 * stderr. If the child wrote the document to stdout instead, the frame would not decode here.
 */
function runChild(frame: Buffer, options: { timeoutMs?: number } = {}): Promise<ChildOutcome> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [BUNDLE], {
      stdio: ["pipe", "pipe", "pipe", "pipe"],
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", NODE_ENV: "production" },
    });
    const fd3: Buffer[] = [];
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("child did not exit within the budget"));
    }, options.timeoutMs ?? 20_000);

    (child.stdio[3] as NodeJS.ReadableStream).on("data", (chunk: Buffer) => fd3.push(chunk));
    child.stdout?.on("data", (chunk: Buffer) => out.push(chunk));
    child.stderr?.on("data", (chunk: Buffer) => err.push(chunk));
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({
        exitCode: code,
        fd3: Buffer.concat(fd3),
        stdout: Buffer.concat(out).toString("utf8"),
        stderr: Buffer.concat(err).toString("utf8"),
      });
    });

    // Explicit end of body: the child decodes on stdin end, so closing the stream is part of
    // the protocol rather than an optimization.
    child.stdin?.end(frame);
  });
}

// ---------------------------------------------------------------------------------------
// The bridge
// ---------------------------------------------------------------------------------------

test("R7D.1-X-1: a real inspect request travels stdin → child → fd 3", async () => {
  const pdf = await fixturePdf();
  const frame = encodeControlV2({ v: 2, op: "inspect" }, pdf, MAX_BODY);
  const outcome = await runChild(frame);

  assert.equal(outcome.exitCode, 0, `child failed: ${outcome.stderr}`);
  assert.ok(outcome.fd3.byteLength > 0, "the result must arrive on fd 3");
  // stdout is for diagnostics. A document on stdout would be indistinguishable in structure
  // from a result on fd 3, which is why the two channels are kept strictly separate.
  assert.equal(outcome.stdout.includes("applicant.name"), false, "the inventory must not leak to stdout");

  const { meta, output } = decodeResultV2(outcome.fd3, 1 << 20, "inspect");
  assert.equal(meta.ok, true);
  assert.equal(meta.op, "inspect");
  if (meta.op !== "inspect") throw new Error("unreachable");
  assert.ok(meta.inventory.fields.length >= 2, "both fixture fields must be found");
  const names = meta.inventory.fields.map((field) => field.name).sort();
  assert.deepEqual(names, ["applicant.consent", "applicant.name"]);
  // A metadata-only result carries no document bytes.
  assert.equal(output.byteLength, 0);
});

test("R7D.1-X-2: a real fill request returns the document on fd 3 and metadata that matches it", async () => {
  const pdf = await fixturePdf();
  const frame = encodeControlV2(
    { v: 2, op: "fill", fields: { "applicant.name": "Layla", "applicant.consent": true }, flatten: false },
    pdf,
    MAX_BODY,
  );
  const outcome = await runChild(frame);
  assert.equal(outcome.exitCode, 0, `child failed: ${outcome.stderr}`);

  const { meta, output } = decodeResultV2(outcome.fd3, 1 << 20, "fill");
  assert.equal(meta.ok, true);
  if (meta.op !== "fill") throw new Error("unreachable");
  // The declaration must match the bytes that actually arrived. This is the F02 rule, checked
  // here against a real subprocess rather than a constructed frame.
  assert.equal(meta.outBytes, output.byteLength);
  assert.ok(output.byteLength > 0, "the filled document must be on fd 3");
  assert.equal(meta.report.filled, 2);

  // The bytes really are a PDF, and really contain the value.
  const reopened = await PDFDocument.load(output);
  assert.equal(reopened.getPageCount(), 1);
  const field = reopened.getForm().getTextField("applicant.name");
  assert.equal(field.getText(), "Layla");
});

test("R7D.1-X-3: a real verify request confirms the filled document and returns no bytes", async () => {
  const pdf = await fixturePdf();
  const fillFrame = encodeControlV2(
    { v: 2, op: "fill", fields: { "applicant.name": "Layla", "applicant.consent": true }, flatten: false },
    pdf,
    MAX_BODY,
  );
  const filled = await runChild(fillFrame);
  assert.equal(filled.exitCode, 0, filled.stderr);
  const filledResult = decodeResultV2(filled.fd3, 1 << 20, "fill");

  // A second, independent process verifies the output. "Fresh parser" is not a slogan here:
  // it is a different OS process that has never seen the input document.
  const verifyFrame = encodeControlV2(
    {
      v: 2,
      op: "verify",
      baseline: {
        kind: "fill",
        expected: { "applicant.name": "Layla", "applicant.consent": true },
        untouched: {},
      },
    },
    Buffer.from(filledResult.output),
    512 * 1024 * 1024,
  );
  const verified = await runChild(verifyFrame);
  assert.equal(verified.exitCode, 0, verified.stderr);
  const { meta, output } = decodeResultV2(verified.fd3, 1 << 20, "verify");
  assert.equal(meta.ok, true);
  if (meta.op !== "verify") throw new Error("unreachable");
  assert.equal(meta.pages, 1);
  assert.ok(meta.preserved >= 0);
  assert.equal(output.byteLength, 0, "verify is metadata-only");
});

test("R7D.1-X-4: a document the engine refuses produces a refusal frame, not a crash", async () => {
  // Not a PDF at all. The executor must report this as data, so the supervisor can distinguish
  // "the executor refused" from "the executor died" without inspecting exit codes alone.
  const garbage = Buffer.from("this is not a pdf", "utf8");
  const frame = encodeControlV2({ v: 2, op: "inspect" }, garbage, MAX_BODY);
  const outcome = await runChild(frame);

  assert.equal(outcome.exitCode, 0, `a refusal is not a crash: ${outcome.stderr}`);
  const { meta, output } = decodeResultV2(outcome.fd3, 1 << 20, "inspect");
  assert.equal(meta.ok, false, "a refusal must be reported as a failure, not as success");
  if (meta.ok) throw new Error("unreachable");
  assert.equal(typeof meta.code, "string");
  // An FF-08 style refusal is content-free: no field value, no document fragment.
  assert.equal(JSON.stringify(meta).includes("not a pdf"), false, "the refusal must not echo the document");
  assert.equal(output.byteLength, 0);
});

test("R7D.1-X-5: a truncated input is refused before the engine sees it", async () => {
  const pdf = await fixturePdf();
  // Declare more bytes than are sent. The child must notice the short body rather than parse a
  // document that is missing its tail.
  const complete = encodeControlV2({ v: 2, op: "inspect" }, pdf, MAX_BODY);
  const frame = complete.subarray(0, complete.byteLength - 1_000);
  const outcome = await runChild(frame);
  assert.equal(outcome.exitCode, 0, outcome.stderr);
  const { meta } = decodeResultV2(outcome.fd3, 1 << 20, "inspect");
  assert.equal(meta.ok, false, "a short body must be refused");
});

test("R7D.1-X-6: the child exits rather than hanging when stdin closes with no frame", async () => {
  // A supervisor that dies leaves the child with an empty stdin. Exiting promptly is what lets
  // the watchdog's deadline be the only thing that ever needs to fire.
  const outcome = await runChild(Buffer.alloc(0), { timeoutMs: 10_000 });
  assert.notEqual(outcome.exitCode, null, "the child must exit on its own");
  assert.equal(outcome.stdout.includes("Error"), false, "an empty request is not an uncaught exception");
});

test("R7D.1-X-7: the artifact self-check passes on the built bundle", async () => {
  // Executes the bundle rather than reading it. A module that imports and crashes on first use
  // is exactly what a file-existence check misses.
  const child = spawn(process.execPath, [BUNDLE, "--self-check"], { stdio: ["ignore", "pipe", "pipe"] });
  const out: Buffer[] = [];
  const err: Buffer[] = [];
  child.stdout.on("data", (chunk: Buffer) => out.push(chunk));
  child.stderr.on("data", (chunk: Buffer) => err.push(chunk));
  const code = await new Promise<number | null>((resolve) => child.on("close", resolve));
  assert.equal(code, 0, `self-check failed: ${Buffer.concat(err).toString("utf8")}`);
  const parsed = JSON.parse(Buffer.concat(out).toString("utf8")) as { selfCheck: boolean; protocolVersion: number };
  assert.equal(parsed.selfCheck, true);
  assert.equal(parsed.protocolVersion, 2);
});

test("R7D.1-X-8: the bundle contains no TypeScript loader and no test surface", async () => {
  // The executor runs where input is hostile. Shipping a TypeScript loader or a mock framework
  // into it would be a needless surface, and the point of precompiling is that it is not there.
  const source = readFileSync(BUNDLE, "utf8");
  for (const forbidden of ["tsx", "esbuild", "node:test", "require(\"typescript\")"]) {
    assert.equal(source.includes(forbidden), false, `the executor bundle must not contain ${forbidden}`);
  }
});
