/**
 * R7C.1 — the Task B diagnostic harness must actually diagnose.
 *
 * ## Why a test for a diagnostic
 *
 * The ARM64 Alpine failure arrived as `FORM_UNSUPPORTED / {"reason":"UNEXPECTED"}`, which
 * is what `failureMeta()` produces for *any* unexpected throw. While investigating it I
 * reproduced that exact refusal by hiding the bundled font files — which proved the
 * message is not attributable to a cause on its own. A diagnostic harness that reports
 * "something failed" is therefore worthless; it has to name the *stage* and the *real
 * error*, or the next investigation starts from zero again.
 *
 * So this asserts the harness's discriminating power on the one fault that could be
 * produced deterministically here: with the font files present it reports PASS, and with
 * them absent it exits 1, marks the font files missing, and surfaces `FONT_UNAVAILABLE`
 * from the stage probe rather than the masked protocol code.
 *
 * The fonts are moved aside and restored in a `finally`, so a failed assertion cannot
 * leave the checkout broken.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, renameSync } from "node:fs";
import { join } from "node:path";

const ROOT = process.cwd();
const FONT_DIR = join(ROOT, "node_modules/@fontsource/noto-sans-arabic/files");
const FONT_HIDDEN = join(ROOT, "node_modules/@fontsource/noto-sans-arabic/files.HIDDEN");
const HARNESS = join(ROOT, "scripts/diagnose-pdf-worker-fill.mjs");

/** Run the harness and capture its JSON report regardless of exit status. */
function diagnose(): { status: number; report: { result: string; fonts: Array<{ present: boolean }>; stages: Record<string, { ok: boolean; code?: string }>; fill: { minimalArabic: { ok: boolean } } } } {
  try {
    const stdout = execFileSync(process.execPath, [HARNESS, ROOT], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    return { status: 0, report: JSON.parse(stdout) };
  } catch (error) {
    const failure = error as { status?: number; stdout?: string };
    return { status: failure.status ?? -1, report: JSON.parse(failure.stdout ?? "{}") };
  }
}

test("R7C.1-B1: the harness reports PASS on a healthy artifact", { timeout: 180_000 }, () => {
  assert.ok(existsSync(FONT_DIR), "the font directory must exist for this environment to be meaningful");
  const { status, report } = diagnose();
  assert.equal(report.result, "PASS", `a healthy artifact must pass, saw ${report.result}`);
  assert.equal(status, 0);
  // The stage probes must all have run — a harness that skipped them would "pass" by
  // never asking the question the failure was about.
  for (const stage of ["font-resolve", "canvas-load", "font-register", "text-measure"]) {
    assert.equal(report.stages[stage]?.ok, true, `${stage} must succeed on a healthy artifact`);
  }
  // Arabic is the scenario that exercises raster appearance; a Latin-only pass would not
  // reproduce the failure that started this investigation.
  assert.equal(report.fill.minimalArabic.ok, true);
});

test("R7C.1-B2: with the font files absent the harness names the cause instead of the masked code", { timeout: 180_000 }, () => {
  assert.ok(existsSync(FONT_DIR), "the font directory must exist before it can be moved");
  renameSync(FONT_DIR, FONT_HIDDEN);
  try {
    const { status, report } = diagnose();
    assert.equal(status, 1, "a broken artifact must exit non-zero");
    assert.equal(report.result, "FAIL");
    // The distinguishing evidence: the *stage* reports the real error.
    assert.equal(report.stages["font-register"]?.ok, false);
    assert.equal(report.stages["font-register"]?.code, "FONT_UNAVAILABLE",
      "the harness must surface FONT_UNAVAILABLE, not the protocol's UNEXPECTED");
    // And the protocol-level result is still the masked one — which is the point.
    assert.equal(report.fill.minimalArabic.ok, false);
    assert.equal(report.fonts.every((font) => !font.present), true, "the font files must be reported missing");
  } finally {
    renameSync(FONT_HIDDEN, FONT_DIR);
  }
});

test("R7C.1-B3: the TMPDIR hypothesis is tested, not assumed", { timeout: 180_000 }, () => {
  // OpenCode suspected the minimal environment's missing TMPDIR. On glibc/x64 that is
  // falsifiable, so the harness runs both and this asserts the differential is present in
  // the report rather than silently omitted. If TMPDIR ever does matter, this comparison
  // is what shows it — the harness keeps asking the question after the answer changes.
  const { report } = diagnose();
  const withTmpdir = (report as unknown as { fill: { withTmpdirArabic: { ok: boolean } } }).fill.withTmpdirArabic;
  assert.ok(withTmpdir, "the harness must report the TMPDIR variant");
  assert.equal(withTmpdir.ok, true, "adding TMPDIR must not change behaviour on this platform");
});
