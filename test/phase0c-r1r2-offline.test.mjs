import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

/**
 * DIP Phase 0C — R1/R2 minimal ISOLATED OFFLINE PoC (Node runner).
 *
 * EXPERIMENTAL / ISOLATED. Runs the deterministic offline PoC (Python stdlib only)
 * and asserts governance + safety invariants. No live ClamAV, no network, no disk
 * writes: the PoC performs zero filesystem extraction. If `python3` is not
 * available in the environment, the tests skip HONESTLY (NOT_VERIFIED here),
 * consistent with the repo's gated-live-test convention.
 */

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const pocPath = path.join(root, "scripts", "experiments", "phase0c_r1r2_poc.py");
const designDocPath = path.join(
  root,
  "docs",
  "operations",
  "experimental",
  "phase0c-r1r2-offline-poc.md",
);

function pythonAvailable() {
  const probe = spawnSync("python3", ["--version"], { encoding: "utf8" });
  return probe.status === 0;
}

let pythonOk = false;
let reportPromise;

function loadReport() {
  if (!reportPromise) {
    reportPromise = (async () => {
      const run = spawnSync("python3", [pocPath, "report"], {
        cwd: root,
        encoding: "utf8",
        timeout: 120_000,
        maxBuffer: 64 * 1024 * 1024,
      });
      assert.equal(run.status, 0, `PoC report failed: ${run.stderr}`);
      return JSON.parse(run.stdout);
    })();
  }
  return reportPromise;
}

function guard(t) {
  if (!pythonOk) {
    t.skip("python3 not available in this environment; Phase 0C offline run is NOT_VERIFIED here");
  }
}

test("Phase 0C python3 runtime probe", (t) => {
  pythonOk = pythonAvailable();
  if (!pythonOk) {
    t.skip("python3 not available in this environment; NOT_VERIFIED here");
  }
});

test("Phase 0C offline self-test passes (suite + hard invariants)", async (t) => {
  guard(t);
  if (!pythonOk) return;
  const run = spawnSync("python3", [pocPath, "self-test"], {
    cwd: root,
    encoding: "utf8",
    timeout: 120_000,
    maxBuffer: 64 * 1024 * 1024,
  });
  assert.equal(run.status, 0, `self-test failed:\n${run.stdout}\n${run.stderr}`);
  assert.match(run.stdout, /SELF-TEST PASS: all invariants hold/u);
  assert.match(run.stdout, /all_verdicts_match\s+: True/u);
});

test("Phase 0C report: verdict taxonomy and coverage invariants", async (t) => {
  guard(t);
  if (!pythonOk) return;
  const report = await loadReport();

  assert.equal(report.mode, "OFFLINE_ONLY_ISOLATED_POC");
  assert.equal(report.run_kind, "DETERMINISTIC_OFFLINE_TESTS_ONLY");
  assert.equal(report.overall_conclusion, "NOT_COMPLETE_SAFE_SCAN");

  // Offline safety: no live scanner, no network, no subprocess, no disk writes.
  assert.equal(report.live_clamav_executed, false);
  assert.equal(report.network_calls, 0);
  assert.equal(report.subprocess_calls, 0);
  assert.equal(report.filesystem_extraction_writes, 0);

  // Verdicts: all expected verdicts match; COMPLETE_SAFE_SCAN is never claimed.
  assert.equal(report.summary.cases_total, 28);
  assert.equal(report.summary.all_verdicts_match, true);
  assert.equal(report.summary.complete_safe_scan_claimed, false);
  assert.deepEqual(report.summary.conclusions_observed, ["NOT_COMPLETE_SAFE_SCAN"]);
  for (const c of report.cases) {
    assert.equal(c.observed_verdict, c.expected_verdict, c.case_id);
    assert.equal(c.budget.filesystem_writes, 0, c.case_id);
    assert.equal(c.budget.temp_disk_bytes_used, 0, c.case_id);
    assert.equal(c.budget.full_extraction_materialized, false, c.case_id);
    assert.equal(c.conclusion.overall_conclusion, "NOT_COMPLETE_SAFE_SCAN", c.case_id);
  }

  // Independent controls.
  const byId = Object.fromEntries(report.cases.map((c) => [c.case_id, c]));
  assert.ok(
    byId["CTRL-POS-01"].objects.some((o) => o.offline_control_signature === "EICAR_SIGNATURE_PRESENT"),
    "EICAR positive control must fire",
  );
  for (const o of byId["CTRL-NEG-01"].objects) {
    assert.equal(o.offline_control_signature, "EICAR_SIGNATURE_ABSENT");
  }
  // CLEAN-looking nested control still never yields COMPLETE_SAFE_SCAN offline.
  for (const o of byId["CTRL-NEG-02"].objects.filter((o) => !o.skipped)) {
    assert.equal(o.verdict, "INSPECTED");
  }
});

test("Phase 0C report: governance preserved verbatim", async (t) => {
  guard(t);
  if (!pythonOk) return;
  const report = await loadReport();
  const gov = report.governance;
  for (const key of ["CLAMAV-CR-P01", "CLAMAV-CR-P02", "CLAMAV-CR-P03", "CLAMAV-CR-R1", "CLAMAV-CR-R2"]) {
    assert.equal(gov[key], "PROPOSED — NOT APPROVED", key);
  }
  assert.equal(gov.Security_Gate, "OPEN");
  assert.equal(gov.Licensing_Gate, "OPEN");
  assert.equal(gov.Stage_7, "NOT ACCEPTED");
  assert.equal(gov.CI, "NOT CHECKED");
  assert.equal(gov.R1, "OPEN");
  assert.equal(gov.R2, "OPEN");
  assert.equal(gov.production_source_or_dependency_changes, "NONE");
  assert.equal(gov.live_execution_workflow_created, false);

  const boundary = report.security_boundary;
  assert.equal(boundary.approved_sequence, "validateUpload -> requireCleanUpload -> storage.put");
  assert.equal(boundary.post_storage_worker_scan_satisfies_pre_storage, false);

  const caps = report.tool_capabilities;
  for (const key of [
    "qpdf_json_stream_inspection",
    "pdfjs_stream_inspection",
    "pdfdetach_attachment_parity",
    "genuine_encrypted_pdf_fixture",
    "clamav_live_scan",
  ]) {
    assert.equal(caps[key].verdict, "NOT_VERIFIED", key);
  }

  // R1/R2 must not claim complete remediation from partial coverage.
  assert.equal(report.r1.complete_r1_remediation_claimed, false);
  assert.equal(report.r2.complete_r2_remediation_claimed, false);

  // Single shared end-to-end budget, including the scanner feed.
  assert.equal(report.resource_budget.single_end_to_end_budget, true);
  assert.ok(report.resource_budget.shared_by.includes("scanner_feed"));
  assert.equal(report.resource_budget.streaming_proof.extraction_to_filesystem, false);
  assert.equal(report.resource_budget.streaming_proof.temp_disk_bytes_written, 0);
});

test("Phase 0C design document exists and states the required statuses", async (t) => {
  guard(t);
  if (!pythonOk) return;
  const { readFile } = await import("node:fs/promises");
  const doc = await readFile(designDocPath, "utf8");
  assert.match(doc, /CI: NOT CHECKED\. Security Gate: OPEN\. Licensing Gate: OPEN\. Stage 7: NOT ACCEPTED\. R1\/R2: OPEN\./u);
  assert.match(doc, /PROPOSED — NOT APPROVED/u);
  assert.match(doc, /post-storage worker scan does NOT satisfy/u);
  assert.match(doc, /NOT claim complete R1 remediation|does NOT claim complete R1 remediation/iu);
});
