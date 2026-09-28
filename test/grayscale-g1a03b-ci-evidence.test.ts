import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const text = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const workflow = text(".github/workflows/g1a03b-candidate-evidence.yml");
const runner = text("scripts/experiments/build-structural-grayscale-g1a03-candidate.sh");
const report = text("docs/g1a-03b-ci-candidate-evidence-and-security-triage.md");
const triage = JSON.parse(text("docs/evidence/g1a03b/pypdf-6.10.0-security-triage.json"));
const nodeCollector = new URL("../scripts/experiments/collect-node-inventory-g1a03b.mjs", import.meta.url);

test("G1-A/03B is a dispatchable and path-filtered isolated ubuntu-24.04 evidence workflow", () => {
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /pull_request:/);
  assert.match(workflow, /paths:/);
  assert.match(workflow, /runs-on: ubuntu-24\.04/);
  assert.match(workflow, /contents: read/);
  assert.doesNotMatch(workflow, /\bpush:\s*\n|docker\s+push|deployment|environment:\s*production/i);
});

test("base image and scanner artifacts are immutable and checksum pinned", () => {
  assert.match(workflow, /node:22\.20\.0-bookworm-slim@sha256:b21fe589dfbe5cc39365d0544b9be3f1f33f55f3c86c87a76ff65a02f8f5848e/);
  assert.match(workflow, /SYFT_VERSION: 1\.52\.0/);
  assert.match(workflow, /caeedb81fb0491615f1ebd1761e4145d41ee86dd2cc7bf80669f9f5ad9d6133d/);
  assert.match(workflow, /GRYPE_VERSION: 0\.119\.0/);
  assert.match(workflow, /3fa2dc4b924621ab65404cf08d0b8438d896d80ab949c9d5a4ca283c36004c9b/);
  assert.match(workflow, /sha256sum --check --strict/g);
});

test("candidate evidence includes inventories, SBOMs, scan, notices, and reconciliation", () => {
  for (const marker of ["debian-packages.tsv", "python-packages.json", "node-packages.json", "python-native-sha256.txt", "debian-notices-sha256.txt", "candidate-image.spdx.json", "candidate-image.cdx.json", "vulnerability-scan.grype.json", "reconciliation.json"])
    assert.match(runner, new RegExp(marker.replaceAll(".", "\\.")));
  assert.match(workflow, /actions\/upload-artifact@v4/);
});

test("Node inventory retains missing names and nested packages deterministically", (context) => {
  const fixture = mkdtempSync(path.join(tmpdir(), "dip-g1a03b-node-inventory-"));
  context.after(() => rmSync(fixture, { recursive: true, force: true }));
  const modules = path.join(fixture, "node_modules");
  const noManifest = path.join(modules, "no-manifest");
  const unnamed = path.join(modules, "unnamed-package");
  const parent = path.join(modules, "parent-package");
  const nested = path.join(parent, "node_modules", "nested-package");
  mkdirSync(noManifest, { recursive: true });
  mkdirSync(unnamed, { recursive: true });
  mkdirSync(nested, { recursive: true });
  writeFileSync(path.join(unnamed, "package.json"), JSON.stringify({ version: "1.0.0", license: "MIT" }));
  writeFileSync(path.join(parent, "package.json"), JSON.stringify({ name: "parent-package", version: "2.0.0" }));
  writeFileSync(path.join(nested, "package.json"), JSON.stringify({ name: "nested-package", version: "3.0.0" }));

  const run = () => spawnSync(process.execPath, [fileURLToPath(nodeCollector), modules], { encoding: "utf8" });
  const first = run();
  const second = run();
  assert.equal(first.status, 0, first.stderr);
  assert.equal(second.status, 0, second.stderr);
  assert.equal(first.stdout, second.stdout);
  const inventory = JSON.parse(first.stdout);
  assert.deepEqual(inventory.map((item: { path: string }) => item.path), [
    "node_modules/no-manifest",
    "node_modules/parent-package",
    "node_modules/parent-package/node_modules/nested-package",
    "node_modules/unnamed-package",
  ]);
  assert.equal(inventory[0].status, "MISSING_METADATA");
  assert.deepEqual(inventory[0].missing_fields, ["package.json"]);
  assert.equal(inventory[0].diagnostic, "MISSING_OR_UNREADABLE_PACKAGE_JSON");
  const unnamedRecord = inventory.at(-1);
  assert.equal(unnamedRecord.name, null);
  assert.equal(unnamedRecord.status, "MISSING_METADATA");
  assert.deepEqual(unnamedRecord.missing_fields, ["name"]);
  assert.equal(inventory[2].name, "nested-package");
  assert.equal(inventory[2].status, "COMPLETE");
});

test("reconciliation fails closed for incomplete Node metadata", () => {
  const reconciliation = text("scripts/experiments/verify-structural-grayscale-g1a03b-evidence.py");
  assert.match(reconciliation, /node_metadata_gaps/);
  assert.match(reconciliation, /not node_metadata_gaps/);
  assert.match(reconciliation, /EMPTY_OR_INVALID_NODE_INVENTORY/);
});

test("pypdf aliases are deduplicated and reachability is not overstated", () => {
  assert.equal(triage.raw_identifier_count, 45);
  assert.equal(triage.unique_advisory_count, 23);
  assert.equal(triage.advisories.length, 23);
  assert.equal(new Set(triage.advisories.map((item: { ghsa: string }) => item.ghsa)).size, 23);
  assert.deepEqual(triage.counts_by_reachability, { REACHABLE: 10, CONDITIONAL: 11, NOT_REACHED_BY_CURRENT_CALL: 2 });
  assert.deepEqual(triage.severity_counts, { HIGH: 2, MODERATE: 21 });
  assert.equal(triage.decision, "FAIL_PENDING_SECURITY_REVIEW");
});

test("03B preserves image identity, licensing, and product boundaries", () => {
  assert.match(report, /Licensing Gate OPEN — NOT APPROVED/);
  assert.match(report, /no Grayscale engine implementation or dispatch/);
  assert.match(report, /registry OCI digest remains \*\*NOT VERIFIED\*\*/);
  assert.match(report, /evidence gap, not a confirmed license violation/i);
  assert.doesNotMatch(workflow, /grayscale-pdf|src\/lib\/tools\/registry|workers\/document-worker/);
});
