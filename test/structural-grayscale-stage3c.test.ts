import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

const read = (path: string) => readFileSync(new URL(path, import.meta.url), "utf8");
const repoRoot = fileURLToPath(new URL("../", import.meta.url));

test("Stage 3C read-only-root probe fails closed without invalid cleanup", () => {
  const python = process.platform === "win32" ? "python" : "python3";
  const result = spawnSync(python, ["test/structural-grayscale-stage3c-root-probe.py"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  const diagnostics = `${result.stdout ?? ""}${result.stderr ?? ""}`;

  assert.equal(result.error, undefined, diagnostics || result.error?.message);
  assert.equal(result.status, 0, diagnostics);
  assert.match(diagnostics, /Ran 3 tests/u);
  assert.match(diagnostics, /OK/u);
});

test("Stage 3C reviewed ICC fixture provisioning is pinned and fail-closed", () => {
  const python = process.platform === "win32" ? "python" : "python3";
  const result = spawnSync(python, ["test/structural-grayscale-stage3c-icc-fixture.py"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  const diagnostics = `${result.stdout ?? ""}${result.stderr ?? ""}`;

  assert.equal(result.error, undefined, diagnostics || result.error?.message);
  assert.equal(result.status, 0, diagnostics);
  assert.match(diagnostics, /Ran 3 tests/u);
  assert.match(diagnostics, /OK/u);
});

test("Stage 3C CI is isolated, fail-closed, and preserves the production worker", () => {
  const workflow = read("../.github/workflows/ci.yml");
  const runner = read("../scripts/experiments/run-structural-grayscale-stage3b-sandbox.sh");
  const derivative = read("../scripts/experiments/Dockerfile.structural-grayscale-stage3b");
  const production = read("../Dockerfile.worker");

  assert.match(workflow, /structural-grayscale-stage3c:/u);
  assert.match(workflow, /Execute fail-closed Stage 3C production-sandbox gate/u);
  assert.match(workflow, /generate-stage3c-widgets/u);
  assert.match(workflow, /Provision and verify reviewed CMYK ICC fixture/u);
  assert.match(workflow, /structural-grayscale-stage3c-widgets[^\n]+wc -l\)" -eq 8/u);
  assert.doesNotMatch(workflow, /structural-grayscale-stage3c:[\s\S]*continue-on-error:/u);
  assert.match(runner, /docker build --file Dockerfile\.worker/u);
  for (const required of [
    "--user 10001:10001",
    "--network none",
    "--read-only",
    "--security-opt no-new-privileges",
    "--cap-drop ALL",
    "--cpus 1",
    "--memory 768m",
    "--pids-limit 128",
    "--tmpfs /tmp:",
    "--tmpfs /tmp/dip:",
  ]) assert.ok(runner.includes(required), `missing sandbox constraint: ${required}`);
  assert.match(runner, /test -z "\$\(find \/output -type f -name "\*\.pdf"/u);
  assert.match(runner, /sha256sum "\$DIP_STAGE3A_CMYK_ICC_PROFILE"/u);
  assert.match(runner, /73e1ba37d2bad5bab2a964f40a9eed96209666efc067c3322626214bbef234a0/u);
  assert.match(derivative, /FROM dip-document-worker:stage3b-base/u);
  assert.match(derivative, /--no-index --find-links=\/wheels/u);
  assert.match(derivative, /DIP_STAGE3A_CMYK_ICC_PROFILE=\/stage3b\/fixtures\/CGATS001Compat-v2-micro\.icc/u);
  assert.match(production, /QPDF_DEBIAN_VERSION=11\.3\.0-1\+deb12u1/u);
});

test("Stage 3C evidence checks native inventory, SBOM, cleanup, and Ghostscript absence", () => {
  const probe = read("../scripts/experiments/structural-grayscale-stage3c-sandbox-probe.py");
  const runner = read("../scripts/experiments/run-structural-grayscale-stage3b-sandbox.sh");
  const audit = read("../scripts/experiments/structural-grayscale-stage3b-wheel-audit.py");
  const fixtureManifest = read("../scripts/experiments/structural-grayscale-stage3c-icc-fixture.json");
  const stage3a = read("../scripts/experiments/structural-grayscale-stage3a.py");

  assert.match(probe, /EXPECTED_QPDF_PACKAGE = "11\.3\.0-1\+deb12u1"/u);
  assert.match(probe, /EXPECTED_EMBEDDED_LIBQPDF = "12\.3\.2"/u);
  assert.match(probe, /EXPECTED_LITTLECMS_RUNTIME = "2\.19"/u);
  assert.match(probe, /libimagequant must be disabled/u);
  assert.match(probe, /Ghostscript is present/u);
  assert.match(runner, /failure-cleanup\.json/u);
  assert.match(runner, /timeout-cleanup\.json/u);
  assert.match(runner, /test ! -e "\$failure_root\/unexpected-output\.pdf"/u);
  assert.match(audit, /supplemental-sbom\.cdx\.json/u);
  assert.match(audit, /wheel-manifest\.json/u);
  assert.match(audit, /365b94f2be7e2857c6cb5445b56dc52dc7417ba9f06c8a4282d9f521cb2d0fb8/u);
  assert.match(audit, /23d27a3e0307ec2244cc51e7287b919aa68d097504ebe19df4e76a98a3eea5bd/u);
  assert.match(fixtureManifest, /73e1ba37d2bad5bab2a964f40a9eed96209666efc067c3322626214bbef234a0/u);
  assert.match(fixtureManifest, /"license": "CC0-1\.0"/u);
  assert.match(stage3a, /reviewed_cmyk_icc_profile/u);
  assert.match(stage3a, /reviewed CMYK ICC fixture profile checksum is invalid/u);
  assert.match(stage3a, /ImageCms\.ImageCmsProfile/u);
});

test("Stage 2 rejects malformed page Contents without partial-output fallbacks", () => {
  const stage2 = read("../scripts/experiments/structural-grayscale-stage2.py");

  assert.match(stage2, /def page_content_streams\(/u);
  assert.match(stage2, /page Contents entry \{index\} is not a stream/u);
  assert.match(stage2, /for page in pdf\.pages:\n\s+page_content_streams\(page\.obj\)/u);
  assert.match(stage2, /STAGE2_STRUCTURAL_TRANSFORMER = StructuralTransformer/u);
  assert.match(stage2, /was not rejected by explicit page Contents validation/u);
  assert.match(stage2, /Run Stage 2 with its baseline policy even when Stage 3A is also loaded/u);
  for (const fixture of [
    "null-page-contents",
    "malformed-page-contents",
    "mixed-page-contents",
  ]) assert.ok(stage2.includes(fixture), `missing malformed Contents regression: ${fixture}`);
  assert.doesNotMatch(
    stage2,
    /pikepdf\.Array\(\[page\.obj\["\/Contents"\], pdf\.make_stream/u,
  );
});

test("Stage 3C remains an experiment and Grayscale is not registered", () => {
  const registry = read("../src/lib/tools/registry.ts");
  const stage3c = read("../scripts/experiments/structural-grayscale-stage3c.py");
  const browserFixture = read("../scripts/experiments/structural-grayscale-stage3a-browser.mjs");

  assert.doesNotMatch(registry, /["']grayscale-pdf["']/u);
  assert.match(stage3c, /not a production converter/u);
  assert.match(stage3c, /--self-test/u);
  assert.match(stage3c, /timeout_killed_safe_rejections/u);
  assert.match(stage3c, /partial_outputs/u);
  assert.match(stage3c, /DIP_STAGE3C_WIDGET_FIXTURE_DIR/u);
  assert.match(stage3c, /independent Chromium widget fixtures are required/u);
  assert.match(browserFixture, /generateStage3cWidgets/u);
  assert.match(browserFixture, /"Noto Sans Arabic"/u);
});
