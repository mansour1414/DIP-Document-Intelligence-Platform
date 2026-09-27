import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import path from "node:path";
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

test("Stage 3C subprocess diagnostics fail closed and redact sensitive data", () => {
  const python = process.platform === "win32" ? "python" : "python3";
  const result = spawnSync(python, ["test/structural-grayscale-stage3c-subprocess.py"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  const diagnostics = `${result.stdout ?? ""}${result.stderr ?? ""}`;

  assert.equal(result.error, undefined, diagnostics || result.error?.message);
  assert.equal(result.status, 0, diagnostics);
  assert.match(diagnostics, /Ran 3 tests/u);
  assert.match(diagnostics, /OK/u);
});

test("Stage 3C evidence artifacts are sanitized and fail closed", () => {
  const python = process.platform === "win32" ? "python" : "python3";
  const result = spawnSync(python, ["test/structural-grayscale-stage3c-artifacts.py"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  const diagnostics = `${result.stdout ?? ""}${result.stderr ?? ""}`;

  assert.equal(result.error, undefined, diagnostics || result.error?.message);
  assert.equal(result.status, 0, diagnostics);
  assert.match(diagnostics, /Ran 6 tests/u);
  assert.match(diagnostics, /OK/u);
});

test("Stage 3C POSIX timeout probe preserves strict unset handling, cleanup, and exit status", () => {
  const shell = process.platform === "win32" ? "C:\\Program Files\\Git\\bin\\sh.exe" : "/bin/sh";
  assert.ok(existsSync(shell), `required POSIX shell is unavailable: ${shell}`);
  const script = fileURLToPath(
    new URL("../scripts/experiments/structural-grayscale-stage3c-timeout-probe.sh", import.meta.url),
  );
  const root = mkdtempSync(path.join(repoRoot, ".dip-stage3c-shell-"));
  const relativeRoot = path.basename(root);
  try {
    for (const [mode, expectedStatus] of [["success", 0], ["failure", 23]] as const) {
      const probe = path.join(root, mode);
      const result = spawnSync(shell, [script, `${relativeRoot}/${mode}`, mode], {
        cwd: repoRoot,
        encoding: "utf8",
      });
      assert.equal(result.status, expectedStatus, `${mode}: ${result.stderr}`);
      assert.equal(existsSync(probe), false, `${mode} probe was not cleaned`);
    }

    const unsetProbe = path.join(root, "unset");
    const environment = { ...process.env };
    delete environment.DIP_STAGE3C_INTENTIONALLY_UNSET;
    const unset = spawnSync(shell, [script, `${relativeRoot}/unset`, "unset"], {
      cwd: repoRoot,
      encoding: "utf8",
      env: environment,
    });
    assert.notEqual(unset.status, 0, unset.stderr);
    assert.match(unset.stderr, /DIP_STAGE3C_INTENTIONALLY_UNSET/u);
    assert.equal(existsSync(unsetProbe), false, "unset-variable probe was not cleaned");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("Stage 3C PDF.js runtime probe is real and browser-helper failures are sanitized", () => {
  const helper = fileURLToPath(
    new URL("../scripts/experiments/structural-grayscale-stage3a-browser.mjs", import.meta.url),
  );
  const success = spawnSync(process.execPath, [helper, "probe-pdfjs"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  assert.equal(success.status, 0, success.stderr);
  assert.deepEqual(JSON.parse(success.stdout), {
    operation: "pdfjs-runtime-probe",
    status: "passed",
    package: "pdfjs-dist",
    version: "6.3.289",
  });

  const secret = "STAGE3C_SECRET_MUST_NOT_LEAK";
  const failure = spawnSync(process.execPath, [helper, "probe-pdfjs"], {
    cwd: repoRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      DIP_STAGE3A_PDFJS_MODULE: "/missing/stage3c/pdfjs-dist/legacy/build/pdf.mjs",
      GROQ_API_KEY: secret,
    },
  });
  assert.notEqual(failure.status, 0);
  assert.equal(failure.stdout, "");
  assert.doesNotMatch(failure.stderr, new RegExp(secret, "u"));
  const diagnostic = JSON.parse(failure.stderr);
  assert.equal(diagnostic.operation, "pdfjs-runtime-probe");
  assert.equal(diagnostic.status, "failed");
  assert.equal(diagnostic.code, "ERR_MODULE_NOT_FOUND");
  assert.match(diagnostic.message, /Cannot find module '\[PDFJS_MODULE\]'/u);
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
  const stage3cJob = workflow.match(/structural-grayscale-stage3c:[\s\S]*?\n  browser-accessibility:/u)?.[0] ?? "";
  assert.doesNotMatch(stage3cJob, /Publish sanitized Stage 3C evidence[\s\S]*if: always\(\)/u);
  assert.match(stage3cJob, /Verify completed Stage 3C evidence before publication[\s\S]*if: success\(\)/u);
  assert.match(stage3cJob, /Publish validated Stage 3C evidence[\s\S]*if: success\(\)/u);
  assert.match(stage3cJob, /Prepare minimal Stage 3C failure diagnostic[\s\S]*if: failure\(\)/u);
  assert.match(stage3cJob, /Publish minimal Stage 3C failure diagnostic[\s\S]*if: failure\(\)/u);
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
  assert.match(derivative, /DIP_STAGE3A_PDFJS_MODULE=\/app\/node_modules\/pdfjs-dist\/legacy\/build\/pdf\.mjs/u);
  assert.match(runner, /probe-pdfjs[\s\\]+>\/output\/pdfjs-runtime\.json/u);
  assert.match(runner, /structural-grayscale-stage3c-timeout-probe\.sh "\$timeout_root"/u);
  assert.doesNotMatch(runner, /trap ['\\]+['\\]+rm -rf "\$probe"/u);
  assert.match(runner, /verify-structural-grayscale-stage3c-artifacts\.py "\$artifact_root"/u);
  assert.match(runner, /rm -rf "\$artifact_root" "\$failure_artifact_root"/u);
  assert.match(runner, /"\$failure_artifact_root\/ci-diagnostic\.json"/u);
  assert.match(production, /QPDF_DEBIAN_VERSION=11\.3\.0-1\+deb12u1/u);
});

test("Stage 3C command-line paths never print raw metrics or exception messages", () => {
  for (const source of [
    "../scripts/experiments/structural-grayscale-stage1.py",
    "../scripts/experiments/structural-grayscale-stage2.py",
    "../scripts/experiments/structural-grayscale-stage3a.py",
    "../scripts/experiments/structural-grayscale-stage3b.py",
    "../scripts/experiments/structural-grayscale-stage3c.py",
  ]) {
    const content = read(source);
    assert.doesNotMatch(content, /print\(json\.dumps\(asdict\(/u, source);
    assert.doesNotMatch(content, /print\(f["']\{type\(error\)\.__name__\}: \{error\}/u, source);
  }
});

test("Stage 3C evidence checks native inventory, SBOM, cleanup, and Ghostscript absence", () => {
  const probe = read("../scripts/experiments/structural-grayscale-stage3c-sandbox-probe.py");
  const runner = read("../scripts/experiments/run-structural-grayscale-stage3b-sandbox.sh");
  const audit = read("../scripts/experiments/structural-grayscale-stage3b-wheel-audit.py");
  const fixtureManifest = read("../scripts/experiments/structural-grayscale-stage3c-icc-fixture.json");
  const stage3a = read("../scripts/experiments/structural-grayscale-stage3a.py");
  const subprocessDiagnostics = read("../scripts/experiments/structural_grayscale_subprocess.py");

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
  assert.match(stage3a, /operation="pdfjs-text-extraction"/u);
  assert.match(subprocessDiagnostics, /"exit_status": result\.returncode/u);
  assert.match(subprocessDiagnostics, /"stderr": sanitize_stderr\(result\.stderr\)/u);
  assert.doesNotMatch(subprocessDiagnostics, /"arguments"/u);
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
