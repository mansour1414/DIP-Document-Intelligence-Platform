import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const WORKFLOW = readFileSync(
  new URL("../.github/workflows/clamav-stage7-private-ghcr.yml", import.meta.url),
  "utf8",
);

const EVIDENCE_STEP = "Generate digest-bound SPDX, CycloneDX, and CVE evidence";
const COLLECT_STEP = "Collect transitive license, notices, and runtime linkage evidence";

// Credential-shaped strings used only to prove the harness never re-emits them.
// Deliberately synthetic (fails GitHub token checksum) so no real credential shape ships.
const FAKE_GITHUB_TOKEN = `ghp_${"0".repeat(36)}`;
const FAKE_BEARER = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkaXAifQ.c2lnbmF0dXJl";
const FAKE_BASIC = "dXNlcjpwYXNzd29yZA==";

function stepBlock(name) {
  const lines = WORKFLOW.split(/\r?\n/u);
  const start = lines.findIndex((line) => line === `      - name: ${name}`);
  assert.notEqual(start, -1, `workflow must define step: ${name}`);
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    if (/^ {6}- name: /u.test(lines[index]) || /^\S/u.test(lines[index])) {
      end = index;
      break;
    }
  }
  return lines.slice(start, end).join("\n");
}

function envValue(block, key) {
  const match = block.match(new RegExp(`^\\s+${key}: (.+)$`, "mu"));
  assert.ok(match, `step must define ${key}`);
  return match[1].trim();
}

function shellQuote(value) {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

const SCAN_STEP = stepBlock(EVIDENCE_STEP);
const COLLECT = stepBlock(COLLECT_STEP);

// The diagnostic harness is executed verbatim: the test drives the real bash
// functions from the workflow instead of a re-implementation of them.
const scanLines = SCAN_STEP.split(/\r?\n/u);
const harnessStart = scanLines.findIndex((line) => line.includes('scanner_diagnostics="$(mktemp'));
const harnessEnd = scanLines.findIndex((line) =>
  line.includes('run_scanner syft "$scanner_diagnostics/syft.stderr.log"'));
assert.ok(harnessStart > -1 && harnessEnd > harnessStart, "diagnostic harness must be extractable");
const HARNESS = scanLines
  .slice(harnessStart, harnessEnd)
  .map((line) => line.replace(/^ {10}/u, ""))
  .join("\n")
  .replace(/\n+$/u, "");

function driveHarness(scannerScript) {
  const evidenceDir = mkdtempSync(join(tmpdir(), "dip-stage7-evidence-"));
  const runnerTemp = mkdtempSync(join(tmpdir(), "dip-stage7-runner-"));
  const driverPath = join(runnerTemp, "driver.sh");
  const driver = [
    "set -euo pipefail",
    HARNESS,
    'echo "DIAG_DIR=$scanner_diagnostics"',
    `run_scanner syft "$scanner_diagnostics/syft.stderr.log" bash -c ${shellQuote(scannerScript)}`,
    'echo "UNREACHABLE_AFTER_SCANNER_FAILURE"',
    "",
  ].join("\n");
  writeFileSync(driverPath, driver, { mode: 0o700 });
  const result = spawnSync("bash", [driverPath], {
    encoding: "utf8",
    env: { ...process.env, EVIDENCE_DIR: evidenceDir, RUNNER_TEMP: runnerTemp },
  });
  const output = `${result.stdout}${result.stderr}`;
  const diagDir = output.match(/^DIAG_DIR=(.+)$/mu)?.[1]?.trim() ?? null;
  const evidenceFiles = readdirSync(evidenceDir, { withFileTypes: true }).map((entry) => ({
    name: entry.name,
    isFile: entry.isFile(),
    content: entry.isFile() ? readFileSync(join(evidenceDir, entry.name), "utf8") : "",
  }));
  return { result, output, diagDir, evidenceDir, runnerTemp, evidenceFiles };
}

function cleanup(context) {
  rmSync(context.evidenceDir, { recursive: true, force: true });
  rmSync(context.runnerTemp, { recursive: true, force: true });
}

function assertNoCredentialLeak(text, label) {
  for (const [name, value] of [
    ["GitHub classic token", FAKE_GITHUB_TOKEN],
    ["Bearer JWT", FAKE_BEARER],
    ["Basic payload", FAKE_BASIC],
  ]) {
    assert.equal(text.includes(value), false, `${label} must not expose the ${name}`);
  }
  assert.doesNotMatch(text, /gh[pousr]_[A-Za-z0-9]{16,}/u, `${label} must not expose GitHub token shapes`);
  assert.doesNotMatch(text, /Bearer\s+[A-Za-z0-9._~+/=-]{8,}/u, `${label} must not expose bearer values`);
  assert.doesNotMatch(text, /Basic\s+[A-Za-z0-9._~+/=-]{8,}/u, `${label} must not expose basic values`);
}

test("Stage 7 scans the immutable registry digest on the built ARM64 platform", () => {
  assert.match(SCAN_STEP, /syft "registry:\$IMAGE_BY_DIGEST"/u);
  assert.match(SCAN_STEP, /grype "registry:\$IMAGE_BY_DIGEST"/u);
  assert.match(
    SCAN_STEP,
    /syft "registry:\$IMAGE_BY_DIGEST" --source-name "\$IMAGE_BY_DIGEST" \\\r?\n\s+--platform linux\/arm64 \\\r?\n/u,
  );
  assert.match(
    SCAN_STEP,
    /grype "registry:\$IMAGE_BY_DIGEST" --platform linux\/arm64 -o json \\\r?\n/u,
  );
  assert.doesNotMatch(SCAN_STEP, /registry:\$IMAGE_NAME/u);
  assert.doesNotMatch(SCAN_STEP, /:latest|\$\{\{\s*env\.(?:CANDIDATE_TAG|RUN_TAG)/u);
});

test("Stage 7 supplies explicit GHCR credentials to both scanners from GITHUB_TOKEN", () => {
  for (const tool of ["SYFT", "GRYPE"]) {
    assert.equal(envValue(SCAN_STEP, `${tool}_REGISTRY_AUTH_AUTHORITY`), "ghcr.io");
    assert.equal(envValue(SCAN_STEP, `${tool}_REGISTRY_AUTH_USERNAME`), "${{ github.actor }}");
    assert.equal(
      envValue(SCAN_STEP, `${tool}_REGISTRY_AUTH_PASSWORD`),
      "${{ secrets.GITHUB_TOKEN }}",
    );
  }
});

test("Stage 7 never echoes or inlines scanner credentials", () => {
  const credentialLines = SCAN_STEP.split(/\r?\n/u)
    .filter((line) => /_REGISTRY_AUTH_PASSWORD/u.test(line));
  assert.equal(credentialLines.length, 2, "only the two env assignments may mention the password");
  for (const line of credentialLines) {
    assert.match(line, /^\s+(?:SYFT|GRYPE)_REGISTRY_AUTH_PASSWORD: \$\{\{ secrets\.GITHUB_TOKEN \}\}$/u);
  }
  assert.doesNotMatch(SCAN_STEP, /\bset -x\b/u);
  assert.doesNotMatch(SCAN_STEP, /^(?:\s+)(?:echo|printf).*(?:PASSWORD|_AUTH_)/mu);
  assert.doesNotMatch(SCAN_STEP, /--password[= ]/u);
});

test("Stage 7 keeps raw scanner stderr outside the uploaded evidence directory", () => {
  assert.match(SCAN_STEP, /mktemp -d "\$\{RUNNER_TEMP\}\/stage7-scanner-diagnostics\.XXXXXX"/u);
  assert.match(SCAN_STEP, /chmod 0700 "\$scanner_diagnostics"/u);
  assert.match(SCAN_STEP, /trap cleanup_scanner_diagnostics EXIT/u);
  assert.match(SCAN_STEP, /rm -rf "\$scanner_diagnostics"/u);
  assert.match(
    SCAN_STEP,
    /case "\$scanner_diagnostics" in\s*\r?\n\s+"\$EVIDENCE_DIR"\/\*\)/u,
  );

  // No stderr log may ever be written under the evidence directory.
  assert.doesNotMatch(SCAN_STEP, /\$EVIDENCE_DIR\/[A-Za-z0-9_.-]*stderr/u);
  assert.doesNotMatch(SCAN_STEP, /\$EVIDENCE_DIR\/[A-Za-z0-9_.-]*\.log/u);
  assert.doesNotMatch(SCAN_STEP, /mktemp[^\n]*EVIDENCE_DIR/u);
  assert.doesNotMatch(SCAN_STEP, /(?:tee|cp|mv)\s+[^\n]*\$EVIDENCE_DIR/u);

  // Raw bytes are never replayed: only classification metadata is printed.
  assert.doesNotMatch(SCAN_STEP, /SCANNER_DIAGNOSTIC_RAW=(?!withheld)/u);
  assert.match(SCAN_STEP, /SCANNER_DIAGNOSTIC_RAW=withheld/u);
  assert.doesNotMatch(SCAN_STEP, /^(?:\s+)(?:cat|sed|awk|tail|head)\b[^\n]*"\$log"/mu);
  assert.doesNotMatch(SCAN_STEP, /grep -[A-Za-z]*[ov][A-Za-z]*\s[^\n]*"\$log"/u);
});

test("Stage 7 classifies authentication and platform failures distinguishably", () => {
  assert.match(SCAN_STEP, /classification=platform_resolution_failed/u);
  assert.match(SCAN_STEP, /classification=registry_authentication_failed/u);
  assert.match(SCAN_STEP, /classification=transport_failed/u);
  assert.match(SCAN_STEP, /classification=\$\{classification\}/u);
  assert.match(SCAN_STEP, /local classification=unclassified/u);
  assert.match(SCAN_STEP, /grep -qiE 'no child with platform/u);
});

test("Stage 7 keeps the digest-bound evidence file contract consumed by later steps", () => {
  assert.match(SCAN_STEP, /spdx-json=\$EVIDENCE_DIR\/stage7\.spdx\.json/u);
  assert.match(SCAN_STEP, /cyclonedx-json=\$EVIDENCE_DIR\/stage7\.cdx\.json/u);
  assert.match(SCAN_STEP, /--file "\$EVIDENCE_DIR\/stage7\.grype\.json"/u);

  const classify = stepBlock("Classify every Stage 7 finding without blanket VEX");
  assert.match(classify, /GRYPE_PATH="\$EVIDENCE_DIR\/stage7\.grype\.json"/u);
  assert.match(classify, /OUTPUT_PREFIX=stage7/u);

  const provenance = stepBlock("Bind scanner and registry provenance to the evidence set");
  assert.match(provenance, /stage7\.spdx\.json/u);
  assert.match(provenance, /stage7\.cdx\.json/u);
  assert.match(provenance, /stage7\.grype\.json/u);
});

test("Stage 7 keeps every scan invariant fail-closed", () => {
  assert.match(SCAN_STEP, /test -s "\$EVIDENCE_DIR\/stage7\.spdx\.json"/u);
  assert.match(SCAN_STEP, /test -s "\$EVIDENCE_DIR\/stage7\.cdx\.json"/u);
  assert.match(SCAN_STEP, /test -s "\$EVIDENCE_DIR\/stage7\.grype\.json"/u);
  assert.match(SCAN_STEP, /jq '\.ignoredMatches \| length'/u);
  assert.match(SCAN_STEP, /\)" = 0$/mu);
  assert.match(SCAN_STEP, /jq -e '\.descriptor\.db\.status\.valid == true'/u);
  assert.match(SCAN_STEP, /set -euo pipefail/u);
  assert.match(SCAN_STEP, /return 1/u);
  assert.doesNotMatch(SCAN_STEP, /\|\|\s*true/u);

  const evidenceDir = WORKFLOW.match(/^\s+EVIDENCE_DIR: (.+)$/mu);
  assert.ok(evidenceDir, "workflow must keep EVIDENCE_DIR");
  assert.equal(evidenceDir[1].trim(), "${{ github.workspace }}/output/clamav-stage7");
});

test("Stage 7 pins the ARM64 platform for transitive licensing evidence collection", () => {
  assert.equal(envValue(COLLECT, "DOCKER_DEFAULT_PLATFORM"), "linux/arm64");
  assert.match(COLLECT, /collect-clamav-stage6-evidence\.sh/u);
});

test("Stage 7 keeps the reviewed scanner supply chain and manual-only boundary", () => {
  const triggerBlock = WORKFLOW.slice(WORKFLOW.indexOf("on:"), WORKFLOW.indexOf("\npermissions:"));
  assert.match(triggerBlock, /^on:\r?\n  workflow_dispatch:/u);
  assert.doesNotMatch(triggerBlock, /^ {2}(?:push|pull_request|schedule|workflow_run):/mu);

  const referencedSecrets = [...WORKFLOW.matchAll(/secrets\.([A-Z0-9_]+)/gu)]
    .map((match) => match[1]);
  assert.deepEqual([...new Set(referencedSecrets)], ["GITHUB_TOKEN"]);

  assert.match(WORKFLOW, /^\s+SYFT_VERSION: 1\.52\.0$/mu);
  assert.match(WORKFLOW, /^\s+GRYPE_VERSION: 0\.119\.0$/mu);
  assert.match(WORKFLOW, /^\s+SYFT_LINUX_AMD64_SHA256: [0-9a-f]{64}$/mu);
  assert.match(WORKFLOW, /^\s+GRYPE_LINUX_AMD64_SHA256: [0-9a-f]{64}$/mu);
  assert.match(WORKFLOW, /docker pull --platform linux\/arm64 "\$IMAGE_BY_DIGEST"/u);
  assert.match(WORKFLOW, /^\s{2}packages: write$/mu);
  assert.match(WORKFLOW, /^\s{2}contents: read$/mu);
});

test("harness: a successful scanner leaves no diagnostic residue in evidence", () => {
  const context = driveHarness("exit 0");
  try {
    assert.equal(context.result.status, 0, "successful scanner must not fail the step");
    assert.equal(context.diagDir !== null, true, "diagnostic directory must be reported");
    assert.equal(existsSync(context.diagDir), false, "diagnostic directory must be removed on success");
    assert.equal(context.evidenceFiles.length, 0, "evidence directory must stay untouched");
    assert.doesNotMatch(context.output, /SCANNER_DIAGNOSTIC=/u);
    assertNoCredentialLeak(context.output, "console output");
  } finally {
    cleanup(context);
  }
});

test("harness: credentials on scanner stderr never reach console or evidence", () => {
  const stderrPayload = [
    `error: GET https://ghcr.io/v2/mansour1414/dip-clamav/manifests/sha256:abc: UNAUTHORIZED: authentication required`,
    `token=${FAKE_GITHUB_TOKEN}`,
    `Authorization: Bearer ${FAKE_BEARER}`,
    `Authorization: Basic ${FAKE_BASIC}`,
  ].join("\\n");
  const context = driveHarness(`printf '%s\\n' "${stderrPayload}" >&2; exit 1`);
  try {
    assert.notEqual(context.result.status, 0, "a failed scanner must fail the step");
    assert.equal(context.output.includes("UNREACHABLE_AFTER_SCANNER_FAILURE"), false);
    assertNoCredentialLeak(context.output, "console output");
    for (const entry of context.evidenceFiles) {
      assert.equal(entry.isFile, true, `evidence entry ${entry.name} must not be a directory`);
      assertNoCredentialLeak(entry.content, `evidence file ${entry.name}`);
    }
    assert.equal(context.evidenceFiles.length, 0, "no diagnostic file may be copied into evidence");
    assert.equal(existsSync(context.diagDir), false, "diagnostic directory must be removed on failure");
  } finally {
    cleanup(context);
  }
});

test("harness: authentication and platform failures stay distinguishable", () => {
  const authentication = driveHarness(
    "printf 'UNAUTHORIZED: authentication required for ghcr.io\\n' >&2; exit 1",
  );
  const platform = driveHarness(
    "printf 'no child with platform linux/amd64 in index ghcr.io/x@sha256:abc\\n' >&2; exit 1",
  );
  try {
    assert.match(authentication.output, /classification=registry_authentication_failed/u);
    assert.match(platform.output, /classification=platform_resolution_failed/u);
    assert.notEqual(
      authentication.output.match(/classification=(\S+)/u)?.[1],
      platform.output.match(/classification=(\S+)/u)?.[1],
      "authentication and platform failures must not collapse into one class",
    );
    for (const context of [authentication, platform]) {
      assert.notEqual(context.result.status, 0);
      assert.match(context.output, /SCANNER_DIAGNOSTIC_RAW=withheld/u);
      assert.match(context.output, /SCANNER_DIAGNOSTIC_HINT=/u);
      assert.equal(existsSync(context.diagDir), false);
    }
  } finally {
    cleanup(authentication);
    cleanup(platform);
  }
});

test("harness: an unclassified failure still fails closed without echoing stderr", () => {
  const context = driveHarness("printf 'something odd happened\\n' >&2; exit 7");
  try {
    assert.notEqual(context.result.status, 0);
    assert.match(context.output, /classification=unclassified/u);
    assert.equal(context.output.includes("something odd happened"), false);
    assertNoCredentialLeak(context.output, "console output");
  } finally {
    cleanup(context);
  }
});
