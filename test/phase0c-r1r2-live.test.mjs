import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const workflow = await readFile(new URL("../.github/workflows/clamav-phase0c-live-evidence.yml", import.meta.url), "utf8");
const dockerfile = await readFile(new URL("../docs/operations/experimental/clamav-phase0c-client.Dockerfile", import.meta.url), "utf8");
const liveScript = await readFile(new URL("../scripts/experiments/phase0c_r1r2_live_evidence.py", import.meta.url), "utf8");

test("Phase 0C live workflow is manual-only, main-bound, read-only, and pinned", () => {
  assert.match(workflow, /workflow_dispatch:/u);
  assert.doesNotMatch(workflow, /^\s*(?:push|pull_request|schedule):/mu);
  assert.match(workflow, /github\.repository == 'mansour1414\/DIP-Document-Intelligence-Platform'/u);
  assert.match(workflow, /github\.ref == 'refs\/heads\/main'/u);
  assert.match(workflow, /run-phase0c-r1r2-isolated-live-evidence/u);
  assert.match(workflow, /permissions:\s*\n\s+contents: read/u);
  assert.match(workflow, /persist-credentials: false/u);
  assert.match(workflow, /runs-on: ubuntu-24\.04-arm/u);
  const uses = [...workflow.matchAll(/^\s+uses:\s+([^\s]+)\s+#/gmu)].map((match) => match[1]);
  assert.ok(uses.length >= 3);
  for (const action of uses) assert.match(action, /@[0-9a-f]{40}$/u);
  assert.doesNotMatch(workflow, /docker\s+(?:login|push)|ghcr\.io\//iu);
  assert.doesNotMatch(workflow, /production\s+secrets|deploy\s+to\s+production/iu);
});

test("both runtime containers use the internal network and OS resource controls", () => {
  assert.match(workflow, /docker network create --internal/u);
  assert.match(workflow, /--network "\$PHASE0C_NETWORK"/gu);
  assert.match(workflow, /--read-only/u);
  assert.match(workflow, /--cap-drop ALL/u);
  assert.match(workflow, /--security-opt no-new-privileges:true/u);
  assert.match(workflow, /--memory 3g --memory-swap 3g/u);
  assert.match(workflow, /--cpus 2 --pids-limit 128/u);
  assert.match(workflow, /--memory 512m --memory-swap 512m --cpus 1 --pids-limit 64/u);
  assert.match(workflow, /--ulimit cpu=1800:1800/u);
  assert.match(workflow, /--ulimit cpu=120:120/u);
  assert.match(workflow, /--signal=TERM --kill-after=5s 1800s/u);
  assert.match(workflow, /--signal=TERM --kill-after=5s 1200s/u);
  assert.match(workflow, /--tmpfs \/tmp:rw,noexec,nosuid,nodev/u);
  assert.match(workflow, /PortBindings/u);
  assert.match(workflow, /cleanup-status\.json/u);
  assert.match(workflow, /retention-days: 30/u);
  assert.match(workflow, /5242880/u);
});

test("client image is experimental, pinned to immutable base, non-root, and manifest-recorded", () => {
  assert.match(dockerfile, /ubuntu:22\.04@sha256:[0-9a-f]{64}/u);
  assert.match(dockerfile, /python3-minimal libpython3\.10-stdlib/u);
  assert.match(dockerfile, /dpkg-manifest\.txt/u);
  assert.match(dockerfile, /licenses\/\$pkg\/copyright/u);
  assert.match(workflow, /CLIENT_IMAGE_IMPORT_SMOKE_PASS/u);
  assert.match(workflow, /docker run --rm --platform linux\/arm64 --read-only/u);
  assert.match(dockerfile, /USER 10001:10001/u);
  assert.match(dockerfile, /not production/iu);
});

test("live adapter preserves independent case, coverage, original, and extracted fields", () => {
  assert.match(liveScript, /parser\.add_argument\("--mode", required=True/u);
  assert.match(liveScript, /choices=\("live", "finalize"\)/u);
  assert.match(liveScript, /"TEST_CASE_RESULT"/u);
  assert.match(liveScript, /"SECURITY_COVERAGE_STATUS"/u);
  assert.match(liveScript, /"ORIGINAL_CONTAINER_SCAN_RESULT"/u);
  assert.match(liveScript, /"EXTRACTED_PAYLOAD_SCAN_RESULT"/u);
  assert.match(liveScript, /"OBSERVATIONAL_ONLY"/u);
  assert.match(liveScript, /"COMPLETE_SAFE_SCAN": False/u);
  assert.match(liveScript, /"clean_is_not_complete_nested_inspection": True/u);
  assert.match(liveScript, /REQUIRED_EXTRACTED_EICAR_DETECTION_MISSING/u);
  assert.match(liveScript, /def _derive_aggregate/u);
  assert.doesNotMatch(liveScript, /\.read\(info\.filename\)|archive\.read\(/u);
  assert.match(liveScript, /INDEPENDENT_ZIP_MAX_MEMBER_BYTES/u);
  assert.match(liveScript, /independent_reader_memory_limit/u);
});

test("scratch cleanup uses validated fixed-path sudo removal and finalizer fails closed", () => {
  const cleanup = workflow.slice(workflow.indexOf("id: cleanup"));
  assert.match(cleanup, /bash scripts\/experiments\/phase0c_safe_scratch_cleanup\.sh/u);
  assert.match(cleanup, /cleanup-status\.json/u);
  assert.match(cleanup, /runtime_verification_passed/u);
  assert.match(cleanup, /LIVE_STEP_OUTCOME: \$\{\{ steps\.live\.outcome \}\}/u);
  assert.match(cleanup, /if: always\(\) && steps\.boundary\.outcome == 'success'/u);
  assert.match(cleanup, /--mode finalize/u);
  assert.ok(cleanup.includes('[[ "$errors" -eq 0 ]]'));
  const helper = readFile(new URL("../scripts/experiments/phase0c_safe_scratch_cleanup.sh", import.meta.url), "utf8");
  return helper.then((script) => {
    assert.ok(script.includes("realpath -e"));
    assert.ok(script.includes('[[ -L "$scratch_dir" ]]'));
    assert.ok(script.includes('sudo rm -rf -- "$scratch_dir"'));
  });
});

test("offline protocol and cleanup unit tests run without a ClamAV service", () => {
  const python = spawnSync("python3", ["test/phase0c-r1r2-live-artifacts.py"], {
    cwd: fileURLToPath(new URL("..", import.meta.url)),
    encoding: "utf8",
    timeout: 30000,
  });
  if (python.error?.code === "ENOENT") return;
  assert.equal(python.status, 0, python.stderr || python.stdout);
});
