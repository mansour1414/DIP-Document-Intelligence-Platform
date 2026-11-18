import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
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

async function boundarySandbox(t) {
  // Execute the actual boundary step, never the later workflow steps.
  const step = workflow.split(/^ {6}- name:/mu).find((item) => /^ {8}id: boundary$/mu.test(item));
  const runBlock = step?.match(/^ {8}run: \|\n((?: {10}[^\n]*\n|\n)+)/mu);
  assert.ok(runBlock, "expected a literal Bash script in the boundary step");
  const script = runBlock[1].replace(/^ {10}/gmu, "");
  const root = await mkdtemp(join(await realpath(tmpdir()), "phase0c-boundary-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const runnerTemp = join(root, "work", "_temp");
  const githubEnv = join(root, "github-env");
  await mkdir(runnerTemp, { recursive: true });
  await writeFile(githubEnv, "");
  // Stub only uname so the runtime architecture check is exercised on any CI host.
  await writeFile(join(root, "uname"), '#!/bin/bash\nprintf "%s\\n" "$TEST_MACHINE"\n', { mode: 0o755 });
  const env = {
    ...process.env,
    ...Object.fromEntries([...workflow.matchAll(/^ {6}(EXPECTED_\w+): (\S+)$/gmu)].map(([, key, value]) => [key, value])),
    PATH: `${root}:${process.env.PATH}`,
    TEST_MACHINE: "aarch64",
    GITHUB_EVENT_NAME: "workflow_dispatch",
    GITHUB_REPOSITORY: "mansour1414/DIP-Document-Intelligence-Platform",
    GITHUB_REF: "refs/heads/main",
    GITHUB_REF_NAME: "main",
    CONFIRMATION_INPUT: "run-phase0c-r1r2-isolated-live-evidence",
    GITHUB_ENV: githubEnv,
    RUNNER_TEMP: runnerTemp,
  };
  return {
    root, runnerTemp, githubEnv,
    run(overrides) {
      const result = spawnSync("bash", ["--noprofile", "--norc", "-e", "-o", "pipefail", "-s"], {
        cwd: fileURLToPath(new URL("..", import.meta.url)),
        env: { ...env, ...overrides },
        input: script,
        encoding: "utf8",
        timeout: 5000,
      });
      assert.ifError(result.error);
      return result;
    },
  };
}

function assertBoundaryFailure(result, assertion) {
  assert.equal(result.status, 1, assertion);
  assert.equal(result.stdout, "", assertion);
  assert.equal(result.stderr, `::error::Phase 0C boundary failed: ${assertion}\n`);
}

test("Phase 0C boundary accepts a canonical work/_temp directory", async (t) => {
  const { run, runnerTemp, githubEnv } = await boundarySandbox(t);
  const result = run();
  assert.equal(result.status, 0, result.stderr);
  const evidence = join(runnerTemp, "clamav-phase0c-evidence");
  const work = join(runnerTemp, "clamav-phase0c-work");
  assert.equal(await readFile(githubEnv, "utf8"), `EVIDENCE_DIR=${evidence}\nWORK_DIR=${work}\n`);
  assert.deepEqual((await readdir(work)).sort(), ["cfg", "client-fixtures", "db", "fixtures"]);
  assert.match(await readFile(join(evidence, "source-files.sha256"), "utf8"), /^[a-f0-9]{64}  \.github\/workflows\/clamav-phase0c-live-evidence\.yml$/mu);
});

test("Phase 0C boundary rejects invalid runner paths before setup", async (t) => {
  const { run, root, runnerTemp, githubEnv } = await boundarySandbox(t);
  const otherParent = join(root, "other", "_temp");
  const wrongLeaf = join(root, "work", "_tmp");
  const symlinkLeaf = join(root, "link-leaf", "work", "_temp");
  const symlinkParent = join(root, "link-parent", "work");
  const file = join(root, "file", "work", "_temp");
  const newline = `${root}/line\nbreak/work/_temp`;
  for (const path of [otherParent, wrongLeaf, newline]) await mkdir(path, { recursive: true });
  for (const path of [symlinkLeaf, symlinkParent, file]) await mkdir(dirname(path), { recursive: true });
  await symlink(runnerTemp, symlinkLeaf);
  await symlink(join(root, "work"), symlinkParent);
  await writeFile(file, "");
  for (const [path, assertion] of [
    ["", "runner-temp-required"],
    ["work/_temp", "runner-temp-absolute"],
    [`${runnerTemp}/`, "runner-temp-absolute"],
    [newline, "runner-temp-absolute"],
    [`${root}/./work/_temp`, "runner-temp-dot-component"],
    [`${root}/other/../work/_temp`, "runner-temp-dot-component"],
    [otherParent, "runner-temp-parent"],
    [wrongLeaf, "runner-temp-leaf"],
    [`${root}//work/_temp`, "runner-temp-canonical"],
    [symlinkLeaf, "runner-temp-canonical"],
    [join(symlinkParent, "_temp"), "runner-temp-canonical"],
    [join(root, "missing", "work", "_temp"), "runner-temp-directory"],
    [file, "runner-temp-directory"],
  ]) {
    assertBoundaryFailure(run({ RUNNER_TEMP: path }), assertion);
  }
  assert.equal(await readFile(githubEnv, "utf8"), "");
  for (const path of [runnerTemp, otherParent, wrongLeaf, newline]) assert.deepEqual(await readdir(path), []);
});

test("Phase 0C authorization and checksum failures leave no scratch or evidence", async (t) => {
  const { run, runnerTemp, githubEnv } = await boundarySandbox(t);
  for (const [key, value, assertion] of [
    ["GITHUB_EVENT_NAME", "push", "manual-dispatch"],
    ["GITHUB_REPOSITORY", "other/repository", "repository"],
    ["GITHUB_REF", "refs/heads/other", "branch-ref"],
    ["GITHUB_REF_NAME", "other", "branch-name"],
    ["CONFIRMATION_INPUT", "invalid", "confirmation"],
    ["TEST_MACHINE", "x86_64", "arm64"],
    ...["EXPECTED_CLAM3102_PATCH_SHA256", "EXPECTED_BASE_CONF_SHA256", "EXPECTED_FRESHNESS_GATE_SHA256"]
      .map((key) => [key, "0".repeat(64), "source-checksums"]),
  ]) {
    assertBoundaryFailure(run({ [key]: value }), assertion);
    assert.deepEqual(await readdir(runnerTemp), []);
    assert.equal(await readFile(githubEnv, "utf8"), "");
  }
});

test("Phase 0C rolls back incomplete setup without touching an existing scratch path", async (t) => {
  const { run, runnerTemp, githubEnv } = await boundarySandbox(t);
  assertBoundaryFailure(run({ GITHUB_ENV: runnerTemp }), "publish-runner-paths");
  assert.deepEqual(await readdir(runnerTemp), []);

  const work = join(runnerTemp, "clamav-phase0c-work");
  await mkdir(work);
  await writeFile(join(work, "sentinel"), "keep");
  assertBoundaryFailure(run(), "scratch-directory-create");
  assert.deepEqual(await readdir(runnerTemp), ["clamav-phase0c-work"]);
  assert.equal(await readFile(join(work, "sentinel"), "utf8"), "keep");
  assert.equal(await readFile(githubEnv, "utf8"), "");
});
