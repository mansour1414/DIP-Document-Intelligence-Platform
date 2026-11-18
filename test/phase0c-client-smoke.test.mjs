import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";

function liveSmokePayload() {
  const workflow = readFileSync(new URL("../.github/workflows/clamav-phase0c-live-evidence.yml", import.meta.url), "utf8");
  // Extract only the smoke command, between saving the image ID and collecting its manifests.
  const smoke = workflow.match(/^ {10}echo "LOCAL_CLIENT_IMAGE_ID=.*\n((?: {10}.*\n|\n)+?)^ {10}cid=/mu);
  assert.ok(smoke, "expected the live client smoke command in the workflow");

  // Remove only YAML's block indentation. Let Bash form the real argv, with no Docker calls.
  const shell = spawnSync("bash", ["--noprofile", "--norc", "-eu", "-o", "pipefail", "-s"], {
    input: `docker() {
  [[ "$1" = run ]] || return 1
  while [[ $# -gt 0 && "$1" != --entrypoint ]]; do shift; done
  [[ $# -eq 5 && "$2" = python3 && "$3" = "$LOCAL_CLIENT_IMAGE" && "$4" = -c ]] || return 1
  printf '%s' "$5"
}
${smoke[1].replace(/^ {10}/gmu, "")}`,
    env: { PATH: process.env.PATH, LOCAL_CLIENT_IMAGE: "dip-phase0c-client:test" },
    encoding: "utf8",
    timeout: 5000,
  });
  assert.ifError(shell.error);
  assert.equal(shell.status, 0, shell.stderr || "expected one python3 -c argument");
  assert.ok(shell.stdout, "expected a nonempty Python smoke payload");
  return shell.stdout;
}

if (process.argv[2] === "--print-payload") {
  process.stdout.write(liveSmokePayload());
} else {
  test("Phase 0C live client smoke passes valid Python to -c", (t) => {
    const python = spawnSync("python3", ["-c", "import sys; compile(sys.argv[1], '<string>', 'exec')", liveSmokePayload()], {
      encoding: "utf8",
      timeout: 5000,
    });
    if (python.error?.code === "ENOENT") return t.skip("python3 unavailable; smoke syntax not verified");
    assert.ifError(python.error);
    assert.equal(python.status, 0, python.stderr);
  });
}
