import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const workflowPath = new URL("../.github/workflows/clamav-phase0b-evidence.yml", import.meta.url);
const workflow = await readFile(workflowPath, "utf8");
const stepStart = workflow.indexOf("      - name: Clean up local containers, image, private network, and scratch directories\n");
assert.notEqual(stepStart, -1, "Phase 0B cleanup step must exist");
const step = workflow.slice(stepStart);
const runBlock = step.match(/\n        run: \|\n((?:(?:          .*)?\n)+)/u);
assert.ok(runBlock, "Phase 0B cleanup step must use an inline shell block");
const cleanupScript = runBlock[1]
  .split("\n")
  .filter(Boolean)
  .map((line) => line.slice(10))
  .join("\n");

async function withSandbox(run) {
  const root = await mkdtemp(path.join(os.tmpdir(), "phase0b-cleanup-test-"));
  const bin = path.join(root, "bin");
  await mkdir(bin);
  await writeFile(path.join(bin, "docker"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  await writeFile(
    path.join(bin, "sudo"),
    `#!/bin/sh\nprintf '%s\\n' "$*" >> "$SUDO_LOG"\nexec "$@"\n`,
    { mode: 0o755 },
  );
  try {
    await run({ root, bin });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

function executeCleanup({ bin, runnerTemp, workDir, sudoLog }) {
  const env = {
    ...process.env,
    PATH: `${bin}:${process.env.PATH ?? ""}`,
    SUDO_LOG: sudoLog,
  };
  delete env.RUNNER_TEMP;
  delete env.WORK_DIR;
  delete env.LOCAL_CANDIDATE_IMAGE;
  delete env.PHASE0B_NETWORK;
  if (runnerTemp !== undefined) env.RUNNER_TEMP = runnerTemp;
  if (workDir !== undefined) env.WORK_DIR = workDir;
  return spawnSync("bash", ["-c", cleanupScript], { encoding: "utf8", env });
}

test("Phase 0B cleanup rejects unset and unexpected runner temp paths without privileged deletion", async () => {
  await withSandbox(async ({ root, bin }) => {
    const sudoLog = path.join(root, "sudo.log");
    const unset = executeCleanup({ bin, sudoLog });
    assert.notEqual(unset.status, 0);
    assert.match(unset.stderr, /RUNNER_TEMP is unset/u);

    const unexpectedTemp = path.join(root, "not-a-runner-temp");
    await mkdir(unexpectedTemp);
    const unexpected = executeCleanup({ bin, runnerTemp: unexpectedTemp, sudoLog });
    assert.notEqual(unexpected.status, 0);
    assert.match(unexpected.stderr, /expected runner work\/_temp/u);
    await assert.rejects(readFile(sudoLog));
  });
});

test("Phase 0B cleanup removes only the fixed scratch leaf below validated runner temp", async () => {
  await withSandbox(async ({ root, bin }) => {
    const runnerTemp = path.join(root, "home", "runner", "work", "_temp");
    const scratch = path.join(runnerTemp, "clamav-phase0b-work");
    const sudoLog = path.join(root, "sudo.log");
    await mkdir(scratch, { recursive: true });
    await writeFile(path.join(scratch, "clamd-owned-signature.tmp"), "temporary test data");

    const result = executeCleanup({ bin, runnerTemp, workDir: scratch, sudoLog });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    await assert.rejects(readFile(path.join(scratch, "clamd-owned-signature.tmp")));
    assert.equal(await readFile(sudoLog, "utf8"), `rm -rf -- ${scratch}\n`);
  });
});
