import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path/posix";
import test from "node:test";

const WORKFLOW = readFileSync(
  new URL("../.github/workflows/clamav-stage7-private-ghcr.yml", import.meta.url),
  "utf8",
);
const PROTOCOL = readFileSync(
  new URL("../docs/operations/experimental/clamav-arm64-stage4-protocol.mts", import.meta.url),
  "utf8",
);

const CONTAINER_PROTOCOL_PATH = "/app/docs/operations/experimental/clamav-arm64-stage4-protocol.mts";
const CONTAINER_PROTOCOL_DIRECTORY = dirname(CONTAINER_PROTOCOL_PATH);

test("Stage 7 preserves the Protocol harness repository-relative module topology", () => {
  const clamdImport = PROTOCOL.match(/from\s+["'](\.\.\/\.\.\/\.\.\/src\/lib\/malware\/clamd)["']/u);
  assert.ok(clamdImport, "Protocol harness must retain its repository-relative ClamdScanner import");
  assert.equal(
    resolve(CONTAINER_PROTOCOL_DIRECTORY, clamdImport[1]),
    "/app/src/lib/malware/clamd",
  );

  assert.match(
    WORKFLOW,
    /-v "\$GITHUB_WORKSPACE\/docs\/operations\/experimental:\/app\/docs\/operations\/experimental:ro" \\\r?\n/u,
  );
  assert.match(
    WORKFLOW,
    new RegExp(`dip-worker:stage7-arm64 node --import tsx ${CONTAINER_PROTOCOL_PATH.replaceAll("/", "\\/")} \\\\\\r?\\n`, "u"),
  );
  assert.doesNotMatch(WORKFLOW, /\/evidence\/protocol\.mts/u);
});

test("Stage 7 remains manual-only and uses only the repository GITHUB_TOKEN", () => {
  const triggerBlock = WORKFLOW.slice(WORKFLOW.indexOf("on:"), WORKFLOW.indexOf("\npermissions:"));
  assert.match(triggerBlock, /^on:\r?\n  workflow_dispatch:/u);
  assert.doesNotMatch(triggerBlock, /^  (?:push|pull_request|schedule|workflow_run):/mu);

  const referencedSecrets = [...WORKFLOW.matchAll(/secrets\.([A-Z0-9_]+)/gu)]
    .map((match) => match[1]);
  assert.deepEqual([...new Set(referencedSecrets)], ["GITHUB_TOKEN"]);
});
