import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

test("G1-A/03 records only conditional owner authorization", async () => {
  const decision = await readFile(new URL("../docs/g1a-02-licensing-gate-decision-record.md", import.meta.url), "utf8");
  assert.match(decision, /conditionally authorized only for building and testing an isolated Candidate Image/u);
  assert.match(decision, /Licensing Gate.*NOT APPROVED/u);
});

test("candidate image remains isolated and cannot silently use a mutable base", async () => {
  const [candidate, runner, production] = await Promise.all([
    readFile(new URL("../scripts/experiments/Dockerfile.structural-grayscale-g1a03-candidate", import.meta.url), "utf8"),
    readFile(new URL("../scripts/experiments/build-structural-grayscale-g1a03-candidate.sh", import.meta.url), "utf8"),
    readFile(new URL("../Dockerfile.worker", import.meta.url), "utf8"),
  ]);
  assert.match(candidate, /g1a03-candidate-only/u);
  assert.match(candidate, /production-adoption="not-approved"/u);
  assert.doesNotMatch(candidate, /COPY .*structural-grayscale-stage3[abc]\.py/u);
  assert.match(runner, /G1A03_NODE_IMAGE.*repository@sha256/u);
  assert.match(runner, /syft .*spdx-json/u);
  assert.match(runner, /syft .*cyclonedx-json/u);
  assert.match(runner, /grype .*json/u);
  assert.doesNotMatch(runner, /docker push/u);
  assert.doesNotMatch(production, /dip-gray-candidate|g1a03-candidate/u);
});

test("prebuild vulnerability evidence fails closed and image scan stays unverified", async () => {
  const evidence = JSON.parse(await readFile(new URL("../docs/evidence/g1a03/g1a03-prebuild-vulnerability-evidence.json", import.meta.url), "utf8"));
  assert.equal(evidence.overall_prebuild_status, "FAIL");
  assert.equal(evidence.image_scan.status, "NOT VERIFIED");
  assert.equal(evidence.npm_audit.vulnerabilities.total, 0);
  const pypdf = evidence.osv_pypi_batch.results.find((item: { package: string }) => item.package === "pypdf");
  assert.equal(pypdf.version, "6.10.0");
  assert.equal(pypdf.vulnerability_ids.length, 45);
});

test("G1-A/03 report preserves OFF and no public or production exposure", async () => {
  const [report, registry, worker, config] = await Promise.all([
    readFile(new URL("../docs/g1a-03-candidate-image-security-licensing-report.md", import.meta.url), "utf8"),
    readFile(new URL("../src/lib/tools/registry.ts", import.meta.url), "utf8"),
    readFile(new URL("../workers/document-worker.ts", import.meta.url), "utf8"),
    readFile(new URL("../src/config/index.ts", import.meta.url), "utf8"),
  ]);
  assert.match(report, /Candidate local image ID: `NOT GENERATED`/u);
  assert.match(report, /Candidate registry repository digest: `NOT VERIFIED`/u);
  assert.match(report, /Licensing Gate remains \*\*OPEN — NOT APPROVED\*\*/u);
  for (const source of [registry, worker, config]) assert.doesNotMatch(source, /["']grayscale-pdf["']/u);
});
