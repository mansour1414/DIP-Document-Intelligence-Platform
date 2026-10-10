import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  EXIT_CODES,
  GhcrVerificationError,
  verifyGhcrPackageTrust,
} from "../scripts/experiments/verify-ghcr-package-metadata.mjs";

const EXPECTED_REPOSITORY = "mansour1414/DIP-Document-Intelligence-Platform";
const EXPECTED_OWNER = "mansour1414";
const EXPECTED_PACKAGE = "dip-clamav";
const DIGEST = `sha256:${"a".repeat(64)}`;
const EXPECTED_SOURCE = `https://github.com/${EXPECTED_REPOSITORY}`;

function packageResponse(options = {}) {
  const visibility = options.visibility ?? "private";
  const repository = Object.hasOwn(options, "repository")
    ? options.repository
    : EXPECTED_REPOSITORY;
  const payload = {
    id: 123,
    name: EXPECTED_PACKAGE,
    package_type: "container",
    visibility,
    owner: { login: EXPECTED_OWNER },
    html_url: "https://github.com/users/mansour1414/packages/container/package/dip-clamav",
    version_count: 3,
  };
  if (repository !== undefined) payload.repository = repository === null ? null : { full_name: repository };
  return { ok: true, body: JSON.stringify(payload) };
}

function probeResponse(overrides = {}) {
  return {
    ok: true,
    accessVerified: true,
    registryDigest: DIGEST,
    arm64ManifestDigest: `sha256:${"b".repeat(64)}`,
    labels: {
      "org.opencontainers.image.source": EXPECTED_SOURCE,
      "org.opencontainers.image.revision": "revision",
      "org.opencontainers.image.version": "run-tag",
      "io.dip.workflow-run-id": "run-id",
    },
    ...overrides,
  };
}

function sequenceFetcher(sequence) {
  let calls = 0;
  return {
    fetchPackage: async () => sequence[Math.min(calls++, sequence.length - 1)],
    calls: () => calls,
  };
}

async function withEvidence(run) {
  const evidenceDir = await mkdtemp(join(tmpdir(), "dip-ghcr-postcheck-"));
  try {
    return await run(evidenceDir);
  } finally {
    await rm(evidenceDir, { recursive: true, force: true });
  }
}

function verify(evidenceDir, { fetchPackage, probeImage = async () => probeResponse(), attempts = 3 }) {
  return verifyGhcrPackageTrust({
    phase: "post-publish",
    expectedRepository: EXPECTED_REPOSITORY,
    expectedOwner: EXPECTED_OWNER,
    expectedPackage: EXPECTED_PACKAGE,
    imageName: `ghcr.io/${EXPECTED_OWNER}/${EXPECTED_PACKAGE}`,
    digest: DIGEST,
    expectedSource: EXPECTED_SOURCE,
    expectedRevision: "revision",
    expectedRunId: "run-id",
    expectedVersion: "run-tag",
    evidenceDir,
    maxAttempts: attempts,
    retryDelayMs: 0,
    fetchPackage,
    probeImage,
    sleep: async () => {},
    now: () => "2026-10-10T00:00:00.000Z",
    logger: { log() {}, warn() {}, error() {} },
  });
}

async function expectFailure(promise, exitCode, classification) {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof GhcrVerificationError);
    assert.equal(error.exitCode, exitCode);
    assert.equal(error.classification, classification);
    return true;
  });
}

test("post-publish retries transient API failures and then passes", async () => {
  await withEvidence(async (evidenceDir) => {
    const sequence = sequenceFetcher([
      { ok: false, retryable: true, reason: "not_visible_to_token" },
      { ok: false, retryable: true, reason: "server_error" },
      packageResponse(),
    ]);
    const result = await verify(evidenceDir, { fetchPackage: sequence.fetchPackage });
    assert.equal(sequence.calls(), 3);
    assert.equal(result.repositoryMetadata, "expected");
  });
});

for (const repository of [undefined, null, ""]) {
  test(`post-publish resolves repository metadata ${String(repository)} with independent signals`, async () => {
    await withEvidence(async (evidenceDir) => {
      const result = await verify(evidenceDir, {
        fetchPackage: async () => packageResponse({ repository }),
      });
      assert.notEqual(result.repositoryMetadata, "expected");
      assert.equal(result.probe.accessVerified, true);
    });
  });
}

for (const visibility of ["public", "internal"]) {
  test(`post-publish refuses ${visibility} immediately`, async () => {
    await withEvidence(async (evidenceDir) => {
      await expectFailure(
        verify(evidenceDir, { fetchPackage: async () => packageResponse({ visibility }) }),
        EXIT_CODES.unsafeVisibility,
        "unsafe_visibility",
      );
    });
  });
}

test("post-publish refuses explicit wrong repository", async () => {
  await withEvidence(async (evidenceDir) => {
    await expectFailure(
      verify(evidenceDir, {
        fetchPackage: async () => packageResponse({ repository: "mansour1414/not-dip" }),
      }),
      EXIT_CODES.wrongRepository,
      "wrong_repository",
    );
  });
});

test("post-publish fails closed on malformed API JSON", async () => {
  await withEvidence(async (evidenceDir) => {
    await expectFailure(
      verify(evidenceDir, { fetchPackage: async () => ({ ok: true, body: "not-json" }) }),
      EXIT_CODES.malformedMetadata,
      "malformed_package_metadata",
    );
  });
});

test("post-publish refuses wrong source provenance", async () => {
  await withEvidence(async (evidenceDir) => {
    const probeImage = async () => probeResponse({
      labels: { ...probeResponse().labels, "org.opencontainers.image.source": "https://github.com/other/repo" },
    });
    const expectedClassification = "provenance_org_opencontainers_image_source_mismatch";
    await expectFailure(
      verify(evidenceDir, { fetchPackage: async () => packageResponse(), probeImage }),
      EXIT_CODES.provenanceMismatch,
      expectedClassification,
    );
  });
});
