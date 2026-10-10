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

const REPOSITORY = "mansour1414/DIP-Document-Intelligence-Platform";
const OWNER = "mansour1414";
const PACKAGE = "dip-clamav";
const IMAGE = `ghcr.io/${OWNER}/${PACKAGE}`;
const DIGEST = `sha256:${"1".repeat(64)}`;
const SOURCE = `https://github.com/${REPOSITORY}`;

function packageResponse(options = {}) {
  const visibility = options.visibility ?? "private";
  const repository = Object.hasOwn(options, "repository") ? options.repository : REPOSITORY;
  const owner = options.owner ?? OWNER;
  const name = options.name ?? PACKAGE;
  const packageType = options.packageType ?? "container";
  const payload = {
    id: 321,
    name,
    package_type: packageType,
    visibility,
    owner: { login: owner },
    html_url: "https://github.com/users/mansour1414/packages/container/package/dip-clamav",
    version_count: 3,
  };
  if (repository !== undefined) payload.repository = repository === null ? null : { full_name: repository };
  return { ok: true, body: JSON.stringify(payload) };
}

function successfulProbe(overrides = {}) {
  return {
    ok: true,
    accessVerified: true,
    registryDigest: DIGEST,
    arm64ManifestDigest: `sha256:${"2".repeat(64)}`,
    labels: {
      "org.opencontainers.image.source": SOURCE,
      "org.opencontainers.image.revision": "trusted-revision",
      "org.opencontainers.image.version": "trusted-run-tag",
      "io.dip.workflow-run-id": "trusted-run-id",
    },
    ...overrides,
  };
}

async function withEvidence(run) {
  const evidenceDir = await mkdtemp(join(tmpdir(), "dip-ghcr-preflight-"));
  try {
    return await run(evidenceDir);
  } finally {
    await rm(evidenceDir, { recursive: true, force: true });
  }
}

function verify(evidenceDir, {
  fetchPackage = async () => packageResponse(),
  probeImage = async () => successfulProbe(),
  attempts = 3,
} = {}) {
  return verifyGhcrPackageTrust({
    phase: "preflight",
    expectedRepository: REPOSITORY,
    expectedOwner: OWNER,
    expectedPackage: PACKAGE,
    imageName: IMAGE,
    digest: DIGEST,
    expectedSource: SOURCE,
    expectedRevision: "trusted-revision",
    expectedRunId: "trusted-run-id",
    expectedVersion: "trusted-run-tag",
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

test("private + expected repository + access and provenance passes", async () => {
  await withEvidence(async (evidenceDir) => {
    const result = await verify(evidenceDir);
    assert.equal(result.repositoryMetadata, "expected");
  });
});

test("private + absent repository + access + matching provenance passes", async () => {
  await withEvidence(async (evidenceDir) => {
    const result = await verify(evidenceDir, {
      fetchPackage: async () => packageResponse({ repository: undefined }),
    });
    assert.equal(result.repositoryMetadata, "absent");
  });
});

test("private + null repository + access + matching provenance passes", async () => {
  await withEvidence(async (evidenceDir) => {
    const result = await verify(evidenceDir, {
      fetchPackage: async () => packageResponse({ repository: null }),
    });
    assert.equal(result.repositoryMetadata, "null");
  });
});

test("private + empty repository + access + matching provenance passes", async () => {
  await withEvidence(async (evidenceDir) => {
    const result = await verify(evidenceDir, {
      fetchPackage: async () => packageResponse({ repository: "" }),
    });
    assert.equal(result.repositoryMetadata, "empty");
  });
});

test("explicit wrong repository fails immediately", async () => {
  await withEvidence(async (evidenceDir) => {
    await expectFailure(
      verify(evidenceDir, {
        fetchPackage: async () => packageResponse({ repository: "mansour1414/wrong" }),
      }),
      EXIT_CODES.wrongRepository,
      "wrong_repository",
    );
  });
});

for (const visibility of ["public", "internal"]) {
  test(`${visibility} visibility fails immediately`, async () => {
    await withEvidence(async (evidenceDir) => {
      await expectFailure(
        verify(evidenceDir, { fetchPackage: async () => packageResponse({ visibility }) }),
        EXIT_CODES.unsafeVisibility,
        "unsafe_visibility",
      );
    });
  });
}

test("missing repository metadata plus package access denied fails", async () => {
  await withEvidence(async (evidenceDir) => {
    await expectFailure(
      verify(evidenceDir, {
        fetchPackage: async () => packageResponse({ repository: undefined }),
        probeImage: async () => ({ ok: false, classification: "package_access_denied" }),
      }),
      EXIT_CODES.packageAccessDenied,
      "package_access_denied",
    );
  });
});

test("missing repository metadata plus wrong provenance fails", async () => {
  await withEvidence(async (evidenceDir) => {
    const labels = { ...successfulProbe().labels, "org.opencontainers.image.source": "https://github.com/other/repo" };
    await expectFailure(
      verify(evidenceDir, {
        fetchPackage: async () => packageResponse({ repository: undefined }),
        probeImage: async () => successfulProbe({ labels }),
      }),
      EXIT_CODES.provenanceMismatch,
      "provenance_org_opencontainers_image_source_mismatch",
    );
  });
});

test("malformed package JSON fails closed", async () => {
  await withEvidence(async (evidenceDir) => {
    await expectFailure(
      verify(evidenceDir, { fetchPackage: async () => ({ ok: true, body: "{" }) }),
      EXIT_CODES.malformedMetadata,
      "malformed_package_metadata",
    );
  });
});

for (const identity of [
  { owner: "unexpected", classification: "identity_owner_mismatch" },
  { name: "unexpected", classification: "identity_name_mismatch" },
  { packageType: "npm", classification: "identity_package_type_mismatch" },
]) {
  test(`unexpected package identity (${identity.classification}) fails`, async () => {
    await withEvidence(async (evidenceDir) => {
      await expectFailure(
        verify(evidenceDir, { fetchPackage: async () => packageResponse(identity) }),
        EXIT_CODES.identityMismatch,
        identity.classification,
      );
    });
  });
}

test("transient package API failure retries within a bounded attempt count", async () => {
  await withEvidence(async (evidenceDir) => {
    let calls = 0;
    const fetchPackage = async () => {
      calls += 1;
      return calls < 3
        ? { ok: false, retryable: true, reason: "server_error" }
        : packageResponse();
    };
    await verify(evidenceDir, { fetchPackage, attempts: 3 });
    assert.equal(calls, 3);
  });
});

test("transient package API failure times out fail-closed at the configured bound", async () => {
  await withEvidence(async (evidenceDir) => {
    let calls = 0;
    const fetchPackage = async () => {
      calls += 1;
      return { ok: false, retryable: true, reason: "server_error" };
    };
    await expectFailure(
      verify(evidenceDir, { fetchPackage, attempts: 3 }),
      EXIT_CODES.consistencyTimeout,
      "api_consistency_timeout",
    );
    assert.equal(calls, 3);
  });
});

test("correct metadata but inaccessible immutable digest fails", async () => {
  await withEvidence(async (evidenceDir) => {
    await expectFailure(
      verify(evidenceDir, {
        probeImage: async () => ({ ok: false, classification: "package_config_unreadable" }),
      }),
      EXIT_CODES.packageAccessDenied,
      "package_config_unreadable",
    );
  });
});
