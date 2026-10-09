import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  EXIT_CODES,
  GhcrPostcheckError,
  verifyPackageMetadata,
} from "../scripts/experiments/verify-ghcr-package-metadata.mjs";

const EXPECTED_REPOSITORY = "mansour1414/DIP-Document-Intelligence-Platform";

function packageResponse(options = {}) {
  const visibility = options.visibility ?? "private";
  const repository = Object.hasOwn(options, "repository")
    ? options.repository
    : EXPECTED_REPOSITORY;
  const payload = { visibility };
  if (repository !== undefined) payload.repository = { full_name: repository };
  return { ok: true, body: JSON.stringify(payload) };
}

function sequenceFetcher(sequence) {
  let calls = 0;
  return {
    fetchPackage: async () => {
      const item = sequence[Math.min(calls, sequence.length - 1)];
      calls += 1;
      return item;
    },
    calls: () => calls,
  };
}

function silentLogger() {
  return { log() {}, warn() {}, error() {} };
}

async function withEvidence(run) {
  const evidenceDir = await mkdtemp(join(tmpdir(), "dip-ghcr-postcheck-"));
  try {
    return await run(evidenceDir);
  } finally {
    await rm(evidenceDir, { recursive: true, force: true });
  }
}

async function expectFailure(promise, exitCode, classification) {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof GhcrPostcheckError);
    assert.equal(error.exitCode, exitCode);
    assert.equal(error.classification, classification);
    return true;
  });
}

function runVerification(evidenceDir, fetchPackage, maxAttempts) {
  return verifyPackageMetadata({
    expectedRepository: EXPECTED_REPOSITORY,
    evidenceDir,
    fetchPackage,
    maxAttempts,
    retryDelayMs: 0,
    sleep: async () => {},
    now: () => "2026-10-09T00:00:00.000Z",
    logger: silentLogger(),
  });
}

test("retries unavailable API responses until private correctly linked metadata appears", async () => {
  await withEvidence(async (evidenceDir) => {
    const sequence = sequenceFetcher([
      { ok: false, retryable: true, reason: "not_yet_visible" },
      { ok: false, retryable: true, reason: "server_error" },
      packageResponse(),
    ]);
    const result = await runVerification(evidenceDir, sequence.fetchPackage, 3);
    assert.equal(result.attempts, 3);
    assert.equal(sequence.calls(), 3);
  });
});

test("waits for an empty repository link and then passes", async () => {
  await withEvidence(async (evidenceDir) => {
    const sequence = sequenceFetcher([
      packageResponse({ repository: undefined }),
      packageResponse(),
    ]);
    const result = await runVerification(evidenceDir, sequence.fetchPackage, 2);
    assert.equal(result.attempts, 2);
    const saved = JSON.parse(await readFile(join(evidenceDir, "package-post-publish.json"), "utf8"));
    assert.equal(saved.repository.full_name, EXPECTED_REPOSITORY);
  });
});

test("times out when a private package link remains pending", async () => {
  await withEvidence(async (evidenceDir) => {
    const sequence = sequenceFetcher([packageResponse({ repository: undefined })]);
    await expectFailure(
      runVerification(evidenceDir, sequence.fetchPackage, 3),
      EXIT_CODES.consistencyTimeout,
      "metadata_consistency_timeout",
    );
    assert.equal(sequence.calls(), 3);
    const diagnostic = JSON.parse(
      await readFile(join(evidenceDir, "package-post-publish-diagnostic.json"), "utf8"),
    );
    assert.equal(diagnostic.failureClassification, "metadata_consistency_timeout");
    assert.equal(diagnostic.finalObservedRepositoryLink, "pending");
  });
});

for (const visibility of ["public", "internal"]) {
  test(`refuses ${visibility} visibility immediately`, async () => {
    await withEvidence(async (evidenceDir) => {
      const sequence = sequenceFetcher([packageResponse({ visibility })]);
      await expectFailure(
        runVerification(evidenceDir, sequence.fetchPackage, 12),
        EXIT_CODES.unsafeVisibility,
        "unsafe_visibility",
      );
      assert.equal(sequence.calls(), 1);
    });
  });
}

test("refuses an explicit wrong repository immediately", async () => {
  await withEvidence(async (evidenceDir) => {
    const sequence = sequenceFetcher([
      packageResponse({ repository: "mansour1414/not-dip" }),
    ]);
    await expectFailure(
      runVerification(evidenceDir, sequence.fetchPackage, 12),
      EXIT_CODES.wrongRepository,
      "wrong_repository",
    );
    assert.equal(sequence.calls(), 1);
  });
});

test("passes immediately for a private correctly linked package", async () => {
  await withEvidence(async (evidenceDir) => {
    const sequence = sequenceFetcher([packageResponse()]);
    const result = await runVerification(evidenceDir, sequence.fetchPackage, 12);
    assert.equal(result.attempts, 1);
    assert.equal(sequence.calls(), 1);
  });
});

test("malformed API JSON remains fail-closed after bounded retries", async () => {
  await withEvidence(async (evidenceDir) => {
    const sequence = sequenceFetcher([{ ok: true, body: "not-json" }]);
    await expectFailure(
      runVerification(evidenceDir, sequence.fetchPackage, 2),
      EXIT_CODES.consistencyTimeout,
      "malformed_metadata_timeout",
    );
    assert.equal(sequence.calls(), 2);
  });
});

test("terminal API authorization failures fail immediately", async () => {
  await withEvidence(async (evidenceDir) => {
    const sequence = sequenceFetcher([
      { ok: false, retryable: false, reason: "http_403" },
    ]);
    await expectFailure(
      runVerification(evidenceDir, sequence.fetchPackage, 12),
      EXIT_CODES.apiFailure,
      "api_failure",
    );
    assert.equal(sequence.calls(), 1);
  });
});
