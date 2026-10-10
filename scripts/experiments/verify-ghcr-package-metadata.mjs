import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

export const EXIT_CODES = Object.freeze({
  unsafeVisibility: 41,
  wrongRepository: 42,
  consistencyTimeout: 43,
  apiFailure: 44,
  invalidConfiguration: 45,
  identityMismatch: 46,
  packageAccessDenied: 47,
  provenanceMismatch: 48,
  malformedMetadata: 49,
});

export class GhcrVerificationError extends Error {
  constructor(message, exitCode, classification) {
    super(message);
    this.name = "GhcrVerificationError";
    this.exitCode = exitCode;
    this.classification = classification;
  }
}

function sanitizeDiagnostic(value, fallback = "unknown") {
  if (typeof value !== "string" || value.length === 0) return fallback;
  return value.replace(/[^A-Za-z0-9._/:@-]/g, "_").slice(0, 200) || fallback;
}

function parseBoundedInteger(value, name, { minimum, maximum }) {
  if (!/^[0-9]+$/.test(String(value))) {
    throw new GhcrVerificationError(
      `GHCR_VERIFY_CONFIG_ERROR ${name}=invalid`,
      EXIT_CODES.invalidConfiguration,
      "invalid_configuration",
    );
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new GhcrVerificationError(
      `GHCR_VERIFY_CONFIG_ERROR ${name}=out_of_range`,
      EXIT_CODES.invalidConfiguration,
      "invalid_configuration",
    );
  }
  return parsed;
}

function run(command, args) {
  return spawnSync(command, args, {
    encoding: "utf8",
    maxBuffer: 20 * 1024 * 1024,
    windowsHide: true,
  });
}

export function classifyGhApiFailure({ stderr = "", errorCode = "" } = {}) {
  if (errorCode === "ENOENT") {
    return { retryable: false, reason: "gh_client_unavailable", httpStatus: null };
  }
  const statusMatch = stderr.match(/(?:HTTP|status(?: code)?)\s+(\d{3})/i);
  const httpStatus = statusMatch ? Number(statusMatch[1]) : null;
  const rateLimited = /rate.?limit|secondary rate limit|too many requests/i.test(stderr);
  if (rateLimited || httpStatus === 429) {
    return { retryable: true, reason: "rate_limited", httpStatus };
  }
  if (httpStatus === 404) {
    return { retryable: true, reason: "not_visible_to_token", httpStatus };
  }
  if (httpStatus !== null && httpStatus >= 500) {
    return { retryable: true, reason: "server_error", httpStatus };
  }
  if (httpStatus !== null && httpStatus >= 400) {
    return { retryable: false, reason: `http_${httpStatus}`, httpStatus };
  }
  return { retryable: true, reason: "api_unavailable", httpStatus };
}

export function fetchGhcrPackage({ expectedOwner, expectedPackage }) {
  const result = run("gh", [
    "api",
    `/users/${expectedOwner}/packages/container/${expectedPackage}`,
  ]);
  if (result.status === 0) return { ok: true, body: result.stdout };
  return {
    ok: false,
    ...classifyGhApiFailure({
      stderr: result.stderr ?? "",
      errorCode: result.error?.code ?? "",
    }),
  };
}

function repositoryMetadata(packageData, expectedRepository) {
  if (!Object.hasOwn(packageData, "repository")) {
    return { state: "absent", value: null, explicitWrong: false };
  }
  if (packageData.repository === null) {
    return { state: "null", value: null, explicitWrong: false };
  }
  if (typeof packageData.repository !== "object" || Array.isArray(packageData.repository)) {
    return { state: "malformed", value: null, explicitWrong: false };
  }
  if (!Object.hasOwn(packageData.repository, "full_name")) {
    return { state: "full_name_absent", value: null, explicitWrong: false };
  }
  const fullName = packageData.repository.full_name;
  if (fullName === null) return { state: "full_name_null", value: null, explicitWrong: false };
  if (fullName === "") return { state: "empty", value: null, explicitWrong: false };
  if (typeof fullName !== "string") {
    return { state: "malformed", value: null, explicitWrong: false };
  }
  if (fullName === expectedRepository) {
    return { state: "expected", value: fullName, explicitWrong: false };
  }
  return { state: "wrong", value: fullName, explicitWrong: true };
}

function sanitizedPackage(packageData, repository) {
  return {
    id: Number.isSafeInteger(packageData.id) ? packageData.id : null,
    name: typeof packageData.name === "string" ? packageData.name : null,
    package_type: typeof packageData.package_type === "string" ? packageData.package_type : null,
    visibility: typeof packageData.visibility === "string" ? packageData.visibility : null,
    owner: { login: typeof packageData.owner?.login === "string" ? packageData.owner.login : null },
    repository: { state: repository.state, full_name: repository.value },
    html_url: typeof packageData.html_url === "string" ? packageData.html_url : null,
    version_count: Number.isSafeInteger(packageData.version_count) ? packageData.version_count : null,
  };
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8" });
}

function parseJson(value) {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

export function probeRegistryImage({ imageName, digest }) {
  const imageByDigest = `${imageName}@${digest}`;
  const indexResult = run("docker", ["buildx", "imagetools", "inspect", imageByDigest, "--raw"]);
  if (indexResult.status !== 0) {
    return { ok: false, classification: "package_access_denied" };
  }
  const index = parseJson(indexResult.stdout);
  if (!index || typeof index !== "object" || Array.isArray(index)) {
    return { ok: false, classification: "registry_manifest_malformed" };
  }

  let arm64ManifestDigest = digest;
  if (Array.isArray(index.manifests)) {
    const matches = index.manifests.filter(
      (manifest) => manifest?.platform?.os === "linux" && manifest?.platform?.architecture === "arm64",
    );
    if (matches.length !== 1 || !/^sha256:[a-f0-9]{64}$/.test(matches[0]?.digest ?? "")) {
      return { ok: false, classification: "arm64_manifest_ambiguous" };
    }
    arm64ManifestDigest = matches[0].digest;
  }

  const labelsResult = run("docker", [
    "buildx",
    "imagetools",
    "inspect",
    `${imageName}@${arm64ManifestDigest}`,
    "--format",
    "{{json .Image.Config.Labels}}",
  ]);
  if (labelsResult.status !== 0) {
    return { ok: false, classification: "package_config_unreadable" };
  }
  const labels = parseJson(labelsResult.stdout.trim());
  if (!labels || typeof labels !== "object" || Array.isArray(labels)) {
    return { ok: false, classification: "package_labels_malformed" };
  }
  return {
    ok: true,
    accessVerified: true,
    registryDigest: digest,
    arm64ManifestDigest,
    labels,
  };
}

function createDiagnostic({ phase, expectedRepository, maxAttempts, now }) {
  return {
    phase,
    policy: "private-expected-identity-authenticated-digest-matching-provenance",
    expectedRepository,
    maxAttempts,
    attempts: [],
    packageVisibility: "unknown",
    repositoryMetadata: "unknown",
    packageAccess: "unknown",
    imageSourceProvenance: "unknown",
    failureClassification: null,
    timestamp: now(),
  };
}

function persistDiagnostic(evidenceDir, phase, diagnostic) {
  writeJson(resolve(evidenceDir, `ghcr-${phase}-diagnostic.json`), diagnostic);
}

function validateConfiguration(configuration) {
  const requiredStrings = [
    "phase",
    "expectedRepository",
    "expectedOwner",
    "expectedPackage",
    "expectedPackageType",
    "imageName",
    "digest",
    "expectedSource",
    "expectedRevision",
    "expectedRunId",
    "expectedVersion",
    "evidenceDir",
  ];
  for (const name of requiredStrings) {
    if (typeof configuration[name] !== "string" || configuration[name].length === 0) {
      throw new GhcrVerificationError(
        `GHCR_VERIFY_CONFIG_ERROR ${name}=missing`,
        EXIT_CODES.invalidConfiguration,
        "invalid_configuration",
      );
    }
  }
  if (!/^sha256:[a-f0-9]{64}$/.test(configuration.digest)) {
    throw new GhcrVerificationError(
      "GHCR_VERIFY_CONFIG_ERROR digest=invalid",
      EXIT_CODES.invalidConfiguration,
      "invalid_configuration",
    );
  }
}

function fail({ diagnostic, evidenceDir, phase, logger, message, exitCode, classification }) {
  diagnostic.failureClassification = classification;
  persistDiagnostic(evidenceDir, phase, diagnostic);
  logger.error(message);
  throw new GhcrVerificationError(message, exitCode, classification);
}

export async function verifyGhcrPackageTrust({
  phase,
  expectedRepository,
  expectedOwner,
  expectedPackage,
  expectedPackageType = "container",
  imageName,
  digest,
  expectedSource,
  expectedRevision,
  expectedRunId,
  expectedVersion,
  evidenceDir,
  maxAttempts = 12,
  retryDelayMs = 5_000,
  fetchPackage = fetchGhcrPackage,
  probeImage = probeRegistryImage,
  sleep = (milliseconds) => new Promise((done) => setTimeout(done, milliseconds)),
  now = () => new Date().toISOString(),
  logger = console,
} = {}) {
  const configuration = {
    phase,
    expectedRepository,
    expectedOwner,
    expectedPackage,
    expectedPackageType,
    imageName,
    digest,
    expectedSource,
    expectedRevision,
    expectedRunId,
    expectedVersion,
    evidenceDir,
  };
  validateConfiguration(configuration);
  mkdirSync(evidenceDir, { recursive: true });
  const diagnostic = createDiagnostic({ phase, expectedRepository, maxAttempts, now });

  let packageData;
  let repository;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const fetched = await fetchPackage({ expectedOwner, expectedPackage });
    if (!fetched.ok) {
      const reason = sanitizeDiagnostic(fetched.reason, "api_unavailable");
      diagnostic.attempts.push({ attempt, apiState: "unavailable", reason, timestamp: now() });
      if (!fetched.retryable) {
        fail({
          diagnostic, evidenceDir, phase, logger,
          message: `GHCR_VERIFY_FAIL phase=${phase} api=${reason}`,
          exitCode: EXIT_CODES.apiFailure,
          classification: "api_failure",
        });
      }
      if (attempt < maxAttempts) {
        persistDiagnostic(evidenceDir, phase, diagnostic);
        logger.warn(`GHCR_VERIFY_WAIT phase=${phase} attempt=${attempt} api=${reason}`);
        await sleep(retryDelayMs);
        continue;
      }
      fail({
        diagnostic, evidenceDir, phase, logger,
        message: `GHCR_VERIFY_TIMEOUT phase=${phase} attempts=${maxAttempts} api=${reason}`,
        exitCode: EXIT_CODES.consistencyTimeout,
        classification: "api_consistency_timeout",
      });
    }

    packageData = parseJson(fetched.body);
    if (!packageData || typeof packageData !== "object" || Array.isArray(packageData)) {
      fail({
        diagnostic, evidenceDir, phase, logger,
        message: `GHCR_VERIFY_FAIL phase=${phase} package_metadata=malformed`,
        exitCode: EXIT_CODES.malformedMetadata,
        classification: "malformed_package_metadata",
      });
    }

    repository = repositoryMetadata(packageData, expectedRepository);
    const safePackage = sanitizedPackage(packageData, repository);
    writeJson(resolve(evidenceDir, `package-${phase}.json`), safePackage);
    diagnostic.packageVisibility = safePackage.visibility ?? "malformed";
    diagnostic.repositoryMetadata = repository.state;
    diagnostic.attempts.push({
      attempt,
      apiState: "success",
      visibility: safePackage.visibility ?? "malformed",
      repositoryMetadata: repository.state,
      timestamp: now(),
    });
    break;
  }

  const identities = [
    [packageData.owner?.login, expectedOwner, "owner"],
    [packageData.name, expectedPackage, "name"],
    [packageData.package_type, expectedPackageType, "package_type"],
  ];
  for (const [actual, expected, field] of identities) {
    if (actual !== expected) {
      fail({
        diagnostic, evidenceDir, phase, logger,
        message: `GHCR_VERIFY_REFUSE phase=${phase} package_identity=${field}_mismatch`,
        exitCode: EXIT_CODES.identityMismatch,
        classification: `identity_${field}_mismatch`,
      });
    }
  }

  if (packageData.visibility !== "private") {
    fail({
      diagnostic, evidenceDir, phase, logger,
      message: `GHCR_VERIFY_REFUSE phase=${phase} visibility=${sanitizeDiagnostic(packageData.visibility)}`,
      exitCode: EXIT_CODES.unsafeVisibility,
      classification: "unsafe_visibility",
    });
  }
  logger.log(`GHCR_VERIFY_SIGNAL phase=${phase} visibility_private`);

  if (repository.state === "malformed") {
    fail({
      diagnostic, evidenceDir, phase, logger,
      message: `GHCR_VERIFY_REFUSE phase=${phase} repository_metadata=malformed`,
      exitCode: EXIT_CODES.malformedMetadata,
      classification: "malformed_repository_metadata",
    });
  }
  if (repository.explicitWrong) {
    fail({
      diagnostic, evidenceDir, phase, logger,
      message: `GHCR_VERIFY_REFUSE phase=${phase} repository_metadata_wrong=${sanitizeDiagnostic(repository.value)}`,
      exitCode: EXIT_CODES.wrongRepository,
      classification: "wrong_repository",
    });
  }
  if (repository.state === "expected") {
    logger.log(`GHCR_VERIFY_SIGNAL phase=${phase} repository_metadata_expected`);
  } else {
    logger.warn(`GHCR_VERIFY_SIGNAL phase=${phase} repository_metadata_missing state=${repository.state}`);
  }

  const probe = await probeImage({ imageName, digest });
  if (!probe?.ok || probe.accessVerified !== true) {
    diagnostic.packageAccess = "denied";
    fail({
      diagnostic, evidenceDir, phase, logger,
      message: `GHCR_VERIFY_REFUSE phase=${phase} package_access_denied reason=${sanitizeDiagnostic(probe?.classification)}`,
      exitCode: EXIT_CODES.packageAccessDenied,
      classification: probe?.classification ?? "package_access_denied",
    });
  }
  diagnostic.packageAccess = "verified";
  logger.log(`GHCR_VERIFY_SIGNAL phase=${phase} package_access_verified digest=${digest}`);

  const expectedLabels = {
    "org.opencontainers.image.source": expectedSource,
    "org.opencontainers.image.revision": expectedRevision,
    "org.opencontainers.image.version": expectedVersion,
    "io.dip.workflow-run-id": expectedRunId,
  };
  for (const [label, expected] of Object.entries(expectedLabels)) {
    if (probe.labels?.[label] !== expected) {
      diagnostic.imageSourceProvenance = "wrong";
      fail({
        diagnostic, evidenceDir, phase, logger,
        message: `GHCR_VERIFY_REFUSE phase=${phase} provenance_wrong label=${sanitizeDiagnostic(label)}`,
        exitCode: EXIT_CODES.provenanceMismatch,
        classification: `provenance_${label.replace(/[^A-Za-z0-9]/g, "_")}_mismatch`,
      });
    }
  }
  diagnostic.imageSourceProvenance = "verified";
  diagnostic.registryDigest = probe.registryDigest;
  diagnostic.arm64ManifestDigest = probe.arm64ManifestDigest;
  diagnostic.failureClassification = null;
  persistDiagnostic(evidenceDir, phase, diagnostic);
  logger.log(`GHCR_VERIFY_SIGNAL phase=${phase} provenance_expected`);
  const passSignal = phase === "preflight" ? "preflight_pass" : `${phase.replaceAll("-", "_")}_pass`;
  logger.log(
    `GHCR_VERIFY_PASS phase=${phase} ${passSignal} repository_metadata=${repository.state} independent_signals=package_access,provenance`,
  );
  return {
    packageData: sanitizedPackage(packageData, repository),
    repositoryMetadata: repository.state,
    probe,
    diagnostic,
  };
}

async function main() {
  const maxAttempts = parseBoundedInteger(
    process.env.GHCR_VERIFY_MAX_ATTEMPTS ?? "12",
    "max_attempts",
    { minimum: 1, maximum: 100 },
  );
  const retrySeconds = parseBoundedInteger(
    process.env.GHCR_VERIFY_RETRY_SECONDS ?? "5",
    "retry_seconds",
    { minimum: 0, maximum: 300 },
  );
  await verifyGhcrPackageTrust({
    phase: process.env.GHCR_VERIFY_PHASE,
    expectedRepository: process.env.EXPECTED_REPOSITORY,
    expectedOwner: process.env.EXPECTED_PACKAGE_OWNER,
    expectedPackage: process.env.EXPECTED_PACKAGE_NAME,
    expectedPackageType: process.env.EXPECTED_PACKAGE_TYPE ?? "container",
    imageName: process.env.IMAGE_NAME,
    digest: process.env.GHCR_VERIFY_DIGEST,
    expectedSource: process.env.GHCR_EXPECTED_SOURCE,
    expectedRevision: process.env.GHCR_EXPECTED_REVISION,
    expectedRunId: process.env.GHCR_EXPECTED_RUN_ID,
    expectedVersion: process.env.GHCR_EXPECTED_VERSION,
    evidenceDir: process.env.EVIDENCE_DIR,
    maxAttempts,
    retryDelayMs: retrySeconds * 1_000,
  });
}

const invokedAsScript = process.argv[1]
  && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (invokedAsScript) {
  main().catch((error) => {
    if (error instanceof GhcrVerificationError) {
      console.error(
        `GHCR_VERIFY_FAIL classification=${sanitizeDiagnostic(error.classification)} exit_code=${error.exitCode}`,
      );
      process.exitCode = error.exitCode;
      return;
    }
    console.error("GHCR_VERIFY_FAIL classification=unexpected_error exit_code=45");
    process.exitCode = EXIT_CODES.invalidConfiguration;
  });
}
