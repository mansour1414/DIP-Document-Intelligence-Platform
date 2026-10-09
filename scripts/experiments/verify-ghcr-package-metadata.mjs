import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

const PACKAGE_API_PATH = "/users/mansour1414/packages/container/dip-clamav";

export const EXIT_CODES = Object.freeze({
  unsafeVisibility: 41,
  wrongRepository: 42,
  consistencyTimeout: 43,
  apiFailure: 44,
  invalidConfiguration: 45,
});

export class GhcrPostcheckError extends Error {
  constructor(message, exitCode, classification) {
    super(message);
    this.name = "GhcrPostcheckError";
    this.exitCode = exitCode;
    this.classification = classification;
  }
}

function sanitizeDiagnostic(value, fallback = "unknown") {
  if (typeof value !== "string" || value.length === 0) return fallback;
  return value.replace(/[^A-Za-z0-9._/-]/g, "_").slice(0, 160) || fallback;
}

function parseBoundedInteger(value, name, { minimum, maximum }) {
  if (!/^[0-9]+$/.test(String(value))) {
    throw new GhcrPostcheckError(
      `GHCR_POSTCHECK_CONFIG_ERROR ${name}=invalid`,
      EXIT_CODES.invalidConfiguration,
      "invalid_configuration",
    );
  }

  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new GhcrPostcheckError(
      `GHCR_POSTCHECK_CONFIG_ERROR ${name}=out_of_range`,
      EXIT_CODES.invalidConfiguration,
      "invalid_configuration",
    );
  }
  return parsed;
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
    return { retryable: true, reason: "not_yet_visible", httpStatus };
  }
  if (httpStatus !== null && httpStatus >= 500) {
    return { retryable: true, reason: "server_error", httpStatus };
  }
  if (httpStatus !== null && httpStatus >= 400) {
    return { retryable: false, reason: `http_${httpStatus}`, httpStatus };
  }
  return { retryable: true, reason: "api_unavailable", httpStatus };
}

export function fetchGhcrPackage() {
  const result = spawnSync("gh", ["api", PACKAGE_API_PATH], {
    encoding: "utf8",
    maxBuffer: 10 * 1024 * 1024,
    windowsHide: true,
  });

  if (result.status === 0) {
    return { ok: true, body: result.stdout };
  }

  const failure = classifyGhApiFailure({
    stderr: result.stderr ?? "",
    errorCode: result.error?.code ?? "",
  });
  return { ok: false, ...failure };
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8" });
}

function preservePackageResponse(evidenceDir, rawBody, filename) {
  if (typeof rawBody !== "string" || rawBody.trim().length === 0) return;
  writeFileSync(resolve(evidenceDir, filename), `${rawBody.trim()}\n`, { encoding: "utf8" });
}

function createDiagnosticState({ expectedRepository, maxAttempts, now }) {
  return {
    policy: "private-and-linked-to-expected-repository",
    expectedRepository,
    maxAttempts,
    attempts: [],
    finalObservedVisibility: "unknown",
    finalObservedRepositoryLink: "unknown",
    failureClassification: null,
    timestamp: now(),
  };
}

function persistDiagnostic(evidenceDir, diagnostic) {
  diagnostic.timestamp = diagnostic.timestamp || new Date().toISOString();
  writeJson(resolve(evidenceDir, "package-post-publish-diagnostic.json"), diagnostic);
}

function recordAttempt(diagnostic, attempt) {
  diagnostic.attempts.push(attempt);
  diagnostic.finalObservedVisibility = attempt.visibility;
  diagnostic.finalObservedRepositoryLink = attempt.repositoryLink;
}

export async function verifyPackageMetadata({
  expectedRepository,
  evidenceDir,
  maxAttempts = 12,
  retryDelayMs = 5_000,
  fetchPackage = fetchGhcrPackage,
  sleep = (milliseconds) => new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds)),
  now = () => new Date().toISOString(),
  logger = console,
} = {}) {
  if (!expectedRepository || !evidenceDir) {
    throw new GhcrPostcheckError(
      "GHCR_POSTCHECK_CONFIG_ERROR required_value_missing",
      EXIT_CODES.invalidConfiguration,
      "invalid_configuration",
    );
  }

  mkdirSync(evidenceDir, { recursive: true });
  const diagnostic = createDiagnosticState({ expectedRepository, maxAttempts, now });

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const fetched = await fetchPackage();

    if (!fetched.ok) {
      const reason = sanitizeDiagnostic(fetched.reason, "api_unavailable");
      const observation = {
        attempt,
        apiState: "unavailable",
        visibility: "unknown",
        repositoryLink: "unknown",
        classification: reason,
        timestamp: now(),
      };
      recordAttempt(diagnostic, observation);

      if (!fetched.retryable) {
        diagnostic.failureClassification = "api_failure";
        persistDiagnostic(evidenceDir, diagnostic);
        logger.error(`GHCR_POSTCHECK_API_FAILURE attempt=${attempt} reason=${reason}`);
        throw new GhcrPostcheckError(
          "GHCR package API returned a terminal failure",
          EXIT_CODES.apiFailure,
          "api_failure",
        );
      }

      if (attempt < maxAttempts) {
        persistDiagnostic(evidenceDir, diagnostic);
        logger.warn(
          `GHCR_POSTCHECK_WAIT attempt=${attempt} api=${reason} visibility=unknown repository_link=unknown`,
        );
        await sleep(retryDelayMs);
        continue;
      }

      diagnostic.failureClassification = "api_consistency_timeout";
      persistDiagnostic(evidenceDir, diagnostic);
      logger.error(
        `GHCR_POSTCHECK_TIMEOUT attempts=${maxAttempts} api=${reason} visibility=unknown repository_link=unknown`,
      );
      throw new GhcrPostcheckError(
        "GHCR package API did not become available within the bounded retry window",
        EXIT_CODES.consistencyTimeout,
        "api_consistency_timeout",
      );
    }

    let packageData;
    try {
      packageData = JSON.parse(fetched.body);
    } catch {
      packageData = null;
    }

    if (!packageData || typeof packageData !== "object" || Array.isArray(packageData)) {
      const observation = {
        attempt,
        apiState: "malformed",
        visibility: "unknown",
        repositoryLink: "unknown",
        classification: "malformed_metadata",
        timestamp: now(),
      };
      recordAttempt(diagnostic, observation);

      if (attempt < maxAttempts) {
        persistDiagnostic(evidenceDir, diagnostic);
        logger.warn(
          `GHCR_POSTCHECK_WAIT attempt=${attempt} api=malformed visibility=unknown repository_link=unknown`,
        );
        await sleep(retryDelayMs);
        continue;
      }

      diagnostic.failureClassification = "malformed_metadata_timeout";
      persistDiagnostic(evidenceDir, diagnostic);
      logger.error(
        `GHCR_POSTCHECK_TIMEOUT attempts=${maxAttempts} api=malformed visibility=unknown repository_link=unknown`,
      );
      throw new GhcrPostcheckError(
        "GHCR package metadata remained malformed within the bounded retry window",
        EXIT_CODES.consistencyTimeout,
        "malformed_metadata_timeout",
      );
    }

    preservePackageResponse(evidenceDir, fetched.body, "package-post-publish-final.json");
    const rawVisibility = packageData.visibility;
    const rawRepository = packageData.repository?.full_name;
    const visibility = sanitizeDiagnostic(rawVisibility, "pending");
    const repositoryLink = sanitizeDiagnostic(rawRepository, "pending");
    const observation = {
      attempt,
      apiState: "success",
      visibility,
      repositoryLink,
      classification: "observed",
      timestamp: now(),
    };
    recordAttempt(diagnostic, observation);

    if (typeof rawVisibility === "string" && rawVisibility.length > 0 && rawVisibility !== "private") {
      observation.classification = "unsafe_visibility";
      diagnostic.failureClassification = "unsafe_visibility";
      persistDiagnostic(evidenceDir, diagnostic);
      logger.error(`GHCR_POSTCHECK_REFUSE visibility=${visibility}`);
      throw new GhcrPostcheckError(
        "GHCR package visibility is explicitly unsafe",
        EXIT_CODES.unsafeVisibility,
        "unsafe_visibility",
      );
    }

    if (typeof rawRepository === "string" && rawRepository.length > 0
      && rawRepository !== expectedRepository) {
      observation.classification = "wrong_repository";
      diagnostic.failureClassification = "wrong_repository";
      persistDiagnostic(evidenceDir, diagnostic);
      logger.error(`GHCR_POSTCHECK_REFUSE repository_link=${repositoryLink}`);
      throw new GhcrPostcheckError(
        "GHCR package is linked to an unexpected repository",
        EXIT_CODES.wrongRepository,
        "wrong_repository",
      );
    }

    if (rawVisibility === "private" && rawRepository === expectedRepository) {

      observation.classification = "verified";
      diagnostic.failureClassification = null;
      preservePackageResponse(evidenceDir, fetched.body, "package-post-publish.json");
      persistDiagnostic(evidenceDir, diagnostic);
      logger.log(
        `GHCR_POSTCHECK_PASS attempt=${attempt} visibility=private repository_link=${repositoryLink}`,
      );
      return { packageData, attempts: attempt, diagnostic };
    }

    observation.classification = "metadata_pending";
    if (attempt < maxAttempts) {
      persistDiagnostic(evidenceDir, diagnostic);
      logger.warn(
        `GHCR_POSTCHECK_WAIT attempt=${attempt} api=success visibility=${visibility} repository_link=${repositoryLink}`,
      );
      await sleep(retryDelayMs);
      continue;
    }

    diagnostic.failureClassification = "metadata_consistency_timeout";
    persistDiagnostic(evidenceDir, diagnostic);
    logger.error(
      `GHCR_POSTCHECK_TIMEOUT attempts=${maxAttempts} visibility=${visibility} repository_link=${repositoryLink}`,
    );
    throw new GhcrPostcheckError(
      "GHCR package metadata did not reach the required state within the bounded retry window",
      EXIT_CODES.consistencyTimeout,
      "metadata_consistency_timeout",
    );
  }

  throw new GhcrPostcheckError(
    "GHCR post-publish verification exhausted unexpectedly",
    EXIT_CODES.consistencyTimeout,
    "unexpected_exhaustion",
  );
}

async function main() {
  const maxAttempts = parseBoundedInteger(process.env.GHCR_POSTCHECK_MAX_ATTEMPTS ?? "12", "max_attempts", {
    minimum: 1,
    maximum: 100,
  });
  const retrySeconds = parseBoundedInteger(
    process.env.GHCR_POSTCHECK_RETRY_SECONDS ?? "5",
    "retry_seconds",
    { minimum: 0, maximum: 300 },
  );

  await verifyPackageMetadata({
    expectedRepository: process.env.EXPECTED_REPOSITORY,
    evidenceDir: process.env.EVIDENCE_DIR,
    maxAttempts,
    retryDelayMs: retrySeconds * 1_000,
  });
}

const invokedAsScript = process.argv[1]
  && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (invokedAsScript) {
  main().catch((error) => {
    if (error instanceof GhcrPostcheckError) {
      console.error(
        `GHCR_POSTCHECK_FAIL classification=${sanitizeDiagnostic(error.classification)} exit_code=${error.exitCode}`,
      );
      process.exitCode = error.exitCode;
      return;
    }
    console.error("GHCR_POSTCHECK_FAIL classification=unexpected_error exit_code=45");
    process.exitCode = EXIT_CODES.invalidConfiguration;
  });
}
