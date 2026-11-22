import { resolve } from "node:path";
import { run } from "node:test";
import { spec } from "node:test/reporters";
import { pathToFileURL } from "node:url";
import pg from "pg";

export const REQUIRED_RLS_TEST_FILES = Object.freeze([
  "test/storage-objects.rls.integration.test.mjs",
  "test/rls.integration.test.mjs",
  "test/auth-identity.rls.integration.test.mjs",
  "test/workflow.rls.integration.test.mjs",
  "test/phase9a.rls.integration.test.mjs",
  "test/phase9b.rls.integration.test.mjs",
  "test/retention.rls.integration.test.mjs",
  "test/feature-flags.permissions.integration.test.mjs",
  "test/pr0-server-tool-access.integration.test.ts",
]);

const ALLOWED_DISPOSABLE_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]", "postgres"]);

/**
 * @param {Record<string, string | undefined>} [env]
 */
export function validateIsolatedRlsGateEnv(env = process.env) {
  const requiredVars = [
    "DIP_RLS_TEST_OWNER_URL",
    "DIP_RLS_TEST_DATABASE_URL",
    "DIP_RETENTION_TEST_DATABASE_URL",
  ];

  for (const name of requiredVars) {
    const raw = env[name]?.trim();
    if (!raw) {
      throw new Error(`RLS_GATE_ENV_MISSING: ${name} is required; refusing to skip RLS security gate.`);
    }
    let parsed;
    try {
      parsed = new URL(raw);
    } catch {
      throw new Error(`RLS_GATE_ENV_INVALID: ${name} is not a valid PostgreSQL connection URL.`);
    }
    if (parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:") {
      throw new Error(`RLS_GATE_ENV_INVALID: ${name} must use postgres:// or postgresql:// protocol.`);
    }
    const host = parsed.hostname.toLowerCase();
    if (host.includes("neon.tech") || host.includes("supabase.co") || host.includes("amazonaws.com")) {
      throw new Error(`RLS_GATE_FORBIDDEN_HOST: ${name} points to non-disposable external host (${host}).`);
    }
    if (!ALLOWED_DISPOSABLE_HOSTS.has(host)) {
      throw new Error(
        `RLS_GATE_FORBIDDEN_HOST: ${name} must target an isolated disposable local/container host, got (${host}).`,
      );
    }
  }

  return {
    ownerUrl: env.DIP_RLS_TEST_OWNER_URL.trim(),
    runtimeUrl: env.DIP_RLS_TEST_DATABASE_URL.trim(),
    retentionUrl: env.DIP_RETENTION_TEST_DATABASE_URL.trim(),
    requirePg18: env.DIP_REQUIRE_PG18 === "1",
  };
}

export function evaluateRlsTestCounts(counts) {
  if (counts.failed > 0) {
    throw new Error(`RLS_GATE_TEST_FAILURE: ${counts.failed} test(s) failed.`);
  }
  if (counts.skipped > 0) {
    throw new Error(
      `RLS_GATE_SKIPPED_FORBIDDEN: ${counts.skipped} test(s) were skipped or marked todo; fail-closed gate requires 0 skips.`,
    );
  }
  if (counts.passed === 0) {
    throw new Error("RLS_GATE_EMPTY_SUITE: 0 tests executed.");
  }
}

async function verifyDatabasePosture({ ownerUrl, requirePg18 }) {
  const client = new pg.Client({ connectionString: ownerUrl });
  await client.connect();
  try {
    const versionResult = await client.query(
      "SELECT current_setting('server_version') AS server_version, current_setting('server_version_num')::int AS server_version_num",
    );
    const { server_version: serverVersion, server_version_num: serverVersionNum } = versionResult.rows[0];
    if (requirePg18 && Number(serverVersionNum) < 180000) {
      throw new Error(
        `RLS_GATE_PG_VERSION_MISMATCH: expected PostgreSQL >= 18 (server_version_num >= 180000), got ${serverVersion} (${serverVersionNum}).`,
      );
    }

    const roles = await client.query(
      `SELECT rolname, rolsuper, rolbypassrls, rolcanlogin
         FROM pg_roles
        WHERE rolname IN ('dip_app', 'dip_retention')
        ORDER BY rolname`,
    );
    if (roles.rowCount !== 2) {
      throw new Error("RLS_GATE_ROLES_MISSING: both dip_app and dip_retention must exist before running RLS suite.");
    }
    for (const row of roles.rows) {
      if (row.rolsuper || row.rolbypassrls || !row.rolcanlogin) {
        throw new Error(
          `RLS_GATE_ROLE_UNSAFE: ${row.rolname} has unsafe flags (rolsuper=${row.rolsuper}, rolbypassrls=${row.rolbypassrls}, rolcanlogin=${row.rolcanlogin}).`,
        );
      }
    }

    process.stdout.write(
      `[rls-security-gate] Verified PostgreSQL ${serverVersion} (${serverVersionNum}) and least-privilege roles dip_app, dip_retention.\n`,
    );
  } finally {
    await client.end();
  }
}

export async function runRlsSecurityGate(env = process.env) {
  const config = validateIsolatedRlsGateEnv(env);
  await verifyDatabasePosture(config);

  const files = REQUIRED_RLS_TEST_FILES.map((relPath) => resolve(process.cwd(), relPath));
  const counts = { passed: 0, failed: 0, skipped: 0 };

  const stream = run({
    files,
    concurrency: 1,
    execArgv: ["--import", "./scripts/node-platform-compat.mjs", "--import", "tsx"],
  });
  stream.on("test:pass", (event) => {
    if (event.skip !== undefined || event.todo !== undefined) {
      counts.skipped += 1;
    } else if (event.details?.type !== "suite") {
      counts.passed += 1;
    }
  });
  stream.on("test:fail", (event) => {
    if (event.details?.type !== "suite") {
      counts.failed += 1;
    }
  });

  const reporter = stream.compose(spec);
  reporter.pipe(process.stdout);

  await new Promise((resolveStream, rejectStream) => {
    reporter.on("end", resolveStream);
    reporter.on("error", rejectStream);
  });

  process.stdout.write(
    `[rls-security-gate] Summary: passed=${counts.passed} failed=${counts.failed} skipped=${counts.skipped}\n`,
  );
  evaluateRlsTestCounts(counts);
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isMain) {
  runRlsSecurityGate().catch((error) => {
    process.stderr.write(`[rls-security-gate] ${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  });
}
