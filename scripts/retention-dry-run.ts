import { writeFile } from "node:fs/promises";
import { logger } from "@/lib/logging";
import {
  assertDryRunAllowed,
  configuredRetentionScope,
  missingRetentionCredentials,
} from "@/lib/retention/safety";
import { parseDryRunArgs, usage } from "@/lib/retention/dry-run-cli";

/**
 * Dry-run-only retention entrypoint.
 *
 * This is the operator-facing command for the preparation phase. It has no
 * destructive mode: `RETENTION_APPLY=1` aborts it, unsupported flags abort it,
 * and the underlying orchestration hard-codes `dryRun: true`.
 *
 * Configuration is validated **before** Prisma or any client module is
 * imported, so a misconfigured run fails without opening a socket. A dry-run
 * needs `DATABASE_URL` and `STORAGE_BUCKET` only; the object-storage endpoint and
 * key pair are apply-only and are not read here.
 */
async function main() {
  const args = parseDryRunArgs(process.argv.slice(2));
  if (args.help) {
    console.log(usage());
    return;
  }

  // Fail closed before importing anything that can open a connection.
  assertDryRunAllowed(process.env);
  const missing = missingRetentionCredentials(process.env, "dry_run");
  if (missing.length > 0) throw new Error(`RETENTION_CONFIGURATION_MISSING:${missing.join(",")}`);
  configuredRetentionScope(process.env);

  const [{ runRetentionDryRun }, { db }] = await Promise.all([
    import("@/lib/retention/dry-run"),
    import("@/lib/db"),
  ]);

  try {
    const report = await runRetentionDryRun();
    const summary = `${JSON.stringify(report, null, 2)}\n`;
    // Aggregate-only: counts, policy constants and fixed status strings.
    console.log(summary);
    if (args.summaryJsonPath) {
      await writeFile(args.summaryJsonPath, summary, "utf8");
      logger.info("retention.dry_run_summary_written", { path_configured: true });
    }
  } finally {
    await db.$disconnect();
  }
}

main().catch((error) => {
  // Classify without ever echoing a credential value or a connection string.
  const prismaCode = (error as { code?: unknown })?.code;
  const message = error instanceof Error ? error.message : "";
  const configurationMissing = message.startsWith("RETENTION_CONFIGURATION_MISSING");
  const safeCode = configurationMissing
    ? "RETENTION_CONFIGURATION_MISSING"
    : message.startsWith("RETENTION_")
      ? message.split(":")[0]
      : typeof prismaCode === "string" && /^P\d{4}$/.test(prismaCode)
        ? prismaCode
        : error instanceof Error
          ? error.name
          : "UNKNOWN";
  logger.error("retention.dry_run_failed", { error_code: safeCode });
  if (configurationMissing) {
    logger.error("retention.missing_configuration", {
      missing_variables: message.slice("RETENTION_CONFIGURATION_MISSING:".length),
    });
  }
  process.exitCode = 1;
});
