/**
 * Argument parsing for the dry-run-only entrypoint.
 *
 * Deliberately tiny and closed: the dry-run command accepts exactly one option
 * and rejects every other flag. There is no `--apply`, and an attempt to pass
 * one must fail loudly rather than be ignored, so an operator can never believe
 * a destructive mode ran when it did not.
 */

export type DryRunCliArguments = {
  /** Optional path for the aggregate JSON report. */
  summaryJsonPath?: string;
  help: boolean;
};

const USAGE = "Usage: npm run retention:dry-run -- [--summary-json=<path>]";

export function usage(): string {
  return USAGE;
}

/**
 * Parse the entrypoint arguments.
 *
 * Throws `RETENTION_DRY_RUN_ARGUMENT_REJECTED:<argument>` for anything that is
 * not an explicitly supported, non-destructive option.
 */
export function parseDryRunArgs(argv: readonly string[]): DryRunCliArguments {
  const parsed: DryRunCliArguments = { help: false };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];

    if (argument === "--help" || argument === "-h") {
      parsed.help = true;
      continue;
    }

    if (argument === "--summary-json") {
      const value = argv[index + 1];
      if (!value || value.startsWith("-")) throw new Error("RETENTION_DRY_RUN_ARGUMENT_REJECTED:--summary-json");
      parsed.summaryJsonPath = value;
      index += 1;
      continue;
    }

    if (argument.startsWith("--summary-json=")) {
      const value = argument.slice("--summary-json=".length);
      if (!value) throw new Error("RETENTION_DRY_RUN_ARGUMENT_REJECTED:--summary-json");
      parsed.summaryJsonPath = value;
      continue;
    }

    // Includes `--apply`, `--force`, `--yes`, positional paths and typos.
    throw new Error(`RETENTION_DRY_RUN_ARGUMENT_REJECTED:${argument}`);
  }

  return parsed;
}
