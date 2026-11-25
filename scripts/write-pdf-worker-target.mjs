#!/usr/bin/env node
/**
 * Record which target a PDF worker artifact was built for.
 *
 * ## Why a file instead of a flag
 *
 * A cross-build (`docker buildx --platform linux/arm64`, or `next build` under an ARM64
 * builder) produces an artifact whose natives are selected for the *output* platform,
 * while `process.arch` inside the build still reports the *builder*. Verifying such an
 * artifact from the build host therefore checks the wrong packages and can report an
 * ARM64 tree "complete" while its own natives are absent — which is exactly the defect
 * this round fixes.
 *
 * Writing the target next to the artifact's dependencies means the verifier can read the
 * intent from the artifact itself, with no flag to forget and no environment variable to
 * leak between steps.
 *
 * Usage:
 *   node scripts/write-pdf-worker-target.mjs --root <artifact-root> --cpu arm64 --libc glibc
 *   TARGETARCH=arm64 node scripts/write-pdf-worker-target.mjs --root /app
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { TARGET_MARKER } from "./verify-pdf-worker-artifact.mjs";
import { resolveTarget } from "./pdf-worker-platform.mjs";

/** Docker's `TARGETARCH` names differ from npm's `cpu` values for exactly one of them. */
const DOCKER_ARCH = { amd64: "x64", arm64: "arm64" };

const args = process.argv.slice(2);
const flags = {};
for (let index = 0; index < args.length; index += 1) {
  const match = /^--(root|cpu|libc)=(.*)$/u.exec(args[index]);
  if (match) { flags[match[1]] = match[2]; continue; }
  if (/^--(root|cpu|libc)$/u.test(args[index])) { flags[args[index].slice(2)] = args[index + 1]; index += 1; }
}

// An explicit flag wins; then BuildKit's own; then the running process.
const rawCpu = flags.cpu ?? (process.env.TARGETARCH ? DOCKER_ARCH[process.env.TARGETARCH] : undefined) ?? process.arch;
if (process.env.TARGETARCH && !DOCKER_ARCH[process.env.TARGETARCH] && !flags.cpu) {
  console.error(`Unsupported TARGETARCH "${process.env.TARGETARCH}". Supported: ${Object.keys(DOCKER_ARCH).join(", ")}.`);
  process.exit(2);
}
let target;
try {
  target = resolveTarget({ cpu: rawCpu, ...(flags.libc ? { libc: flags.libc } : {}) });
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(2);
}

const root = resolve(flags.root ?? process.cwd());
const marker = join(root, TARGET_MARKER);
mkdirSync(dirname(marker), { recursive: true });
writeFileSync(marker, `${JSON.stringify(target, null, 2)}\n`);
console.log(`PDF worker target recorded: ${target.cpu}/${target.libc} -> ${marker}`);
