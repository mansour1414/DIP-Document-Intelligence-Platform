/**
 * Which native packages the bounded PDF worker needs, for *which* target.
 *
 * ## Why this file exists
 *
 * The worker artifact contains three native or platform-bound dependencies:
 *
 *   - `esbuild`, which `tsx` spawns to compile the child on the fly;
 *   - `@napi-rs/canvas`, which renders the Arabic appearance and its bundled font;
 *   - `@fontsource/noto-sans-arabic`, which is pure data (no platform axis).
 *
 * Before this module, the platform package names were written out literally in
 * `next.config.ts` and in `scripts/verify-pdf-worker-artifact.mjs` as
 * `@esbuild/linux-x64` and `@napi-rs/canvas-linux-x64-gnu`. That is correct on an
 * x86_64 glibc host and wrong everywhere else: an ARM64 worker image could not
 * build, and an emitted ARM64 standalone artifact silently lacked its own native
 * packages. Both failures were confirmed independently before this change.
 *
 * ## The two axes are independent
 *
 * This is the part that is easy to get wrong, so it is stated explicitly:
 *
 *   - **CPU** (`x64` / `arm64`) always selects a package.
 *   - **libc** selects a package *only for canvas*.
 *
 * `esbuild` publishes one static, libc-independent binary per CPU — verified
 * against the lockfile, which contains `@esbuild/linux-x64` and
 * `@esbuild/linux-arm64` and no musl variants at all, and against the binary
 * itself (`ldd` reports "not a dynamic executable"). `@napi-rs/canvas` publishes
 * real per-libc binaries (`gnu` / `musl`), which is why Alpine and Debian need
 * different packages. Treating libc as a single global axis would therefore
 * invent esbuild packages that do not exist; treating it as irrelevant would
 * ship a glibc canvas to Alpine, where it cannot load.
 *
 * ## Selection is not installation
 *
 * Selecting a package here says only what the artifact must *contain*. Whether
 * it actually loads is a runtime question, and the artifact smoke test answers it
 * by executing the child against the real bytes. A package whose metadata is
 * present but whose binary is wrong still fails there, which is the only check
 * that can see the difference.
 */

/** Linux CPU values npm uses in `os`/`cpu` fields. */
export const SUPPORTED_CPUS = ["x64", "arm64"];

/** Linux libc values npm uses in the `libc` field. */
export const SUPPORTED_LIBCS = ["glibc", "musl"];

/**
 * Map Node's `process.arch` onto npm's CPU vocabulary.
 *
 * They agree for the two supported values, but the mapping is explicit rather
 * than assumed so an unsupported host fails with a clear message instead of
 * producing `@esbuild/linux-${arch}` for an arch that has no such package.
 */
const NODE_ARCH_TO_CPU = { x64: "x64", arm64: "arm64" };

/**
 * Detect the libc of the *running* process.
 *
 * `process.report.getReport().header.glibcVersionRuntime` is present on glibc and
 * absent on musl — that is the documented discriminator and it needs no
 * dependency. A host that reports neither is not something we can classify, and
 * guessing "glibc" here is exactly how an Alpine image ends up with a Debian
 * binary, so it throws instead.
 */
export function detectLibc() {
  const report = typeof process.report?.getReport === "function" ? process.report.getReport() : undefined;
  const glibc = report?.header?.glibcVersionRuntime;
  if (glibc) return "glibc";
  // musl exposes no version marker of this kind. Node built for musl simply lacks
  // the field, so an absent field on Linux is musl — but only for Linux, because
  // on another OS the field is also absent for unrelated reasons.
  if (process.platform === "linux") return "musl";
  throw new Error(`Cannot determine the C library on platform "${process.platform}"; the PDF worker artifact targets Linux only.`);
}

/**
 * Normalise a target, or explain why it is not supported.
 *
 * Accepts npm's libc spelling (`glibc`/`musl`) and the spelling the package names
 * themselves use (`gnu`/`musl`), because both appear in this repository's
 * comments and either is unambiguous. An unsupported CPU or libc is a hard error:
 * the task's requirement is that unsupported combinations fail explicitly rather
 * than fall back to x64.
 */
/** @param {{ cpu?: string, libc?: string }} [target] */
export function resolveTarget(target = {}) {
  const rawCpu = target.cpu ?? NODE_ARCH_TO_CPU[process.arch];
  const cpu = rawCpu === "x86_64" ? "x64" : rawCpu === "aarch64" ? "arm64" : rawCpu;
  if (!SUPPORTED_CPUS.includes(cpu)) {
    throw new Error(`Unsupported CPU "${String(rawCpu)}" for the PDF worker artifact. Supported: ${SUPPORTED_CPUS.join(", ")}.`);
  }
  const rawLibc = target.libc ?? detectLibc();
  const libc = rawLibc === "gnu" ? "glibc" : rawLibc;
  if (!SUPPORTED_LIBCS.includes(libc)) {
    throw new Error(`Unsupported libc "${String(rawLibc)}" for the PDF worker artifact. Supported: ${SUPPORTED_LIBCS.join(", ")}.`);
  }
  return { cpu, libc };
}

/**
 * The canvas package suffix for a target.
 *
 * The published names use `gnu`, not `glibc`: `canvas-linux-x64-gnu`. The
 * `{ cpu, libc }` model stays npm's, and only the last mile is spelled npm's way.
 *
 * @param {{ cpu: string, libc: string }} target
 */
export function canvasPlatformName({ cpu, libc }) {
  return `@napi-rs/canvas-linux-${cpu}-${libc === "glibc" ? "gnu" : "musl"}`;
}

/**
 * The esbuild platform package for a target. CPU only — see the header.
 *
 * @param {{ cpu: string, libc?: string }} target
 */
export function esbuildPlatformName({ cpu }) {
  return `@esbuild/linux-${cpu}`;
}

/**
 * Every platform-bound path the artifact must contain, for one target.
 *
 * Returned as `node_modules/...` paths with no leading `./`, matching how both
 * the verifier and `next.config.ts` already express them.
 *
 * `esbuild` is listed by its *binary*, not its `package.json`: with the package
 * installed but the executable absent esbuild reports "no native binary
 * executable", and a presence check on the metadata cannot see that.
 */
/** @param {{ cpu?: string, libc?: string }} [target] */
export function platformArtifactPaths(target) {
  const resolved = resolveTarget(target);
  const esbuildJar = esbuildPlatformName(resolved);
  const canvasJar = canvasPlatformName(resolved);
  return {
    target: resolved,
    /** Must exist. */
    files: [`node_modules/${esbuildJar}/bin/esbuild`, `node_modules/${canvasJar}/package.json`],
    /** Must exist *and* carry an execute bit. */
    executables: [`node_modules/${esbuildJar}/bin/esbuild`],
    /** The canvas native addon itself, checked as a glob because the filename is versioned. */
    canvasBinding: `node_modules/${canvasJar}`,
    esbuildPackage: esbuildJar,
    canvasPackage: canvasJar,
  };
}

/**
 * Trace globs for `next.config.ts`, for one target.
 *
 * The same two packages as `platformArtifactPaths`, in the `./node_modules/**\/*`
 * form the tracing config uses. Keeping both derivations here means the build and
 * the verifier read one list, which is the drift the R6.4 route-key bug came from.
 */
/** @param {{ cpu?: string, libc?: string }} [target] */
export function platformTraceGlobs(target) {
  const resolved = resolveTarget(target);
  return [`./node_modules/${esbuildPlatformName(resolved)}/**/*`, `./node_modules/${canvasPlatformName(resolved)}/**/*`];
}

/**
 * The same two packages as plain `node_modules/...` entries.
 *
 * `next.config.ts` must carry one literal string per platform package rather than
 * a computed glob, because the config is evaluated at build time on whichever
 * machine runs the build and a computed value would bake that machine's CPU into
 * an artifact that might be built for another. The literals are therefore written
 * out, and `test/pdf.worker-platform.test.ts` asserts they are exactly this
 * function's output — so the build cannot silently keep tracing x64 while the
 * verifier demands arm64, which is the second defect this round fixes.
 */
/** @param {{ cpu?: string, libc?: string }} [target] */
export function platformPackageEntries(target) {
  const resolved = resolveTarget(target);
  return [`node_modules/${esbuildPlatformName(resolved)}`, `node_modules/${canvasPlatformName(resolved)}`];
}

/** The four combinations this repository supports, for matrix assertions and docs. */
export function supportedPlatformMatrix() {
  return SUPPORTED_CPUS.flatMap((cpu) => SUPPORTED_LIBCS.map((libc) => {
    const target = { cpu, libc };
    return {
      cpu,
      libc,
      esbuild: esbuildPlatformName(target),
      canvas: canvasPlatformName(target),
    };
  }));
}
