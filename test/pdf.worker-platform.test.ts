/**
 * R7C — architecture and libc selection for the PDF worker artifact.
 *
 * ## The defect these guard
 *
 * The artifact contract named its native packages literally: `@esbuild/linux-x64` and
 * `@napi-rs/canvas-linux-x64-gnu`. On x86_64 glibc that is right. On the owner's ARM64
 * Ubuntu VPS the worker image could not build (it demanded a package the repository does
 * not contain), and an emitted Alpine ARM64 standalone artifact shipped without its own
 * natives while the verifier still reported it complete. Both were confirmed before this
 * round; these tests exist so the second cannot recur silently.
 *
 * ## What is asserted, and what is deliberately not
 *
 * The selection *logic* is asserted here. Whether a selected package actually loads is a
 * runtime question, and it is answered by executing the child — the artifact smoke suite
 * does that, and no amount of metadata checking can substitute for it. So there is no
 * test here that a native addon "is valid"; there is a test that the wrong target is
 * rejected, which is the failure that was invisible.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";

import {
  SUPPORTED_CPUS,
  SUPPORTED_LIBCS,
  canvasPlatformName,
  detectLibc,
  esbuildPlatformName,
  platformArtifactPaths,
  platformPackageEntries,
  platformTraceGlobs,
  resolveTarget,
  supportedPlatformMatrix,
} from "../scripts/pdf-worker-platform.mjs";

const require = createRequire(import.meta.url);

/** The lockfile is the authority on which packages exist; the registry is not consulted. */
function lockfilePackages(): Set<string> {
  const lock = JSON.parse(readFileSync(new URL("../package-lock.json", import.meta.url), "utf8")) as {
    packages: Record<string, { os?: string[]; cpu?: string[]; libc?: string[]; optional?: boolean }>;
  };
  return new Set(Object.keys(lock.packages));
}

test("R7C-1: every supported combination names packages that actually exist in the lockfile", () => {
  // This is the check that would have caught the original ARM64 build failure: it does
  // not ask the registry, it asks the lockfile this repository ships. A selection that
  // names a package outside the lockfile cannot be installed by `npm ci` on any machine.
  const present = lockfilePackages();
  const matrix = supportedPlatformMatrix();
  assert.equal(matrix.length, SUPPORTED_CPUS.length * SUPPORTED_LIBCS.length, "the matrix must cover CPU x libc");
  for (const combination of matrix) {
    assert.ok(present.has(`node_modules/${combination.esbuild}`),
      `${combination.cpu}/${combination.libc} selects ${combination.esbuild}, which the lockfile does not contain`);
    assert.ok(present.has(`node_modules/${combination.canvas}`),
      `${combination.cpu}/${combination.libc} selects ${combination.canvas}, which the lockfile does not contain`);
  }
});

test("R7C-2: the four required combinations are exactly the ones supported", () => {
  // The task names four: Linux x64 GNU, x64 musl, ARM64 GNU, ARM64 musl. Asserting the
  // exact set stops a future change from quietly dropping one (an ARM64 musl gap would
  // reintroduce the Alpine defect) or adding an unproven fifth.
  assert.deepEqual(
    supportedPlatformMatrix().map((entry) => `${entry.cpu}/${entry.libc}`).sort(),
    ["arm64/glibc", "arm64/musl", "x64/glibc", "x64/musl"],
  );
});

test("R7C-3: esbuild is selected by CPU only — it has no libc axis", () => {
  // Verified against the binary itself: `ldd node_modules/@esbuild/linux-x64/bin/esbuild`
  // reports "not a dynamic executable", and the lockfile has no `@esbuild/linux-*-musl`.
  // Inventing a musl variant would fail the build on a package that does not exist, which
  // is the same class of bug as the original defect, with the axes swapped.
  assert.equal(esbuildPlatformName({ cpu: "x64", libc: "glibc" }), esbuildPlatformName({ cpu: "x64", libc: "musl" }));
  assert.equal(esbuildPlatformName({ cpu: "arm64", libc: "glibc" }), esbuildPlatformName({ cpu: "arm64", libc: "musl" }));
  assert.equal(esbuildPlatformName({ cpu: "arm64", libc: "musl" }), "@esbuild/linux-arm64");
  // And no selected esbuild name may contain a libc token.
  for (const combination of supportedPlatformMatrix()) {
    assert.doesNotMatch(combination.esbuild, /gnu|musl|glibc/u, `${combination.esbuild} must not carry a libc suffix`);
  }
});

test("R7C-4: canvas IS selected by libc, and the published suffix is gnu/musl not glibc", () => {
  // `gnu` is not a synonym the package authors chose for elegance: the packages are
  // literally `canvas-linux-x64-gnu`. Mapping `glibc` -> `gnu` at the last step keeps the
  // internal model npm's vocabulary while emitting names npm accepts.
  assert.equal(canvasPlatformName({ cpu: "arm64", libc: "glibc" }), "@napi-rs/canvas-linux-arm64-gnu");
  assert.equal(canvasPlatformName({ cpu: "arm64", libc: "musl" }), "@napi-rs/canvas-linux-arm64-musl");
  assert.equal(canvasPlatformName({ cpu: "x64", libc: "musl" }), "@napi-rs/canvas-linux-x64-musl");
  assert.notEqual(canvasPlatformName({ cpu: "x64", libc: "glibc" }), canvasPlatformName({ cpu: "x64", libc: "musl" }),
    "glibc and musl canvas packages are different binaries and must not collapse");
});

test("R7C-5: npm's libc vocabulary and the package suffix vocabulary are both accepted", () => {
  // `next.config.ts`, Dockerfiles and docs use both spellings interchangeably; an
  // resolver that accepted only one would fail confusingly at the point of use.
  assert.deepEqual(resolveTarget({ cpu: "arm64", libc: "gnu" }), { cpu: "arm64", libc: "glibc" });
  assert.deepEqual(resolveTarget({ cpu: "arm64", libc: "glibc" }), { cpu: "arm64", libc: "glibc" });
  assert.deepEqual(resolveTarget({ cpu: "arm64", libc: "musl" }), { cpu: "arm64", libc: "musl" });
  // Node's uname spellings too, since a CI script may pass `aarch64`/`x86_64`.
  assert.deepEqual(resolveTarget({ cpu: "aarch64", libc: "musl" }), { cpu: "arm64", libc: "musl" });
  assert.deepEqual(resolveTarget({ cpu: "x86_64", libc: "glibc" }), { cpu: "x64", libc: "glibc" });
});

test("R7C-6: an unsupported CPU or libc fails explicitly instead of falling back to x64", () => {
  // The requirement is explicit: unsupported combinations must produce errors. A silent
  // x64 fallback is precisely the behaviour that made the ARM64 defect invisible.
  for (const cpu of ["ia32", "ppc64", "s390x", "riscv64", ""]) {
    assert.throws(() => resolveTarget({ cpu, libc: "glibc" }), /Unsupported CPU/u, `cpu "${cpu}" must be rejected`);
  }
  for (const libc of ["uclibc", "bionic", ""]) {
    assert.throws(() => resolveTarget({ cpu: "x64", libc }), /Unsupported libc/u, `libc "${libc}" must be rejected`);
  }
  // And the rejection must name the supported values so the reader can act on it.
  assert.throws(() => resolveTarget({ cpu: "riscv64", libc: "glibc" }), /x64, arm64/u);
});

test("R7C-7: the running host is detected correctly (glibc vs musl)", () => {
  // `process.report.getReport().header.glibcVersionRuntime` is the documented discriminator
  // and needs no dependency. Cross-checked against the report rather than assumed.
  const report = process.report?.getReport() as { header?: { glibcVersionRuntime?: string } } | undefined;
  const expected = report?.header?.glibcVersionRuntime ? "glibc" : "musl";
  assert.equal(detectLibc(), expected);
  // The container this suite runs in is glibc; asserting that catches a silent flip to
  // musl detection that would send every default-target check to the wrong package.
  assert.equal(detectLibc(), "glibc", "this sandbox is glibc; a musl result means detection is broken");
});

test("R7C-8: the artifact paths and the trace globs describe the same two packages", () => {
  // These are the two places the original x64 literals appeared (verifier and tracing).
  // If they can disagree, they will: that is what happened. One derived source, two views.
  for (const combination of supportedPlatformMatrix()) {
    const target = { cpu: combination.cpu, libc: combination.libc };
    const paths = platformArtifactPaths(target);
    const globs = platformTraceGlobs(target);
    const entries = platformPackageEntries(target);
    assert.ok(globs.some((glob) => glob.includes(paths.esbuildPackage)),
      `${combination.cpu}/${combination.libc}: tracing does not include ${paths.esbuildPackage}`);
    assert.ok(globs.some((glob) => glob.includes(paths.canvasPackage)),
      `${combination.cpu}/${combination.libc}: tracing does not include ${paths.canvasPackage}`);
    assert.deepEqual(entries, [`node_modules/${paths.esbuildPackage}`, `node_modules/${paths.canvasPackage}`]);
    // The verifier must demand the esbuild *binary*, not the package metadata.
    assert.ok(paths.files.includes(`node_modules/${paths.esbuildPackage}/bin/esbuild`),
      "presence of the esbuild package does not imply its binary; the binary must be checked");
    assert.deepEqual(paths.executables, [`node_modules/${paths.esbuildPackage}/bin/esbuild`]);
  }
});

test("R7C-9: the build config literally enumerates every supported native package", () => {
  // `next.config.ts` cannot compute these: Next evaluates the config on the *build* host,
  // so a `process.arch` expression would bake that host into a cross-built artifact. The
  // literals are therefore written out, and this asserts they are exactly the matrix —
  // which is how a future arm64-only or x64-only list gets caught here rather than in CI.
  const config = readFileSync(new URL("../next.config.ts", import.meta.url), "utf8");
  const block = config.slice(
    config.indexOf("const PDF_WORKER_RUNTIME_PACKAGES = ["),
    config.indexOf("] as const;", config.indexOf("const PDF_WORKER_RUNTIME_PACKAGES = [")),
  );
  // Scoped packages carry a slash (`@esbuild/linux-x64`), so the capture must allow one
  // more path segment — a single-segment regex silently captures only the unscoped names
  // and would make this test pass while checking nothing.
  const globs = [...block.matchAll(/"\.\/node_modules\/(@[^/"]+\/[^/"]+|[^/@][^/"]*)\/\*\*\/\*"/gu)].map((match) => match[1]);
  for (const combination of supportedPlatformMatrix()) {
    assert.ok(globs.includes(combination.esbuild), `next.config.ts must trace ${combination.esbuild}`);
    assert.ok(globs.includes(combination.canvas), `next.config.ts must trace ${combination.canvas}`);
  }
  // And it must not trace a native package outside the matrix: `@esbuild/linux-ia32` or a
  // hypothetical musl esbuild would be a package that cannot be installed.
  const nativeGlobs = globs.filter((entry) => /^(@esbuild|@napi-rs\/canvas-linux)/u.test(entry));
  const allowed = new Set(supportedPlatformMatrix().flatMap((entry) => [entry.esbuild, entry.canvas]));
  for (const entry of nativeGlobs) {
    assert.ok(allowed.has(entry), `next.config.ts traces native package ${entry}, which is not in the supported matrix`);
  }
});

test("R7C-10: the verifier's target resolution prefers an explicit declaration over the host", () => {
  // A cross-build verifies an artifact for a target that is not its own machine. If the
  // host won that argument the check would silently pass on x64 while the artifact was
  // ARM64 — the exact defect. `declaredTarget` is asserted directly.
  const markers = require("../scripts/verify-pdf-worker-artifact.mjs") as {
    TARGET_MARKER: string;
    declaredTarget: (root: string, overrides?: { cpu?: string; libc?: string }) => { cpu: string; libc: string };
  };
  assert.equal(markers.TARGET_MARKER, "node_modules/.dip-pdf-worker-target.json");
  // Explicit overrides win outright.
  assert.deepEqual(markers.declaredTarget(process.cwd(), { cpu: "arm64", libc: "musl" }), { cpu: "arm64", libc: "musl" });
  // With no marker and no override, the running host is the answer — and only then.
  assert.deepEqual(markers.declaredTarget("/nonexistent-artifact-root", {}), { cpu: process.arch === "arm64" ? "arm64" : "x64", libc: "glibc" });
});

test("R7C-11: the target marker is what a cross-build verifies against, and it wins over the host", () => {
  // End-to-end on the real CLI entry point: write a marker for a foreign target into a
  // temporary root, then let the verifier resolve it with no flags. If the host won this
  // argument, a cross-built ARM64 artifact would be checked for x64 packages and reported
  // complete — the ARM64 defect, reached from the other direction.
  const root = mkdtempSync(join(tmpdir(), "dip-target-"));
  try {
    // `write-pdf-worker-target.mjs` is the same helper the Dockerfile runs, so this
    // exercises the shipped path rather than a reimplementation of it.
    execFileSync(process.execPath, [join(process.cwd(), "scripts/write-pdf-worker-target.mjs"), `--root=${root}`, "--cpu=arm64", "--libc=musl"], { stdio: "pipe" });
    const written = JSON.parse(readFileSync(join(root, "node_modules/.dip-pdf-worker-target.json"), "utf8"));
    assert.deepEqual(written, { cpu: "arm64", libc: "musl" });

    const verifier = require("../scripts/verify-pdf-worker-artifact.mjs") as {
      declaredTarget: (root: string, overrides?: Record<string, string>) => { cpu: string; libc: string };
    };
    assert.deepEqual(verifier.declaredTarget(root), { cpu: "arm64", libc: "musl" });
    // An explicit flag still wins over the artifact's own marker.
    assert.deepEqual(verifier.declaredTarget(root, { cpu: "x64", libc: "glibc" }), { cpu: "x64", libc: "glibc" });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("R7C-12: the helper refuses an unsupported Docker architecture instead of guessing", () => {
  // `TARGETARCH` is BuildKit's, and it uses `amd64`/`arm64` — a different vocabulary from
  // npm's. An unmapped value must fail rather than silently produce an x64 marker.
  assert.throws(
    () => execFileSync(process.execPath, [join(process.cwd(), "scripts/write-pdf-worker-target.mjs"), `--root=${tmpdir()}`, "--cpu=riscv64"], { stdio: "pipe" }),
    (error: unknown) => (error as { status?: number }).status === 2,
    "an unsupported CPU must exit 2",
  );
});
