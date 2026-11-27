/**
 * R7C.3.1 — the artifact runtime check must detect the failures it was built for.
 *
 * ## The two defects these guard
 *
 * 1. **R7C.1 packaging.** The emitted image contained
 *    `/app/node_modules/@prisma/adapter-pg/dist/index.js` — the file was there, and the
 *    require stack pointed at it — yet loading it raised `MODULE_NOT_FOUND:
 *    @prisma/driver-adapter-utils`. The package had been copied by a file glob, which does
 *    not know about dependencies, so its own `require()` had nowhere to resolve.
 *
 * 2. **R7C.3 verifier.** The check that loads `@prisma/client` returned `{ path }` and the
 *    construction check then tried to `new` that object, so a perfectly good artifact
 *    failed with "@prisma/client did not yield a constructor". CI run `45750694222` shows
 *    every packaging check passing and only construction and disconnect failing, which is
 *    exactly the signature of a verifier bug rather than a packaging one.
 *
 * ## What is real here, and what is not
 *
 * Every package copied below is the repository's own, at its locked version. So tests 1–5
 * exercise genuine `@prisma/adapter-pg`, genuine `pg`, and genuine Node resolution —
 * including the nested `postgres-array@2` under `pg-types` that differs from the hoisted
 * `postgres-array@3`.
 *
 * **`@prisma/client` is the exception, and it matters.** A real one requires a *generated*
 * `.prisma/client`, and `prisma generate` is TLS-blocked in this sandbox: it fetches the
 * schema engine from `binaries.prisma.sh` before it generates anything. So the client tests
 * below use a deliberately synthetic module that exports a class with a `$disconnect` —
 * and they assert only the **verifier's control flow**, never that Prisma works. The
 * constructor-versus-metadata bug is a control-flow bug, so this is the right level to test
 * it at, but it is not evidence about the real client.
 *
 * The genuine acceptance gate is untouched: CI and the Dockerfile run this same script
 * against a real generated client. Nothing here substitutes for that.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ROOT = process.cwd();
const HARNESS = join(ROOT, "scripts/verify-prisma-artifact-runtime.mjs");

/**
 * How long the verifier may run before the test fails it.
 *
 * It must outlive the verifier's own 5s leak watchdog, because a leak is reported *by* the
 * verifier and this bound is only the backstop for a true hang. If the event loop stays
 * alive after `$disconnect()`, the process never exits and this timeout is what turns that
 * into a failure instead of a stuck CI job.
 */
const EXTERNAL_TIMEOUT_MS = 20_000;

/** Packages copied into every synthetic artifact: the real adapter and pg closure. */
const CLOSURE = [
  "@prisma/adapter-pg",
  "@prisma/driver-adapter-utils",
  "@prisma/debug",
  "pg",
  "pg-connection-string",
  "pg-int8",
  "pg-pool",
  "pg-protocol",
  "pg-types",
  "pgpass",
  "postgres-array",
  "postgres-bytea",
  "postgres-date",
  "postgres-interval",
  "split2",
  "xtend",
];

interface Report {
  result: string;
  checks: Array<{ check: string; ok: boolean; detail?: unknown; error?: string }>;
  failed?: string[];
}

/**
 * A synthetic `@prisma/client` that mimics the *shape* of a generated one.
 *
 * This exists solely to exercise the verifier's control flow, which a real client cannot do
 * here because generation is TLS-blocked. It records each construction and each
 * `$disconnect()` on `globalThis` so the test can assert the same client that was built is
 * the one torn down — the property the R7C.3 bug destroyed.
 *
 * It is written into a throwaway directory. It is never used by CI, the Dockerfile, or any
 * acceptance claim.
 */
function writeSyntheticClient(root: string, options: { leakHandle?: boolean } = {}): void {
  const dir = join(root, "node_modules/@prisma/client");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "@prisma/client", version: "0.0.0-synthetic", main: "index.js" }));
  writeFileSync(
    join(dir, "index.js"),
    `
// SYNTHETIC — verifier control-flow test only. Not Prisma.
class PrismaClient {
  constructor(config) {
    if (!config || typeof config !== "object") throw new Error("expected a config object");
    if (!config.adapter) throw new Error("expected an adapter, which is the PrismaPg instance");
    globalThis.__syntheticConstructed = (globalThis.__syntheticConstructed || 0) + 1;
    globalThis.__syntheticClient = this;
    this.disconnected = false;
  }
  async $disconnect() {
    this.disconnected = true;
    globalThis.__syntheticDisconnected = this;
    ${options.leakHandle ? 'setInterval(() => {}, 1000); // deliberately keeps the loop alive' : ""}
  }
}
module.exports = { PrismaClient };
`,
  );
  // The generated-client directory the verifier looks for. Its contents are irrelevant to
  // these tests; presence is what the check asserts.
  mkdirSync(join(root, "node_modules/.prisma/client"), { recursive: true });
  writeFileSync(join(root, "node_modules/.prisma/client/default.js"), "// SYNTHETIC\nmodule.exports = {};\n");
}

/**
 * Build a throwaway artifact containing the real packages.
 *
 * `nested` reproduces the lockfile's second, older `postgres-array` under `pg-types`.
 */
function makeArtifact(options: { nested?: boolean; client?: "synthetic" | "none"; leakHandle?: boolean } = {}): string {
  const { nested = true, client = "none", leakHandle = false } = options;
  const root = mkdtempSync(join(tmpdir(), "dip-prisma-artifact-"));
  for (const name of CLOSURE) {
    const from = join(ROOT, "node_modules", name);
    if (!existsSync(from)) continue;
    cpSync(from, join(root, "node_modules", name), { recursive: true });
  }
  if (nested) {
    cpSync(join(ROOT, "node_modules/pg-types/node_modules/postgres-array"), join(root, "node_modules/pg-types/node_modules/postgres-array"), { recursive: true });
  }
  if (client === "synthetic") writeSyntheticClient(root, { leakHandle });
  return root;
}

/**
 * Run the verifier under a bounded external timeout.
 *
 * `execFileSync` with `timeout` kills the child and throws, which is what turns a leaked
 * handle into a test failure. Nothing here relies on the verifier terminating itself.
 */
function runHarness(root: string): { status: number; report: Report; timedOut: boolean } {
  const started = Date.now();
  try {
    const stdout = execFileSync(process.execPath, [HARNESS, root], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: EXTERNAL_TIMEOUT_MS,
      killSignal: "SIGKILL",
    });
    return { status: 0, report: JSON.parse(stdout), timedOut: false };
  } catch (error) {
    const failure = error as { status?: number; stdout?: string; signal?: string; killed?: boolean };
    const timedOut = failure.signal === "SIGKILL" || Boolean(failure.killed) || Date.now() - started >= EXTERNAL_TIMEOUT_MS - 250;
    return { status: failure.status ?? -1, report: JSON.parse(failure.stdout ?? "{}") as Report, timedOut };
  }
}

const failedEntries = (report: Report) => report.checks.filter((entry) => !entry.ok);
const findCheck = (report: Report, prefix: string) => report.checks.find((entry) => entry.check.startsWith(prefix));

// ---------------------------------------------------------------------------------------
// Packaging closure (the R7C.1 defect).
// ---------------------------------------------------------------------------------------

test("R7C.3.1-1: the adapter's own requires resolve against a real, complete artifact", () => {
  const root = makeArtifact();
  try {
    const { report } = runHarness(root);
    const adapterCheck = findCheck(report, "@prisma/adapter-pg loads");
    assert.equal(adapterCheck?.ok, true, `the adapter must load; failures: ${JSON.stringify(failedEntries(report))}`);
    const requires = (adapterCheck?.detail as { requires: Record<string, string> }).requires;
    assert.ok(requires["@prisma/driver-adapter-utils"]?.startsWith(root),
      "@prisma/driver-adapter-utils must resolve inside the artifact");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("R7C.3.1-2: removing @prisma/driver-adapter-utils reproduces the exact production failure", () => {
  // The negative regression for the real defect: everything else intact, only the one
  // orphaned dependency removed — precisely the state a file-glob copy produces.
  const root = makeArtifact();
  try {
    rmSync(join(root, "node_modules/@prisma/driver-adapter-utils"), { recursive: true, force: true });
    const { status, report } = runHarness(root);
    assert.equal(status, 1, "the check must fail when a required dependency is absent");
    assert.equal(report.result, "FAIL");
    const adapterFailure = failedEntries(report).find((entry) => entry.check.startsWith("@prisma/adapter-pg loads"));
    assert.match(String(adapterFailure?.error), /@prisma\/driver-adapter-utils/u);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("R7C.3.1-3: removing pg is detected, not silently tolerated", () => {
  const root = makeArtifact();
  try {
    rmSync(join(root, "node_modules/pg"), { recursive: true, force: true });
    const { status, report } = runHarness(root);
    assert.equal(status, 1);
    assert.ok(failedEntries(report).some((entry) => /\bpg\b/u.test(String(entry.error))), JSON.stringify(failedEntries(report)));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------------------
// Nested dependency layout (the R7C.3.1 Task 2 false positive).
// ---------------------------------------------------------------------------------------

test("R7C.3.1-4: the nested postgres-array@2 and hoisted @3 are both required, separate, and correct", () => {
  const root = makeArtifact();
  try {
    const { report } = runHarness(root);
    const nestedCheck = findCheck(report, "the nested postgres-array@2 and hoisted postgres-array@3");
    assert.equal(nestedCheck?.ok, true, `nested layout must be verified; failures: ${JSON.stringify(failedEntries(report))}`);
    const detail = nestedCheck?.detail as { nested: string; hoisted: string; nestedDir: string; hoistedDir: string };
    assert.equal(detail.nested.split(".")[0], "2");
    assert.equal(detail.hoisted.split(".")[0], "3");
    assert.notEqual(detail.nestedDir, detail.hoistedDir);
    assert.ok(detail.nestedDir.includes("pg-types/node_modules/postgres-array"), detail.nestedDir);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("R7C.3.1-5: a flattened tree is REJECTED, not reported as acceptable", () => {
  // The false positive that shipped in R7C.3: when both resolve to one directory the check
  // returned success with a note. A flattened tree hands `pg-types` major 3 when it
  // requires ~2.0.0, and nothing fails until a result row is parsed.
  const root = makeArtifact({ nested: false });
  try {
    rmSync(join(root, "node_modules/pg-types/node_modules"), { recursive: true, force: true });
    const { status, report } = runHarness(root);
    const nestedCheck = findCheck(report, "the nested postgres-array@2 and hoisted postgres-array@3");
    assert.equal(nestedCheck?.ok, false, "a single shared copy must fail the check");
    assert.match(String(nestedCheck?.error), /flattened|major 2/u,
      `the failure must explain the layout problem, got: ${nestedCheck?.error}`);
    assert.equal(status, 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("R7C.3.1-6: a missing nested copy is not treated as success", () => {
  // `pg-types` ships its own `node_modules`, so copying the package carries the nested copy
  // with it. Delete the directory outright to model a tree where the nested copy was never
  // emitted at all (the packaging failure), rather than one where it was flattened.
  const root = makeArtifact();
  rmSync(join(root, "node_modules/pg-types/node_modules"), { recursive: true, force: true });
  try {
    const { status, report } = runHarness(root);
    assert.equal(status, 1);
    assert.equal(findCheck(report, "the nested postgres-array@2 and hoisted postgres-array@3")?.ok, false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------------------
// Verifier control flow (the R7C.3.1 constructor/metadata bug).
// ---------------------------------------------------------------------------------------

test("R7C.3.1-7: construction uses the real constructor, and disconnects the SAME client", () => {
  // This is the regression for CI 45750694222. The load check validated `PrismaClient` was a
  // function and then returned `{ path }`, so the construction check `new`'d metadata and
  // reported "@prisma/client did not yield a constructor" on a good artifact.
  //
  // The synthetic client is a stand-in for the generated one — see the file header. What it
  // proves is the control flow: the value handed to `new` is the exported class, and the
  // object torn down is the object built.
  const root = makeArtifact({ client: "synthetic" });
  try {
    const { status, report } = runHarness(root);
    assert.equal(findCheck(report, "@prisma/client loads")?.ok, true, JSON.stringify(failedEntries(report)));
    const construction = findCheck(report, "PrismaPg and PrismaClient construct");
    assert.equal(construction?.ok, true,
      `construction must succeed when the client exports a constructor; got: ${construction?.error}`);
    const disconnected = findCheck(report, "$disconnect resolves");
    assert.equal(disconnected?.ok, true, `disconnect must succeed; got: ${disconnected?.error}`);
    assert.deepEqual((disconnected?.detail as { disconnectedSameClient: boolean }).disconnectedSameClient, true);
    assert.equal(status, 0, `a complete artifact must pass; failed: ${JSON.stringify(report.failed)}`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("R7C.3.1-8: the constructor is not the report metadata", () => {
  // The precise bug, asserted directly: the load check's `detail` is `{ path }`, which is not
  // callable, and construction must not depend on it. If someone reintroduces the mistake by
  // returning the constructor in `detail` and `new`ing it, `new metadata` throws
  // "is not a constructor" and this fails.
  const root = makeArtifact({ client: "synthetic" });
  try {
    const { report } = runHarness(root);
    const loadDetail = findCheck(report, "@prisma/client loads")?.detail as { path?: string; PrismaClient?: unknown };
    assert.equal(typeof loadDetail, "object");
    assert.equal(typeof loadDetail.PrismaClient, "undefined",
      "the constructor must not be placed in serializable report metadata");
    assert.equal(typeof loadDetail.path, "string", "the report should carry the resolved path");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("R7C.3.1-9: an ungenerated client fails for the right reason, without a misleading constructor error", () => {
  const root = makeArtifact({ client: "none" });
  try {
    mkdirSync(join(root, "node_modules/@prisma/client"), { recursive: true });
    cpSync(join(ROOT, "node_modules/@prisma/client/default.js"), join(root, "node_modules/@prisma/client/default.js"));
    cpSync(join(ROOT, "node_modules/@prisma/client/package.json"), join(root, "node_modules/@prisma/client/package.json"));
    const { status, report } = runHarness(root);
    assert.equal(status, 1);
    const clientFailure = failedEntries(report).find((entry) => entry.check.startsWith("@prisma/client loads"));
    assert.match(String(clientFailure?.error), /prisma\/client\/default/u, "the cause must be the missing generated client");
    assert.equal(findCheck(report, "the generated client is present")?.ok, false);
    // The construction failure must point at the real cause rather than pretending it is a
    // packaging problem of its own.
    const construction = findCheck(report, "PrismaPg and PrismaClient construct");
    assert.match(String(construction?.error), /see its error/u);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------------------
// Natural exit (Task 3).
// ---------------------------------------------------------------------------------------

test("R7C.3.1-10: the verifier never forces termination", () => {
  // `process.exit()` would end the process even with the client's pool still open, so it
  // cannot distinguish a clean disconnect from a torn-down one. Exit status must come from
  // `process.exitCode` and the loop must be allowed to drain.
  const source = readFileSync(HARNESS, "utf8");
  // Strip comments first. The script's own docblock *names* `process.exit()` to explain why
  // it is not used, and a scan that cannot tell code from prose would fail on that.
  const code = source.replace(/\/\*[\s\S]*?\*\//gu, "").replace(/(^|[^:])\/\/.*$/gmu, "$1");
  assert.deepEqual([...code.matchAll(/process\.exit\s*\(/gu)], [], "process.exit() must not be called; use process.exitCode");
  assert.match(code, /process\.exitCode\s*=/u, "the exit status must be set via process.exitCode");
  // And the watchdog must not keep the process alive on its own.
  assert.match(code, /\.unref\(\)/u, "the leak watchdog must be unref'd so it cannot hold the loop open");
});

test("R7C.3.1-11: a completed run exits naturally within the external bound", () => {
  const root = makeArtifact({ client: "synthetic" });
  try {
    const { status, timedOut } = runHarness(root);
    assert.equal(timedOut, false, "a clean run must not be killed by the external timeout");
    assert.equal(status, 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("R7C.3.1-12: a leaked handle holds the process open and is caught by the external bound", () => {
  // The complement of test 11: this is what proves the natural exit is real rather than
  // merely declared. The synthetic client starts an interval in `$disconnect`, which is
  // exactly the failure mode of a pool that was not torn down. The verifier's own unref'd
  // watchdog fires, and the test's external timeout kills the process.
  const root = makeArtifact({ client: "synthetic", leakHandle: true });
  try {
    const { status, timedOut } = runHarness(root);
    assert.equal(timedOut, true,
      "a leaked handle must keep the process alive; if this fails, the natural-exit check is not being exercised");
    assert.equal(status, -1, `the killed process must not report success, got ${status}`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------------------
// Anti-drift and isolation.
// ---------------------------------------------------------------------------------------

test("R7C.3.1-13: the verifier's hardcoded majors match the lockfile", () => {
  // The verifier runs inside the built image, where the lockfile is absent, so the required
  // majors are literals. This is what stops those literals drifting from the real graph.
  const lock = JSON.parse(readFileSync(join(ROOT, "package-lock.json"), "utf8")) as {
    packages: Record<string, { version?: string; dependencies?: Record<string, string> }>;
  };
  const hoisted = lock.packages["node_modules/postgres-array"]?.version;
  const nested = lock.packages["node_modules/pg-types/node_modules/postgres-array"]?.version;
  const pgTypesRange = lock.packages["node_modules/pg-types"]?.dependencies?.["postgres-array"];
  const adapterRange = lock.packages["node_modules/@prisma/adapter-pg"]?.dependencies?.["postgres-array"];
  assert.ok(hoisted && nested, "both postgres-array copies must be in the lockfile");

  const source = readFileSync(HARNESS, "utf8");
  const nestedMajor = /NESTED_POSTGRES_ARRAY_MAJOR = "(\d+)"/u.exec(source)?.[1];
  const hoistedMajor = /HOISTED_POSTGRES_ARRAY_MAJOR = "(\d+)"/u.exec(source)?.[1];
  assert.equal(nestedMajor, nested?.split(".")[0], `verifier expects nested major ${nestedMajor}, lockfile has ${nested}`);
  assert.equal(hoistedMajor, hoisted?.split(".")[0], `verifier expects hoisted major ${hoistedMajor}, lockfile has ${hoisted}`);

  // And the ranges really do diverge, so two copies are genuinely required.
  assert.equal(pgTypesRange, "~2.0.0");
  assert.equal(adapterRange, "3.0.4");
  assert.notEqual(nested?.split(".")[0], hoisted?.split(".")[0],
    "the two copies must be different majors, otherwise a flattened tree would be harmless");
});

test("R7C.3.1-14: the harness refuses to run inside a source checkout", () => {
  // The escape hatch that would make every check vacuous: run from a directory under the
  // repository and Node's upward walk finds the repository's node_modules, so a completely
  // empty artifact would pass.
  const { status, report } = runHarness(ROOT);
  assert.equal(status, 1);
  assert.equal(report.result, "FAIL");
  assert.deepEqual(report.failed, ["artifact isolation"]);
  // No module check may run once isolation is refused. The refusal itself is recorded in
  // `checks` (so the report is never silently empty), and nothing else may be.
  assert.deepEqual(report.checks.map((entry) => entry.check), ["artifact isolation"],
    "no module check may run once isolation is refused");
});

test("R7C.3.1-15: the declared externals are exactly the lockfile's runtime closure", () => {
  // Kept from R7C.3: the config is the only place deciding what is externalised, and getting
  // it wrong is silent. The list is derived from the lockfile, not from the config, and the
  // two are compared.
  const lock = JSON.parse(readFileSync(join(ROOT, "package-lock.json"), "utf8")) as {
    packages: Record<string, { dependencies?: Record<string, string> }>;
  };
  const packages = lock.packages;
  const resolve = (fromPath: string, name: string): string | undefined => {
    let base = fromPath;
    for (;;) {
      const candidate = base ? `${base}/node_modules/${name}` : `node_modules/${name}`;
      if (candidate in packages) return candidate;
      if (!base) return undefined;
      const index = base.lastIndexOf("/node_modules/");
      base = index >= 0 ? base.slice(0, index) : "";
    }
  };
  const seen = new Set<string>();
  const names = new Set<string>();
  const stack: Array<[string, string]> = [["", "@prisma/client"], ["", "@prisma/adapter-pg"]];
  while (stack.length) {
    const [from, name] = stack.pop() as [string, string];
    const path = resolve(from, name);
    if (!path || seen.has(path)) continue;
    seen.add(path);
    names.add(name);
    for (const dependency of Object.keys(packages[path]?.dependencies ?? {})) stack.push([path, dependency]);
  }
  const runtimeClosure = new Set([...names].filter((name) => !name.startsWith("@types/") && name !== "undici-types"));

  const config = readFileSync(join(ROOT, "next.config.ts"), "utf8");
  const block = config.slice(config.indexOf("const PRISMA_EXTERNAL_PACKAGES = ["), config.indexOf("] as const;", config.indexOf("const PRISMA_EXTERNAL_PACKAGES = [")));
  const declared = new Set([...block.matchAll(/"([^"]+)"/gu)].map((match) => match[1]));

  const missing = [...runtimeClosure].filter((name) => !declared.has(name)).sort();
  const extra = [...declared].filter((name) => !runtimeClosure.has(name)).sort();
  assert.deepEqual(missing, [], `not external, would be orphaned: ${missing.join(", ")}`);
  assert.deepEqual(extra, [], `external but not in the runtime graph: ${extra.join(", ")}`);
  assert.equal(declared.size, 18, "the closure is 18 packages");
  assert.equal(declared.has("pg-cloudflare"), false, "pg-cloudflare is optional and must not be externalised");
});

test("R7C.3.1-16: the packaging strategy is both externals AND complete globs", () => {
  // Measured: globs alone orphan dependencies; externals alone emit only the ESM entry of a
  // dual-format package. Both are needed, and both are asserted here.
  const config = readFileSync(join(ROOT, "next.config.ts"), "utf8");
  assert.match(config, /serverExternalPackages:\s*\[\.\.\.PRISMA_EXTERNAL_PACKAGES\]/u);
  assert.match(config, /PRISMA_EXTERNAL_PACKAGES\.map\(\(name\) => `\.\/node_modules\/\$\{name\}\/\*\*\/\*`\)/u);
  assert.match(config, /\.\/node_modules\/pg-types\/node_modules\/postgres-array\/\*\*\/\*/u);
  assert.match(config, /"\.\/node_modules\/\.prisma\/client\/\*\*\/\*"/u);
  const prismaKeyLine = config.slice(config.indexOf("outputFileTracingIncludes: {")).split("\n").find((line) => line.includes("PRISMA_RUNTIME_TRACING"));
  assert.match(prismaKeyLine as string, /^\s*"\/":/u, `the database closure must be keyed to "/", found: ${prismaKeyLine}`);
});
