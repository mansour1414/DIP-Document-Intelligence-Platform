/**
 * R7C.3 — the artifact runtime check must detect the failure it was built for.
 *
 * ## The defect these guard
 *
 * The R7C.1 image contained `/app/node_modules/@prisma/adapter-pg/dist/index.js` — the
 * file was there, and the require stack in the failure pointed at it — yet loading it
 * raised `MODULE_NOT_FOUND: @prisma/driver-adapter-utils`. The package had been copied by
 * a file glob, which does not know about dependencies, so its own `require()` had nowhere
 * to resolve.
 *
 * No earlier gate could see this. TypeScript checks types, webpack checks bundling, the
 * tracer decides packaging, and only `require()` at runtime exercises the real directory
 * layout. So the regression test for the *checker* has to be a real require against a
 * real directory layout — not an assertion about configuration text.
 *
 * ## What is real here, and what is not
 *
 * Every package used below is copied from the repository's own `node_modules` at their
 * locked versions. The tests therefore exercise genuine `@prisma/adapter-pg`, genuine
 * `pg`, and genuine Node resolution — including the nested `postgres-array@2` under
 * `pg-types` that differs from the hoisted `postgres-array@3`.
 *
 * `@prisma/client` is the one thing that cannot be real here: it requires a *generated*
 * `.prisma/client`, and `prisma generate` is TLS-blocked in this sandbox. So the
 * generated-client checks are asserted as their own failing outcome rather than faked —
 * fabricating a client would make this suite prove nothing and would violate the
 * "no fake Prisma Client" rule. The construction checks are BLOCKED until run natively;
 * the adapter and pg closure checks are fully exercised.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

const ROOT = process.cwd();
const HARNESS = join(ROOT, "scripts/verify-prisma-artifact-runtime.mjs");

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

/**
 * Build a throwaway artifact containing the real packages.
 *
 * `nested` reproduces the lockfile's second, older `postgres-array` under `pg-types`.
 * It is the detail a naive flat copy loses, and losing it hands `pg-types` the wrong
 * major version without any error until a query payload is parsed.
 */
function makeArtifact(): string {
  const root = mkdtempSync(join(tmpdir(), "dip-prisma-artifact-"));
  for (const name of CLOSURE) {
    const from = join(ROOT, "node_modules", name);
    if (!existsSync(from)) continue;
    cpSync(from, join(root, "node_modules", name), { recursive: true });
  }
  cpSync(join(ROOT, "node_modules/pg-types/node_modules/postgres-array"), join(root, "node_modules/pg-types/node_modules/postgres-array"), { recursive: true });
  return root;
}

function runHarness(root: string): { status: number; report: { result: string; checks: Array<{ check: string; ok: boolean; detail?: unknown; error?: string }>; failed?: string[] } } {
  try {
    const stdout = execFileSync(process.execPath, [HARNESS, root], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    return { status: 0, report: JSON.parse(stdout) };
  } catch (error) {
    const failure = error as { status?: number; stdout?: string };
    return { status: failure.status ?? -1, report: JSON.parse(failure.stdout ?? "{}") };
  }
}

test("R7C.3-1: the adapter's own requires resolve against a real, complete artifact", () => {
  const root = makeArtifact();
  try {
    const { report } = runHarness(root);
    const adapterCheck = report.checks.find((entry) => entry.check.startsWith("@prisma/adapter-pg loads"));
    assert.equal(adapterCheck?.ok, true, `the adapter must load, failures: ${JSON.stringify(report.checks.filter((entry) => !entry.ok))}`);
    // And it must have resolved the *specific* module whose absence killed the R7C.1 image.
    const requires = (adapterCheck?.detail as { requires: Record<string, string> }).requires;
    assert.ok(requires["@prisma/driver-adapter-utils"]?.startsWith(root),
      "@prisma/driver-adapter-utils must resolve inside the artifact");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("R7C.3-2: removing @prisma/driver-adapter-utils reproduces the exact production failure", () => {
  // This is the negative regression case for the real defect: everything else stays
  // intact, only the one orphaned dependency is removed — which is precisely the state a
  // file-glob copy produces.
  const root = makeArtifact();
  try {
    rmSync(join(root, "node_modules/@prisma/driver-adapter-utils"), { recursive: true, force: true });
    const { status, report } = runHarness(root);
    assert.equal(status, 1, "the check must fail when a required dependency is absent");
    assert.equal(report.result, "FAIL");
    const joined = JSON.stringify(report.checks.filter((entry) => !entry.ok));
    assert.match(joined, /@prisma\/driver-adapter-utils/u, "the failure must name the missing module");
    assert.match(joined, /@prisma\/adapter-pg/u, "the failure must attribute it to the adapter");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("R7C.3-3: removing pg is detected, not silently tolerated", () => {
  const root = makeArtifact();
  try {
    rmSync(join(root, "node_modules/pg"), { recursive: true, force: true });
    const { status, report } = runHarness(root);
    assert.equal(status, 1);
    assert.match(JSON.stringify(report.checks.filter((entry) => !entry.ok)), /\bpg\b/u);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("R7C.3-4: the nested postgres-array is preserved and proven distinct", () => {
  // `pg-types` needs postgres-array@2 while the adapter uses @3. A flat copy collapses
  // them and nothing fails until a result is parsed — so the harness asserts the two
  // resolve to different directories, and this asserts the harness does that.
  const root = makeArtifact();
  try {
    const { report } = runHarness(root);
    const pgCheck = report.checks.find((entry) => entry.check.startsWith("pg loads"));
    assert.equal(pgCheck?.ok, true, JSON.stringify(report.checks.filter((entry) => !entry.ok)));
    const detail = pgCheck?.detail as { nestedPostgresArray: string; hoistedPostgresArray: string };
    assert.ok(detail.nestedPostgresArray.includes("pg-types/node_modules/postgres-array"),
      `nested copy must be the nested one, saw ${detail.nestedPostgresArray}`);
    assert.ok(detail.hoistedPostgresArray.endsWith("/node_modules/postgres-array/index.js"),
      `hoisted copy must be the hoisted one, saw ${detail.hoistedPostgresArray}`);
    assert.notEqual(detail.nestedPostgresArray, detail.hoistedPostgresArray);
    // Versions confirm the majors really differ, so this is not a same-version no-op.
    // The resolved path is `<pkgdir>/index.js`, so the manifest is one level up.
    const nested = JSON.parse(readFileSync(join(dirname(detail.nestedPostgresArray), "package.json"), "utf8")) as { version: string };
    const hoisted = JSON.parse(readFileSync(join(dirname(detail.hoistedPostgresArray), "package.json"), "utf8")) as { version: string };
    assert.equal(nested.version.split(".")[0], "2");
    assert.equal(hoisted.version.split(".")[0], "3");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("R7C.3-5: the harness refuses to run inside a source checkout", () => {
  // The escape hatch that would make every check vacuous: run from a directory under the
  // repository and Node's upward walk finds the repository's node_modules, so a completely
  // empty artifact would pass. This is the guard against that, tested where it matters.
  const { status, report } = runHarness(ROOT);
  assert.equal(status, 1);
  assert.equal(report.result, "FAIL");
  // The isolation refusal happens before any module check, so `checks` is empty and the
  // reason is reported in `failed`. Both are asserted: an empty `checks` alone could also
  // mean the script crashed before doing anything.
  assert.deepEqual(report.checks, [], "no module check may run once isolation is refused");
  assert.deepEqual(report.failed, ["artifact isolation"]);
});

test("R7C.3-6: a missing generated client fails the client checks while the adapter still proves itself", () => {
  // Honest split. `@prisma/client` needs a generated `.prisma/client`, and generation is
  // BLOCKED here (TLS), so this asserts the *diagnosis* rather than faking a client:
  // the client checks fail for the right reason, the adapter check still passes, and the
  // report distinguishes them. Native acceptance covers the construction path.
  const root = makeArtifact();
  try {
    mkdirSync(join(root, "node_modules/@prisma/client"), { recursive: true });
    cpSync(join(ROOT, "node_modules/@prisma/client/default.js"), join(root, "node_modules/@prisma/client/default.js"));
    cpSync(join(ROOT, "node_modules/@prisma/client/package.json"), join(root, "node_modules/@prisma/client/package.json"));
    const { status, report } = runHarness(root);
    assert.equal(status, 1);
    const clientCheck = report.checks.find((entry) => entry.check.startsWith("@prisma/client loads"));
    assert.equal(clientCheck?.ok, false, "an ungenerated client must fail");
    assert.match(String(report.checks.find((entry) => entry.check.startsWith("@prisma/client loads"))?.error), /prisma\/client\/default/u);
    const generated = report.checks.find((entry) => entry.check.startsWith("the generated client is present"));
    assert.equal(generated?.ok, false, "the generated-client directory must be reported absent");
    // The adapter half is independent of this and must still have proven itself.
    assert.equal(report.checks.find((entry) => entry.check.startsWith("@prisma/adapter-pg loads"))?.ok, true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("R7C.3-7: the declared externals are exactly the lockfile's runtime closure", () => {
  // The config is the only place that decides what gets externalised, and the failure
  // mode of getting it wrong is silent: an omitted package orphans its dependents, and an
  // extra one ships code that never runs. So the list is derived here from the *lockfile*
  // — not from the config — and compared. This is what would have caught R7C.1: the
  // adapter's dependency edge existed in the lockfile and was absent from the packaging.
  const lock = JSON.parse(readFileSync(join(ROOT, "package-lock.json"), "utf8")) as { packages: Record<string, { version?: string; dependencies?: Record<string, string> }> };
  const packages = lock.packages;
  const resolveFrom = (fromPath: string, name: string): string | undefined => {
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
    const path = resolveFrom(from, name);
    if (!path || seen.has(path)) continue;
    seen.add(path);
    names.add(name);
    for (const dependency of Object.keys(packages[path]?.dependencies ?? {})) stack.push([path, dependency]);
  }
  // Type declarations are in the graph but are never required at runtime.
  const runtimeClosure = new Set([...names].filter((name) => !name.startsWith("@types/") && name !== "undici-types"));

  const config = readFileSync(join(ROOT, "next.config.ts"), "utf8");
  const block = config.slice(config.indexOf("const PRISMA_EXTERNAL_PACKAGES = ["), config.indexOf("] as const;", config.indexOf("const PRISMA_EXTERNAL_PACKAGES = [")));
  const declared = new Set([...block.matchAll(/"([^"]+)"/gu)].map((match) => match[1]));

  const missing = [...runtimeClosure].filter((name) => !declared.has(name)).sort();
  const extra = [...declared].filter((name) => !runtimeClosure.has(name)).sort();
  assert.deepEqual(missing, [], `these runtime dependencies are not external, so they would be orphaned or bundled: ${missing.join(", ")}`);
  assert.deepEqual(extra, [], `these are external but are not in the runtime graph: ${extra.join(", ")}`);
  // And the optional Cloudflare driver must stay out: it is a worker-only adapter this
  // application never loads, and pulling it in would add code that cannot execute here.
  assert.equal(declared.has("pg-cloudflare"), false, "pg-cloudflare is optional and must not be externalised");
});

test("R7C.3-8: the packaging strategy is both externals AND complete globs", () => {
  // Measured, not assumed. Two builds of the same app proved each mechanism insufficient
  // alone, and the combination correct:
  //
  //   globs only (R7C.1)        -> adapter present, @prisma/driver-adapter-utils absent
  //   externals only            -> adapter emitted as package.json + dist/index.mjs ONLY;
  //                                Node's `require` condition wants dist/index.js, absent
  //   externals + globs         -> every file of every package, correct nesting
  //
  // The second row is the subtle one: the tracer follows the ESM entry because the server
  // bundle *imports* the package, while the shipped `server.js` is CommonJS and *requires*
  // it. A dual-format package then resolves to a file that was never emitted.
  const config = readFileSync(join(ROOT, "next.config.ts"), "utf8");
  assert.match(config, /serverExternalPackages:\s*\[\.\.\.PRISMA_EXTERNAL_PACKAGES\]/u,
    "the closure must be declared external, which is what makes the tracer emit dependencies");

  // The globs must cover both formats of each package. Globbing the package directory does
  // that; globbing named files would silently miss whichever format is added later.
  assert.match(config, /PRISMA_EXTERNAL_PACKAGES\.map\(\(name\) => `\.\/node_modules\/\$\{name\}\/\*\*\/\*`\)/u,
    "every external package needs its whole directory traced, so both entry formats ship");
  // And the one package whose dependency is nested rather than hoisted needs its own entry.
  assert.match(config, /\.\/node_modules\/pg-types\/node_modules\/postgres-array\/\*\*\/\*/u,
    "the nested postgres-array must be traced at its own path");

  // The generated client cannot be derived from the lockfile, so it stays explicit.
  assert.match(config, /"\.\/node_modules\/\.prisma\/client\/\*\*\/\*"/u,
    "the generated client is not a package and needs an explicit glob");

  // The database closure must not be keyed to a subset of routes. Routes that reach
  // src/lib/db/index.ts are the auth, usage, dashboard and locale pages — not the PDF
  // routes — so keying it to `/` is what keeps it from depending on which route runs.
  const includesBlock = config.slice(config.indexOf("outputFileTracingIncludes: {"));
  const prismaKeyLine = includesBlock.split("\n").find((line) => line.includes("PRISMA_RUNTIME_TRACING"));
  assert.ok(prismaKeyLine, "the Prisma tracing list must be applied to some route key");
  assert.match(prismaKeyLine as string, /^\s*"\/":/u,
    `the database closure must be keyed to "/", found: ${prismaKeyLine}`);
});
