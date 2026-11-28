#!/usr/bin/env node
/**
 * Verify the database runtime actually loads inside an emitted standalone artifact.
 *
 * ## Why a compile is not evidence
 *
 * R7C.1 shipped an application image where `next build` passed, Prisma Client generated
 * successfully, and 111 static pages rendered — and the image still died at
 * `require("@prisma/adapter-pg")` with `MODULE_NOT_FOUND: @prisma/driver-adapter-utils`.
 *
 * Every error belonged to a different phase than the one that was checked. TypeScript
 * checks *types*; webpack checks *bundling*; the file tracer decides *packaging*; and only
 * at runtime does module resolution actually happen, against the real directory layout,
 * with the real `package.json` `exports` maps and the real nesting. Those layers can
 * disagree, and when they do, nothing before the container starts notices.
 *
 * So this script checks the only thing that matters: it runs **inside the emitted
 * artifact, outside the source checkout**, and requires the modules for real.
 *
 * ## What it does, in order
 *
 *   1. `@prisma/client` loads (the generated client, not a stub).
 *   2. The generated `.prisma/client` directory is present beside it.
 *   3. `@prisma/adapter-pg` loads, and each of its own `require()` targets resolves
 *      *from the adapter's directory*.
 *   4. `pg` loads, and its own closure resolves from `pg`'s directory.
 *   5. The nested `postgres-array@2` and the hoisted `postgres-array@3` are both present,
 *      are separate copies, and are the majors the lockfile requires.
 *   6. `PrismaPg` and `PrismaClient` construct against synthetic configuration.
 *   7. That same client `$disconnect()`s and the process exits on its own.
 *
 * ## What it deliberately does not do
 *
 * No `DATABASE_URL` is read, no credentials are used, no connection is opened and no
 * query runs. Construction is lazy in Prisma: building a client does not connect, and
 * `$disconnect()` on an unconnected client is a no-op. The connection string below is a
 * syntactically valid, obviously fake loopback value — it is never dialled, and it is not
 * a secret.
 *
 * ## Natural exit, not forced termination
 *
 * The script sets `process.exitCode` and returns. It never calls `process.exit()`. That
 * distinction is the whole point of the last check: `process.exit()` would terminate the
 * process even with the client's pool, timers or sockets still open, so it cannot
 * distinguish "disconnected cleanly" from "torn down mid-flight". With a natural exit, a
 * leaked handle keeps the event loop alive and the process hangs — which is visible,
 * whereas a forced exit hides it.
 *
 * Because a hang shows nothing by itself, an unref'd watchdog timer is armed. Being
 * unref'd, it never *keeps* the process alive: it fires only if something else already is,
 * and then it prints the live handle types so the log says why the run stalled. It does not
 * terminate anything — external bounds (the test harness timeout, the CI step timeout, the
 * Docker build limit) still own termination.
 *
 * ## The repository escape hatch is closed on purpose
 *
 * A Node process resolves `node_modules` by walking *up* from the requiring file. Run
 * from a directory beneath the repository, that walk finds the repository's own
 * `node_modules` and every check would pass while the artifact is empty. So this script
 * refuses to run when it can see a path from its own location up to a checkout that
 * contains `.git`.
 *
 * Usage:
 *   node scripts/verify-prisma-artifact-runtime.mjs [artifact-root]
 *
 * Exit status: 0 when the whole closure loads, constructs and disconnects; 1 otherwise,
 * listing every failure rather than stopping at the first — one missing module usually
 * implies others, and fixing them one container run at a time is how the closure stays
 * broken.
 */
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import { createRequire } from "node:module";

const ARTIFACT_ROOT = resolve(process.argv[2] ?? process.cwd());

/**
 * The majors this artifact must contain, from `package-lock.json`.
 *
 * `pg-types` declares `postgres-array: ~2.0.0` while `@prisma/adapter-pg` declares
 * `3.0.4`, so npm installed two copies. They are not interchangeable — the row parser and
 * the adapter each expect their own — and a flattened tree hands one of them the wrong
 * major with no error until a result is parsed.
 *
 * These are literals because this script runs inside the built image, where the lockfile
 * is not present. A test in the repository asserts they still match the lockfile, so the
 * two cannot drift.
 */
const NESTED_POSTGRES_ARRAY_MAJOR = "2";
const HOISTED_POSTGRES_ARRAY_MAJOR = "3";

/** How long to keep the process under observation before reporting a leak. */
const LEAK_OBSERVATION_MS = 5000;

/** Every check, in the order it must run. */
const failures = [];
const results = [];

/**
 * Run one check and record it.
 *
 * Returns only **serializable diagnostic metadata** for the report. It deliberately does
 * not return the loaded values themselves: a previous version of this script returned
 * `{ path }` from the client-load check and then tried to `new` that object, so the
 * construction check could never pass and reported "@prisma/client did not yield a
 * constructor" even on a perfectly good artifact. Anything the run needs to *use* is held
 * in a module-level binding instead, so executable references and report data cannot be
 * confused for one another again.
 */
function check(label, run) {
  try {
    const detail = run();
    const entry = { check: label, ok: true, ...(detail ? { detail } : {}) };
    results.push(entry);
    return detail;
  } catch (error) {
    const entry = { check: label, ok: false, error: error instanceof Error ? `${error.name}: ${error.message}` : String(error) };
    failures.push(entry);
    // Also recorded in `checks` so the report lists every check that ran, in order, with
    // its outcome. A report that hides failures in a separate array makes "did this check
    // run, and did it pass?" ambiguous — the same ambiguity that let the R7C.1 image ship.
    results.push(entry);
    return undefined;
  }
}

/**
 * Executable references, kept apart from the report.
 *
 * `prismaClient` is the single client this run constructs, and the one it disconnects.
 * Constructing a second client just to exercise `$disconnect()` would prove less: it would
 * not show that the object which was built can be torn down.
 */
let PrismaClientConstructor;
let prismaClient;

/**
 * The packages the adapter requires, and the ones `pg` requires.
 *
 * Listed explicitly rather than discovered by reading `package.json` at runtime: the
 * point is to assert a *known* closure, not to accept whatever is present. A package
 * that disappears from the graph should fail here, loudly.
 */
const ADAPTER_REQUIRES = ["@prisma/driver-adapter-utils", "pg", "postgres-array"];
const PG_REQUIRES = ["pg-connection-string", "pg-pool", "pg-protocol", "pg-types", "pgpass"];
const PG_TYPES_REQUIRES = ["pg-int8", "postgres-array", "postgres-bytea", "postgres-date", "postgres-interval"];

/**
 * Resolve a package the way Node would, starting from a real directory in the artifact.
 *
 * `createRequire(fromFile)` is the closest thing to "what would the adapter's own
 * `require()` do" without executing its code. A bare `import()` from this script would
 * resolve from *here* instead, which is exactly the mistake the R7C.1 defect hid behind.
 */
function resolveFrom(fromDir, specifier) {
  const anchor = join(fromDir, "noop.js");
  return createRequire(anchor).resolve(specifier);
}

function requireFromArtifact(specifier) {
  return createRequire(join(ARTIFACT_ROOT, "noop.js"))(specifier);
}

function assertInsideArtifact(resolvedPath, what) {
  const real = realpathSync(resolvedPath);
  if (!real.startsWith(ARTIFACT_ROOT + sep) && real !== ARTIFACT_ROOT) {
    throw new Error(`${what} resolved outside the artifact: ${real} (artifact root: ${ARTIFACT_ROOT})`);
  }
  return real;
}

/** Read a resolved package's manifest and report its directory, version and major. */
function describePackage(resolvedFile, what) {
  const dir = dirname(realpathSync(resolvedFile));
  const manifestPath = join(dir, "package.json");
  if (!existsSync(manifestPath)) throw new Error(`${what} resolved to ${dir}, which has no package.json`);
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const version = String(manifest.version ?? "");
  if (!version) throw new Error(`${what} at ${dir} declares no version`);
  return { dir, version, major: version.split(".")[0] };
}

// ---------------------------------------------------------------------------------------
// Guard: refuse to pass by falling back into a source checkout.
// ---------------------------------------------------------------------------------------
function artifactIsIsolated() {
  let cursor = ARTIFACT_ROOT;
  for (let depth = 0; depth < 8; depth += 1) {
    if (existsSync(join(cursor, ".git"))) {
      const entry = {
        check: "artifact isolation",
        ok: false,
        error: `refusing to run: ${ARTIFACT_ROOT} is inside a source checkout (found .git at ${cursor}). `
          + "Node walks up to the repository's node_modules, so every module would resolve and the check would pass against an empty artifact.",
      };
      failures.push(entry);
      results.push(entry);
      return false;
    }
    const parent = dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }
  return true;
}

// ---------------------------------------------------------------------------------------
// 1 & 2. The generated Prisma Client.
// ---------------------------------------------------------------------------------------
function checkClient() {
  check("@prisma/client loads", () => {
    const path = resolveFrom(ARTIFACT_ROOT, "@prisma/client");
    assertInsideArtifact(path, "@prisma/client");
    const mod = requireFromArtifact("@prisma/client");
    // A generated client exports `PrismaClient`; an ungenerated `@prisma/client` package
    // throws on require ("did not initialize yet") or lacks the export. Both must fail.
    if (typeof mod?.PrismaClient !== "function") {
      throw new Error("the package loaded but exports no PrismaClient constructor");
    }
    // Hold the constructor itself; return only what belongs in the JSON report.
    PrismaClientConstructor = mod.PrismaClient;
    return { path };
  });

  // The generated client's own directory proves generation actually ran into this tree.
  check("the generated client is present beside the package", () => {
    for (const candidate of [join(ARTIFACT_ROOT, "node_modules/.prisma/client"), join(ARTIFACT_ROOT, ".prisma/client")]) {
      if (existsSync(candidate)) return { path: candidate };
    }
    throw new Error("no .prisma/client directory: the client was not generated into this artifact");
  });
}

// ---------------------------------------------------------------------------------------
// 3. The adapter, and its own dependency context.
// ---------------------------------------------------------------------------------------
function checkAdapter() {
  check("@prisma/adapter-pg loads, and each of its requires resolves from ITS OWN directory", () => {
    const adapterPath = resolveFrom(ARTIFACT_ROOT, "@prisma/adapter-pg");
    assertInsideArtifact(adapterPath, "@prisma/adapter-pg");
    const dir = dirname(adapterPath);
    const resolved = {};
    for (const dependency of ADAPTER_REQUIRES) {
      // Resolved *from the adapter*, which is the resolution the failing container did.
      const target = resolveFrom(dir, dependency);
      assertInsideArtifact(target, `${dependency} (required by @prisma/adapter-pg)`);
      resolved[dependency] = target;
    }
    // Then actually load it, because resolution and execution are different failures.
    // The shipping `server.js` is CommonJS, so `require` is the path that must work here.
    requireFromArtifact("@prisma/adapter-pg");
    return { path: adapterPath, requires: resolved };
  });
}

// ---------------------------------------------------------------------------------------
// 4 & 5. pg, its closure, and the two postgres-array copies.
// ---------------------------------------------------------------------------------------
function checkPg() {
  check("pg loads, and its requires resolve from pg's own directory", () => {
    const pgPath = resolveFrom(ARTIFACT_ROOT, "pg");
    assertInsideArtifact(pgPath, "pg");
    const dir = dirname(pgPath);
    for (const dependency of PG_REQUIRES) {
      assertInsideArtifact(resolveFrom(dir, dependency), `${dependency} (required by pg)`);
    }
    // `pg-types` has its own nested closure, including a *nested* postgres-array@2 that
    // differs from the hoisted postgres-array@3 the adapter uses.
    const pgTypesDir = dirname(resolveFrom(dir, "pg-types"));
    for (const dependency of PG_TYPES_REQUIRES) {
      assertInsideArtifact(resolveFrom(pgTypesDir, dependency), `${dependency} (required by pg-types)`);
    }
    requireFromArtifact("pg");
    return { path: pgPath };
  });

  // The two copies must both exist, must not be the same directory, and must be the majors
  // the lockfile requires. Returning success on a single shared copy would let a flattened
  // tree pass while `pg-types` silently received major 3 — a defect that surfaces only
  // when a result row is parsed, long after the image was published.
  check("the nested postgres-array@2 and hoisted postgres-array@3 are separate copies", () => {
    const pgTypesDir = dirname(resolveFrom(ARTIFACT_ROOT, "pg-types"));
    const nested = describePackage(resolveFrom(pgTypesDir, "postgres-array"), "nested postgres-array");
    const hoisted = describePackage(resolveFrom(ARTIFACT_ROOT, "postgres-array"), "hoisted postgres-array");
    assertInsideArtifact(join(nested.dir, "package.json"), "nested postgres-array");
    assertInsideArtifact(join(hoisted.dir, "package.json"), "hoisted postgres-array");

    if (nested.dir === hoisted.dir) {
      throw new Error(
        `the dependency tree is flattened: pg-types and @prisma/adapter-pg both resolve postgres-array from ${nested.dir}. `
        + `The lockfile requires two copies (${NESTED_POSTGRES_ARRAY_MAJOR}.x for pg-types, ${HOISTED_POSTGRES_ARRAY_MAJOR}.x for the adapter).`,
      );
    }
    if (nested.major !== NESTED_POSTGRES_ARRAY_MAJOR) {
      throw new Error(`pg-types resolves postgres-array@${nested.version} at ${nested.dir}; the lockfile requires major ${NESTED_POSTGRES_ARRAY_MAJOR}`);
    }
    if (hoisted.major !== HOISTED_POSTGRES_ARRAY_MAJOR) {
      throw new Error(`the adapter resolves postgres-array@${hoisted.version} at ${hoisted.dir}; the lockfile requires major ${HOISTED_POSTGRES_ARRAY_MAJOR}`);
    }
    // Confirm each copy is loadable, not merely present on disk.
    createRequire(join(pgTypesDir, "noop.js"))("postgres-array");
    requireFromArtifact("postgres-array");
    return { nested: nested.version, hoisted: hoisted.version, nestedDir: nested.dir, hoistedDir: hoisted.dir };
  });
}

// ---------------------------------------------------------------------------------------
// 6 & 7. Construction, then disconnect of that same client.
// ---------------------------------------------------------------------------------------
const SYNTHETIC_CONNECTION = "postgresql://artifact-check:artifact-check@127.0.0.1:5432/artifact_check";

function checkConstruction() {
  check("PrismaPg and PrismaClient construct against synthetic configuration", () => {
    // This failure has one honest cause. If it says "did not yield a constructor", the
    // client load above did not succeed — look at its error first.
    if (typeof PrismaClientConstructor !== "function") {
      throw new Error("@prisma/client did not yield a constructor (the client load check above did not succeed; see its error)");
    }
    const { PrismaPg } = requireFromArtifact("@prisma/adapter-pg");
    if (typeof PrismaPg !== "function") throw new Error("@prisma/adapter-pg exports no PrismaPg");
    // Obvious fake: loopback, no real host, no secret. Never dialled — construction is lazy.
    const adapter = new PrismaPg({ connectionString: SYNTHETIC_CONNECTION });
    // One client. The disconnect check below tears down this exact object.
    prismaClient = new PrismaClientConstructor({ adapter });
    if (typeof prismaClient.$disconnect !== "function") throw new Error("the constructed client has no $disconnect");
    return { constructed: true, engine: "driver adapter (pg), no query engine binary" };
  });
}

async function checkDisconnect() {
  const label = "$disconnect resolves and the process can exit on its own";
  try {
    if (!prismaClient) throw new Error("no client was constructed, so there is nothing to disconnect");
    // No query runs before this. An unconnected client's $disconnect is a no-op, which is
    // what makes it safe to call without a database.
    await prismaClient.$disconnect();
    results.push({ check: label, ok: true, detail: { disconnectedSameClient: true } });
  } catch (error) {
    const entry = { check: label, ok: false, error: error instanceof Error ? `${error.name}: ${error.message}` : String(error) };
    failures.push(entry);
    results.push(entry);
  }
}

// ---------------------------------------------------------------------------------------
// Run.
// ---------------------------------------------------------------------------------------
if (artifactIsIsolated()) {
  checkClient();
  checkAdapter();
  checkPg();
  checkConstruction();
  await checkDisconnect();
}

const report = {
  artifactRoot: ARTIFACT_ROOT,
  node: process.version,
  result: failures.length === 0 ? "PASS" : "FAIL",
  // Every check that ran, pass or fail, in execution order.
  checks: results,
  ...(failures.length ? { failed: failures.map((entry) => entry.check) } : {}),
};
console.log(JSON.stringify(report, null, 2));

// Natural exit: `process.exitCode` lets the event loop drain on its own. If the client
// leaked a handle, the process stays alive here — which is the detection. The watchdog is
// unref'd, so it never causes that liveness itself; it only reports it.
if (failures.length === 0) {
  const watchdog = setTimeout(() => {
    console.error(
      `Leaked handles: the process was still alive ${LEAK_OBSERVATION_MS}ms after $disconnect resolved. `
      + `Active resources: ${process.getActiveResourcesInfo().join(", ") || "(none reported)"}. `
      + "A clean disconnect should leave nothing behind; this run will be terminated by its external timeout.",
    );
    process.exitCode = 1;
  }, LEAK_OBSERVATION_MS);
  watchdog.unref();
}

process.exitCode = failures.length === 0 ? 0 : 1;
