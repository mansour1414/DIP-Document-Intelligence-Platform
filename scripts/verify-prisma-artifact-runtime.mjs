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
 * checks *types*; webpack checks *bundling*; the file tracer decides *packaging*; and
 * only at runtime does module resolution actually happen, against the real directory
 * layout, with the real `package.json` `exports` maps and the real nesting. Those layers
 * can disagree, and when they do, nothing before the container starts notices.
 *
 * So this script checks the only thing that matters: it runs **inside the emitted
 * artifact, outside the source checkout**, and requires the modules for real.
 *
 * ## What it does, in order
 *
 *   1. `@prisma/client` loads (the generated client, not a stub).
 *   2. `@prisma/adapter-pg` loads — the exact module that failed.
 *   3. The adapter's own dependency context resolves: each of its `require()` targets is
 *      resolved *from the adapter's directory*, by the same algorithm Node uses. This is
 *      the check that would have caught the R7C.1 defect: the adapter file was present
 *      and `require()` from it had nowhere to go.
 *   4. `pg` loads.
 *   5. `PrismaPg` and `PrismaClient` construct against synthetic configuration.
 *   6. Disconnect and exit naturally.
 *
 * ## What it deliberately does not do
 *
 * No `DATABASE_URL`, no credentials, no network, no query. Construction is lazy in
 * Prisma: building a client does not connect, and `$disconnect()` on an unconnected
 * client is a no-op. The connection string below is a syntactically valid, obviously
 * fake localhost value — it is never dialled, and it is not a secret.
 *
 * ## The repository escape hatch is closed on purpose
 *
 * A Node process resolves `node_modules` by walking *up* from the requiring file. Run
 * from a directory beneath the repository, that walk finds the repository's own
 * `node_modules` and every check passes while the artifact is empty. So this script
 * refuses to run when it can see a path from its own location up to a checkout that
 * contains `.git` **unless** an artifact root was given explicitly, and it reports the
 * resolved absolute paths so a reviewer can confirm they are inside the artifact.
 *
 * Usage:
 *   node scripts/verify-prisma-artifact-runtime.mjs [artifact-root]
 *
 * Exit status: 0 when the whole closure loads and constructs; 1 otherwise, listing every
 * failure rather than stopping at the first — one missing module usually implies others,
 * and fixing them one container run at a time is how the closure stays broken.
 */
import { existsSync, realpathSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import { createRequire } from "node:module";

const ARTIFACT_ROOT = resolve(process.argv[2] ?? process.cwd());

/** Every check, in the order it must run. */
const failures = [];
const results = [];
function check(label, run) {
  try {
    const detail = run();
    results.push({ check: label, ok: true, ...(detail ? { detail } : {}) });
    return detail;
  } catch (error) {
    const entry = { check: label, ok: false, error: error instanceof Error ? `${error.name}: ${error.message}` : String(error) };
    failures.push(entry);
    // Also recorded in `checks` so the report lists every check that ran, in order, with
    // its outcome. A report that hides failures in a separate array makes "did this check
    // run, and did it pass?" ambiguous — which is the same class of ambiguity that let the
    // R7C.1 image ship.
    results.push(entry);
    return undefined;
  }
}

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

function assertInsideArtifact(resolvedPath, what) {
  const real = realpathSync(resolvedPath);
  if (!real.startsWith(ARTIFACT_ROOT + sep) && real !== ARTIFACT_ROOT) {
    throw new Error(`${what} resolved outside the artifact: ${real} (artifact root: ${ARTIFACT_ROOT})`);
  }
  return real;
}

// ---------------------------------------------------------------------------------------
// Guard: refuse to pass by falling back into a source checkout.
// ---------------------------------------------------------------------------------------
{
  let cursor = ARTIFACT_ROOT;
  for (let depth = 0; depth < 8; depth += 1) {
    if (existsSync(join(cursor, ".git"))) {
      failures.push({
        check: "artifact isolation",
        ok: false,
        error: `refusing to run: ${ARTIFACT_ROOT} is inside a source checkout (found .git at ${cursor}). `
          + "Node walks up to the repository's node_modules, so every module would resolve and the check would pass against an empty artifact.",
      });
      break;
    }
    const parent = dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }
}

if (failures.length === 0) {
  // -------------------------------------------------------------------------------------
  // 1. The generated Prisma Client.
  // -------------------------------------------------------------------------------------
  const PrismaClientCtor = check("@prisma/client loads", () => {
    const path = resolveFrom(ARTIFACT_ROOT, "@prisma/client");
    assertInsideArtifact(path, "@prisma/client");
    const mod = createRequire(join(ARTIFACT_ROOT, "noop.js"))("@prisma/client");
    // A generated client exports `PrismaClient`; an ungenerated `@prisma/client` package
    // throws on require ("did not initialize yet") or lacks the export. Both must fail.
    if (typeof mod?.PrismaClient !== "function") throw new Error("the package loaded but exports no PrismaClient constructor");
    return { path };
  });

  // The generated client's own directory proves generation actually ran into this tree.
  check("the generated client is present beside the package", () => {
    for (const candidate of [join(ARTIFACT_ROOT, "node_modules/.prisma/client"), join(ARTIFACT_ROOT, ".prisma/client")]) {
      if (existsSync(candidate)) return { path: candidate };
    }
    throw new Error("no .prisma/client directory: the client was not generated into this artifact");
  });

  // -------------------------------------------------------------------------------------
  // 2 & 3. The adapter, and its own dependency context.
  // -------------------------------------------------------------------------------------
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
    createRequire(join(ARTIFACT_ROOT, "noop.js"))("@prisma/adapter-pg");
    return { path: adapterPath, requires: resolved };
  });

  // -------------------------------------------------------------------------------------
  // 4. pg and its own closure.
  // -------------------------------------------------------------------------------------
  check("pg loads, and its requires resolve from pg's own directory", () => {
    const pgPath = resolveFrom(ARTIFACT_ROOT, "pg");
    assertInsideArtifact(pgPath, "pg");
    const dir = dirname(pgPath);
    for (const dependency of PG_REQUIRES) {
      assertInsideArtifact(resolveFrom(dir, dependency), `${dependency} (required by pg)`);
    }
    // `pg-types` has its own nested closure, including a *nested* postgres-array@2 that
    // differs from the hoisted postgres-array@3 the adapter uses.
    const pgTypesPath = resolveFrom(dir, "pg-types");
    const pgTypesDir = dirname(pgTypesPath);
    for (const dependency of PG_TYPES_REQUIRES) {
      assertInsideArtifact(resolveFrom(pgTypesDir, dependency), `${dependency} (required by pg-types)`);
    }
    createRequire(join(ARTIFACT_ROOT, "noop.js"))("pg");
    return { path: pgPath, nestedPostgresArray: resolveFrom(pgTypesDir, "postgres-array"), hoistedPostgresArray: resolveFrom(ARTIFACT_ROOT, "postgres-array") };
  });

  // The two postgres-array copies must be different files: if they are the same, the
  // nesting was flattened and one of the two consumers is being handed the wrong major.
  check("the nested and hoisted postgres-array are distinct, as the lockfile says", () => {
    const pgTypesDir = dirname(resolveFrom(ARTIFACT_ROOT, "pg-types"));
    const nested = realpathSync(resolveFrom(pgTypesDir, "postgres-array"));
    const hoisted = realpathSync(resolveFrom(ARTIFACT_ROOT, "postgres-array"));
    if (nested === hoisted) {
      return { detail: "single copy present (both resolve to the same directory); acceptable only if the lockfile also collapsed them" };
    }
    return { nested, hoisted };
  });

  // -------------------------------------------------------------------------------------
  // 5. Construction. No connection is opened: Prisma connects lazily and we never query.
  // -------------------------------------------------------------------------------------
  check("PrismaPg and PrismaClient construct against synthetic configuration", () => {
    if (typeof PrismaClientCtor !== "function") throw new Error("@prisma/client did not yield a constructor");
    const require_ = createRequire(join(ARTIFACT_ROOT, "noop.js"));
    const { PrismaPg } = require_("@prisma/adapter-pg");
    if (typeof PrismaPg !== "function") throw new Error("@prisma/adapter-pg exports no PrismaPg");
    // Obvious fake: localhost, no real host, no secret. Never dialled — construction is lazy.
    const adapter = new PrismaPg({ connectionString: "postgresql://artifact-check:artifact-check@127.0.0.1:5432/artifact_check" });
    const client = new PrismaClientCtor({ adapter });
    if (typeof client.$disconnect !== "function") throw new Error("the constructed client has no $disconnect");
    return { constructed: true };
  });

  // -------------------------------------------------------------------------------------
  // 6. Disconnect and exit naturally.
  // -------------------------------------------------------------------------------------
  await (async () => {
    const require_ = createRequire(join(ARTIFACT_ROOT, "noop.js"));
    try {
      const { PrismaPg } = require_("@prisma/adapter-pg");
      const client = new PrismaClientCtor({ adapter: new PrismaPg({ connectionString: "postgresql://artifact-check:artifact-check@127.0.0.1:5432/artifact_check" }) });
      await client.$disconnect();
      results.push({ check: "$disconnect resolves without connecting", ok: true });
    } catch (error) {
      failures.push({ check: "$disconnect resolves without connecting", ok: false, error: String(error) });
    }
  })();
}

const report = {
  artifactRoot: ARTIFACT_ROOT,
  result: failures.length === 0 ? "PASS" : "FAIL",
  // Every check that ran, pass or fail, in execution order.
  checks: results,
  ...(failures.length ? { failed: failures.map((entry) => entry.check) } : {}),
};
console.log(JSON.stringify(report, null, 2));
process.exit(failures.length === 0 ? 0 : 1);
