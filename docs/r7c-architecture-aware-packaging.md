# R7C — Architecture-aware PDF worker packaging

**Status: implementation complete for x64 (executed). ARM64 execution is BLOCKED in the Arena sandbox and must be run natively.** This document records the defect, the selection model, the platform matrix, what was actually executed, and the exact commands to close the ARM64 gap.

## The defect

Two confirmed ARM64 packaging defects, found independently before this round:

1. `scripts/verify-pdf-worker-artifact.mjs` required `@esbuild/linux-x64` and `@napi-rs/canvas-linux-x64-gnu` as literal paths, so the ARM64 worker image build failed on a package the repository does not contain.
2. `next.config.ts` traced the same two x64 packages, so an emitted ARM64 standalone artifact lacked its own natives while the verifier still reported it complete.

Both had the same root cause: the platform package names were *literals* rather than a function of the target. A literal is correct on exactly one target and silently wrong on the others.

## The selection model

Selection lives in one module, `scripts/pdf-worker-platform.mjs`. The build config, the verifier and the Dockerfile all read it, so they cannot drift apart.

**The two axes are independent.** This is the part that is easy to get wrong:

| Axis | esbuild | canvas |
| --- | --- | --- |
| CPU (`x64` / `arm64`) | ✅ selects | ✅ selects |
| libc (`glibc` / `musl`) | ❌ no effect | ✅ selects |

`esbuild` publishes one *static* binary per CPU. Verified two ways: the lockfile contains `@esbuild/linux-x64` and `@esbuild/linux-arm64` with no musl variants, and `ldd node_modules/@esbuild/linux-x64/bin/esbuild` reports `not a dynamic executable`. `@napi-rs/canvas` publishes real per-libc binaries (`-gnu` / `-musl`), which is why Alpine and Debian need different packages.

Treating libc as a global axis would invent esbuild packages that do not exist. Treating it as irrelevant would ship a glibc canvas to Alpine, where it cannot load.

## Platform compatibility matrix

Four combinations, all using packages already in `package-lock.json`:

| CPU | libc | Image family | esbuild | canvas | Status |
| --- | --- | --- | --- | --- | --- |
| x64 | glibc | Debian worker, CI | `@esbuild/linux-x64` | `@napi-rs/canvas-linux-x64-gnu` | **PASS** — executed |
| x64 | musl | Alpine standalone | `@esbuild/linux-x64` | `@napi-rs/canvas-linux-x64-musl` | Selection verified; runtime **BLOCKED** |
| arm64 | glibc | Owner VPS (Ubuntu ARM64) | `@esbuild/linux-arm64` | `@napi-rs/canvas-linux-arm64-gnu` | Selection verified; runtime **BLOCKED** |
| arm64 | musl | Alpine ARM64 | `@esbuild/linux-arm64` | `@napi-rs/canvas-linux-arm64-musl` | Selection verified; runtime **BLOCKED** |

"Selection verified" means the resolver names packages that exist in the lockfile and the verifier demands exactly those — asserted by tests. It does **not** mean a native addon was loaded; only execution proves that.

## How the target is determined

Priority order, so a cross-build is never verified against its builder:

1. Explicit `--target-cpu=` / `--target-libc=` flags.
2. `node_modules/.dip-pdf-worker-target.json`, written by `scripts/write-pdf-worker-target.mjs`. The Dockerfile runs it with BuildKit's own `TARGETARCH`, which describes the **output** platform.
3. The running process (`process.arch` + `process.report` libc detection).

An unsupported CPU or libc exits **2** with the supported values named. There is no fallback to x64 — a silent fallback is precisely how a wrong-target artifact gets reported complete.

## What was actually executed (x64/glibc, this sandbox)

| Check | Result |
| --- | --- |
| `scripts/verify-pdf-worker-artifact.mjs .` (x64/glibc) | **PASS** — complete |
| Same root, `--target-cpu=arm64` | **FAIL as designed** — names `@esbuild/linux-arm64` and `@napi-rs/canvas-linux-arm64-gnu` |
| Same root, `--target-cpu=riscv64` | **exit 2** — unsupported CPU |
| Artifact marker `arm64/musl`, no flags | **PASS** — resolves arm64/musl from the marker |
| `smoke-pdf-worker-artifact.mjs . --in-place` | **6/6 scenarios PASS** |
| `test/pdf.worker-platform.test.ts` | **12/12 PASS** |
| `test/fill-forms.main-worker-parser.test.ts` | 8/8 PASS (drift test updated to the shared module) |
| Focused suites (worker bounds, concurrency, protocol, runtime) | 79/79 PASS |
| `eslint` on changed files | clean |
| `tsc --noEmit` | 454 = 452 baseline + 2 pre-existing `tmp/verify` scratch; 0 in changed files |

The six smoke scenarios are unchanged and still cover: inspect, fill, flatten, Arabic appearance with Unicode round-trip, the production runner inside the artifact, and the fd-3 frame protocol.

## BLOCKED in this environment

- **`next build` / the emitted standalone artifact.** `prisma generate` is TLS-blocked (`binaries.prisma.sh` unreachable), so no standalone tree can be produced here. The verifier was exercised against the repository tree and against synthetic roots instead.
- **ARM64 execution of any kind.** This sandbox is x64. No ARM64 hardware and no Docker, so neither `docker buildx --platform linux/arm64` nor a native ARM64 run was possible.
- **musl runtime.** No Alpine environment available.

## Reproducible ARM64 verification commands

Run these on the owner's Ubuntu ARM64 VPS (Docker 29.8.1, cgroup v2). They are the acceptance evidence this sandbox cannot produce.

```bash
# 0. Sanity: confirm the host really is ARM64 and glibc
uname -m                      # expect aarch64
ldd --version | head -1       # expect the glibc line

# 1. Worker image, built natively for the host
docker build -f Dockerfile.worker -t dip-document-worker:r7c-arm64 .
# The build itself runs, in order:
#   scripts/write-pdf-worker-target.mjs --root /app --libc glibc   (records arm64/glibc)
#   scripts/verify-pdf-worker-artifact.mjs /app                    (checks arm64 packages)
#   scripts/smoke-pdf-worker-artifact.mjs /app --in-place          (6 scenarios, real execution)
# A wrong-arch image fails at the verifier with the arm64 paths named.

# 2. Prove the image is really ARM64 and non-root
docker run --rm --entrypoint uname dip-document-worker:r7c-arm64 -m      # aarch64
docker run --rm --entrypoint id    dip-document-worker:r7c-arm64 -u      # 10001

# 3. Re-run the artifact gate explicitly (same flags Stage 3C uses)
docker run --rm --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777 \
  --tmpfs /tmp/dip:rw,nosuid,nodev,noexec,size=256m,uid=10001,gid=10001,mode=0700 \
  --entrypoint node dip-document-worker:r7c-arm64 scripts/verify-pdf-worker-artifact.mjs /app

# 4. Cross-build check: emit an arm64 artifact from an x64 builder
#    (proves TARGETARCH wiring, not just the native path)
docker buildx build --platform linux/arm64 -f Dockerfile.worker \
  -t dip-document-worker:r7c-cross --load .

# 5. Alpine ARM64 standalone: the musl path
#    A full next build needs a reachable Prisma engine download.
npx prisma generate
npm run build
node scripts/write-pdf-worker-target.mjs --root .next/standalone --cpu arm64 --libc musl
node scripts/verify-pdf-worker-artifact.mjs .next/standalone
node scripts/smoke-pdf-worker-artifact.mjs .next/standalone

# 6. Negative control: the verifier must REJECT the wrong target
docker run --rm --entrypoint node dip-document-worker:r7c-arm64 \
  scripts/verify-pdf-worker-artifact.mjs /app --target-cpu=x64 --target-libc=glibc
# expect: exit 1, naming @esbuild/linux-x64 and @napi-rs/canvas-linux-x64-gnu
```

Step 6 is the check that would have caught the original defect. If it passes, the verifier has regressed to a literal x64 assumption.

## Scope and what this does not decide

- **No new dependencies.** All packages come from the existing lockfile.
- **No post-build injection, no verifier substitution, no in-executor installs.** The verifier runs against whatever the build emitted.
- **B31-03 remains OPEN.** Option C (disposable isolated Docker executor per PDF operation) is the recommended candidate pending owner architecture approval. Its PoC resource limits are **not** production limits. No supervisor, daemon integration or isolation transport is implemented here.
- **CPU, memory, concurrency, billing, queue-recovery, retention and payload policies are unchanged.**
- **Dependency security:** Codex reported an `npm audit` summary of **15 findings, 2 critical**. This is **not** addressed in this round and requires a separate dependency-security assessment. No upgrades were performed.

## Files changed

| File | Change |
| --- | --- |
| `scripts/pdf-worker-platform.mjs` | **new** — the selection model (CPU × libc, both axes) |
| `scripts/write-pdf-worker-target.mjs` | **new** — records the artifact's target from BuildKit's `TARGETARCH` |
| `scripts/verify-pdf-worker-artifact.mjs` | target-aware; `--target-cpu`/`--target-libc`; reads the marker; exit 2 on unsupported |
| `next.config.ts` | traces all four native combinations instead of the two x64 literals |
| `Dockerfile.worker` | copies the two new scripts; records the target; verifies against it |
| `test/pdf.worker-platform.test.ts` | **new** — 12 regression tests for selection, rejection, and drift |
| `test/fill-forms.main-worker-parser.test.ts` | drift test now asserts against the shared module instead of literals |

---

# R7C.1 — ARM64 packaging and runtime compatibility

Independent native ARM64 acceptance (Codex, Ubuntu 22.04 ARM64, Docker 29.8.1) confirmed the **worker** image passes everything: build, Prisma generation, all six smoke scenarios including the hardened runtime container. That work is not reopened here.

The **application** image did not. This round corrects what was proven and records what remains open.

## Task A — application Dockerfile

**Defect:** `Dockerfile` ran `npm ci || npm install` and then `npm run build`, with no `prisma generate`. The generated client is what gives `@prisma/client` its exports, so compilation failed on ARM64 Alpine with the reported `TS2305` errors.

**Correction:**

| Before | After |
| --- | --- |
| `COPY package.json package-lock.json* ./` | `COPY package.json package-lock.json prisma.config.ts ./` + `COPY prisma ./prisma` |
| `RUN npm ci \|\| npm install` | `RUN npm ci` |
| — | `RUN npx prisma generate` before `npm run build` |

The unlocked fallback is gone: a broken lockfile must fail, not resolve a different graph. Generation needs the schema and `prisma.config.ts` only — `prisma generate` never connects, so no production credentials are required.

`next.config.ts` now also declares the Prisma runtime closure (`@prisma/client`, `.prisma/client`, `@prisma/adapter-pg`) on the database-touching routes. `.prisma/client` is generated into `node_modules` and is not a package anything imports by name, so it is exactly the kind of input a tracer can miss; the standalone tree would then ship a re-export with nothing behind it. No engine binary is included: this application queries through `PrismaPg`, not a native engine.

**Verification status: BLOCKED locally.** `prisma generate` fails here on TLS to `binaries.prisma.sh`, so no `next build` and no emitted application artifact could be produced in this sandbox. The correction is verified structurally (config parses, generation is ordered before build, closure declared, existing drift tests pass), not by an executed ARM64 build.

## Task B — Alpine Fill failure

### What was actually tested here (x64/glibc)

| Experiment | Result |
| --- | --- |
| Real spawned child, minimal env (`PATH`,`NODE_ENV`), Latin fill | **PASS** — `ok:true`, 1 page |
| Real spawned child, minimal env, Arabic fill (raster path) | **PASS** — `ok:true`, `rasterAppearances:1` |
| Same, with `TMPDIR=/tmp` and `HOME=/tmp` added | **PASS** — byte-identical result |
| Same, with `TMPDIR`/`HOME` absent | **PASS** — byte-identical result |
| **Font files hidden**, Latin fill | **PASS** (Latin uses vector appearance; fonts untouched) |
| **Font files hidden**, Arabic fill | **FAIL** — `FORM_UNSUPPORTED`, `{"reason":"UNEXPECTED"}` |
| Full 6-scenario smoke with fonts hidden | **1 of 6 failed** — only the Arabic scenario |

### What this establishes

1. **The TMPDIR hypothesis is falsified on glibc/x64.** The minimal environment, with and without `TMPDIR`/`HOME`, produces identical successful fills. OpenCode's hypothesis is not confirmed by this evidence.
2. **The masked code is not attributable.** Hiding the font files reproduces `{"reason":"UNEXPECTED"}` **exactly**, from a completely different cause than Alpine. So `UNEXPECTED` cannot be used to infer the Alpine cause.
3. **Latin fill does not exercise fonts.** `rasterAppearances:0` for Latin; only Arabic registers fonts and rasterises. This matters because on ARM64 **all four** appearance-generating operations failed, including Latin fill and flatten — which on glibc succeed even with every font file removed.

Point 3 is the reason Task B is **not** corrected here. If the Alpine failure were "fonts missing", Alpine Latin fill would have failed while glibc Latin fill survives without fonts — but glibc Latin fill is font-independent, so the divergence cannot be explained by font presence alone. The cause is **musl-specific behaviour I cannot reproduce**: this sandbox is x64 glibc with no Docker, so neither the musl canvas build nor Alpine could be exercised.

**Task B: BLOCKED.** No production correction is proposed. A correction without the demonstrated exception would be guesswork, and the task prohibits a speculative fix.

### Diagnostic harness (delivered)

`scripts/diagnose-pdf-worker-fill.mjs` — run inside the failing image:

```bash
docker run --rm --entrypoint node dip-document-app:r7c1 \
  /app/scripts/diagnose-pdf-worker-fill.mjs /app
```

It reports, as JSON: the detected platform, whether the two `.woff` files `registerFormFonts()` actually opens are present (the artifact verifier only checks the font *package*), then four per-stage probes inside a **real spawned child with the production minimal environment** (`font-resolve`, `canvas-load`, `font-register`, `text-measure`), then three full fills (Latin, Arabic, Arabic+TMPDIR). Each stage reports its **real** error code; production continues to return only the masked code.

Source-level differences from the OpenCode diagnostic, which is why this should be trusted over it: OpenCode called `fillFormPdf` **in-process** with a fuller environment; this harness spawns the actual child with the actual minimal environment over the actual fd-3 protocol, which is the path that fails.

## Task C — strict target-marker validation

**Defect:** `declaredTarget()` passed parsed marker values to `resolveTarget()`, which substitutes the running host for missing fields. Codex measured empty, CPU-only, libc-only and array markers all exiting **0**.

**Correction:** a present marker must be a complete, correctly typed, supported declaration. Rejected with **exit 2**: empty objects, partial declarations, arrays, `null`, primitives, non-string fields, empty/whitespace values, unsupported values, unknown fields, and invalid JSON. Host derivation now happens **only** when no marker and no override exist. Overrides are validated separately, require both fields, and are **refused if they contradict** the artifact's own marker rather than silently replacing it.

Re-measured, all 11 Codex rows plus the contradiction cases:

| Case | Before | After |
| --- | ---: | ---: |
| Valid target | 0 | **0** |
| Wrong CPU | 1 | **1** |
| Wrong libc | 1 | **1** |
| Invalid JSON | 2 | **2** |
| **Empty object** | 0 | **2** |
| **CPU-only marker** | 0 | **2** |
| **libc-only marker** | 0 | **2** |
| **Array** | 0 | **2** |
| Unsupported CPU | 2 | **2** |
| Declared wrong CPU | 1 | **1** |
| Declared wrong libc | 1 | **1** |
| Partial override | — | **2** |
| Override contradicts marker | — | **2** |

Both Dockerfiles now generate and ship a coherent marker from BuildKit's `TARGETARCH` (`Dockerfile`: musl; `Dockerfile.worker`: glibc), so the artifact describes itself and the verifier needs no flag.

**The marker did not cause the Fill failure** and is not claimed to have.

## Platform compatibility matrix

| Target | Packaging | Artifact selection | Native runtime |
| --- | --- | --- | --- |
| Linux x64 / glibc | **PASS** (executed) | **PASS** | **PASS** (executed here) |
| Linux x64 / musl | Structure verified | **PASS** | **BLOCKED** — no Alpine here |
| Linux ARM64 / glibc (worker) | **PASS** (Codex, native) | **PASS** | **PASS** (Codex, native) |
| Linux ARM64 / glibc (app) | **Correction written, build BLOCKED** | **PASS** | **FAIL** — Tasks A/B not yet re-tested natively |
| Linux ARM64 / musl (app) | **Correction written, build BLOCKED** | **PASS** | **FAIL** — Task B open |

Full R7C acceptance is **not** claimed: the application artifact has not been shown to succeed natively on ARM64.

## Native ARM64 acceptance commands

```bash
# Task A — the application build must now succeed, and the artifact must declare itself
docker build -f Dockerfile -t dip-document-app:r7c1 .
docker run --rm --entrypoint node dip-document-app:r7c1 -e \
  'console.log(require("fs").readFileSync("node_modules/.dip-pdf-worker-target.json","utf8"))'
# expect: {"cpu":"arm64","libc":"musl"}   (or x64 on an x86 builder)

# Task C — marker validation, all cases
docker run --rm --entrypoint node dip-document-app:r7c1 \
  scripts/verify-pdf-worker-artifact.mjs /app
# expect exit 0 on a coherent artifact; exit 2 if the marker is edited to {} / partial / array

# Task B — the diagnostic, inside the failing image
docker run --rm --entrypoint node dip-document-app:r7c1 \
  scripts/diagnose-pdf-worker-fill.mjs /app
# Read `stages` first: the failing stage names the real error.
#   font-register failing with FONT_UNAVAILABLE  -> font assets absent from the artifact
#   font-register failing with another code       -> musl font backend
#   canvas-load failing                           -> native addon resolution
#   all stages ok but minimalLatin/minimalArabic failing -> the child spawn path itself
# Then compare minimalArabic vs withTmpdirArabic to confirm or reject the TMPDIR hypothesis.

# Task D — the six scenarios, unchanged, against the emitted artifact
node scripts/smoke-pdf-worker-artifact.mjs .next/standalone
```

## Remaining blockers and risks

- **B31-03 remains OPEN.** Option C (disposable isolated Docker executor) is the recommended candidate but has no production architecture approval. No supervisor, daemon integration or isolation transport is implemented. PoC limits are **not** production limits.
- **Task B root cause unknown.** The Alpine failure is not explained by the evidence available here; the TMPDIR hypothesis is falsified on glibc. It needs the harness run on real ARM64 Alpine.
- **No ARM64 application acceptance.** Task A's correction is unverified by execution.
- **Dependency security deferred:** 21 npm audit findings before dev-dependency pruning, **15 after pruning, 2 critical** (Codex). Requires a separate dependency-security and licensing assessment. No upgrades, no `npm audit fix --force`, no new packages were added.
- **Groq evaluation:** HTTP 429 in CI run `45655814740`, independent of this work. No manual rerun performed.

---

# R7C.3 — Standalone Prisma Runtime Dependency Closure

## The failure

The R7C.2 ARM64 acceptance run built the image successfully and then stopped at the database
stop-gate:

```
require('@prisma/client')        -> returns
require('@prisma/adapter-pg')    -> MODULE_NOT_FOUND: Cannot find module '@prisma/driver-adapter-utils'
                                    at /app/node_modules/@prisma/adapter-pg/dist/index.js:38:36
```

Exit 1, not OOM. `pg` resolution, adapter construction, client construction and server startup
were never reached.

## The cause, reproduced rather than inferred

A standalone Next build of a minimal app using the **exact R7C.1 `PRISMA_RUNTIME_TRACING`
array** reproduces the production error character for character, including the `38:36`
throw location:

```
$ node -e "require('@prisma/adapter-pg')"        # from the artifact root
Error: Cannot find module '@prisma/driver-adapter-utils'
    at Object.<anonymous> (.../node_modules/@prisma/adapter-pg/dist/index.js:38:36)
```

The artifact contained:

| package | present | why |
| --- | --- | --- |
| `@prisma/adapter-pg` | **all 7 files** | the R7C.1 glob worked |
| `@prisma/client` | yes | the R7C.1 glob worked |
| `pg` | yes | Next externalises `pg` by default |
| `@prisma/driver-adapter-utils` | **absent** | nothing copied it |

`outputFileTracingIncludes` is a **file glob**. It copies what the pattern matches; it never
reads a `package.json`, so it does not know that `@prisma/adapter-pg` depends on
`@prisma/driver-adapter-utils`, `@prisma/debug`, `pg` and `postgres-array`. The adapter's
JavaScript was copied into the image and its dependency edge was dropped.

There is a second, independent defect underneath it. `@prisma/adapter-pg` is **not** in Next's
built-in external list (which contains `@prisma/client`, `prisma` and `pg`), so webpack
*bundled* it into the server chunk. Its bundled `require()` calls for the unlisted packages
were resolved at build time against a full `node_modules`; at runtime those packages were
simply not in the image.

Measured directly on the two builds:

| config | adapter in server chunk | adapter emitted as external |
| --- | --- | --- |
| R7C.1 (globs only) | yes — bundled | no |
| R7C.3 (externals + globs) | no | yes |

## The correction

Two mechanisms, both required:

1. **`serverExternalPackages`** — all 18 runtime packages of the closure. This is what makes
   the tracer emit each package *with its dependencies*, resolved from their real nesting.
   It also stops webpack inlining the adapter and leaving its requires unresolved.
2. **`outputFileTracingIncludes`** — the whole directory of each of those packages, plus the
   nested `pg-types/node_modules/postgres-array`, plus the generated `.prisma/client`.

Mechanism 2 is not redundant. With **externals and no globs**, a real build emitted:

```
node_modules/@prisma/adapter-pg/package.json
node_modules/@prisma/adapter-pg/dist/index.mjs
```

Two files. The package is dual-format: its `exports` map picks `dist/index.mjs` for `import`
and `dist/index.js` for `require`. The server bundle *imports* it, so the tracer followed the
ESM path; the shipped `server.js` is CommonJS and *requires* it, resolving to `dist/index.js`,
which was never emitted. `@prisma/driver-adapter-utils` and
`@prisma/client-runtime-utils` have the same split, so fixing one only moves the error to the
next one.

The globs therefore cover **both formats of every package**, and the route key is `"/"`
because `outputFileTracingIncludes` keys match with `contains: true`. The routes that actually
reach `src/lib/db/index.ts` are `/api/auth/signin`, `/api/auth/signup`,
`/api/auth/oauth/github/callback`, `/api/usage`, `/[locale]/agent`, `/[locale]/workflows` and
`/dashboard` — **not** the three PDF routes the R7C.1 array was keyed to. Keying the database
closure to `/` is what stops it depending on which route happens to run.

The closure is 18 packages, derived from `package-lock.json` and asserted equal to the
declaration by a test, so the two cannot drift. Deliberately excluded: `pg-cloudflare`
(optional Cloudflare Workers driver, never loaded here), `@types/pg` / `@types/node` /
`undici-types` (type declarations, never `require()`d), and any Prisma query engine binary
(queries go through `PrismaPg`).

## Verification

Local, executed:

| check | result |
| --- | --- |
| exact R7C.1 config reproduces the production `MODULE_NOT_FOUND` | **reproduced**, same module and `38:36` |
| corrected config emits the full closure | `adapter-pg` all 7 files, `driver-adapter-utils` all 7, nested `postgres-array@2` present |
| `require('@prisma/adapter-pg')` from the emitted artifact root | **loads** |
| `new PrismaPg({...})` in the emitted artifact | **constructs** |
| emitted `server.js` started, `GET /api/probe` (constructs `PrismaPg`) | **HTTP 200 `{"ok":true}`** |
| `scripts/verify-prisma-artifact-runtime.mjs` on the artifact | all adapter/pg/nesting checks **PASS** |
| `@prisma/client` + `PrismaClient` construction | **BLOCKED** — `prisma generate` is TLS-blocked here |
| R7C.1 regression suite + smoke | **37/37 tests, smoke 6/6** |

Not executed here, and not claimed: any ARM64 or Alpine run, genuine Prisma client
generation, `PrismaClient` construction, server startup of the **real** application, or the
six PDF smoke scenarios inside a rebuilt image.

## Acceptance gate for the artifact

`scripts/verify-prisma-artifact-runtime.mjs <artifact-root>` loads the closure **inside the
emitted artifact, outside the source checkout**. It refuses to run at all if it can find a
`.git` in any parent directory, because Node resolves `node_modules` by walking upward and
would then find the repository's own tree and pass against an empty artifact.

It checks, in order: `@prisma/client` loads; the generated client is present; the adapter
loads **and each of its `require()` targets resolves from the adapter's own directory** — the
check that would have caught this defect; `pg` loads and its requires resolve from `pg`'s
directory; the nested and hoisted `postgres-array` are distinct and are majors 2 and 3;
`PrismaPg` and `PrismaClient` construct; `$disconnect()` resolves. It opens no connection,
takes no credentials and runs no query.

It is wired into both places a broken closure can escape from:

- **`Dockerfile`** (runner stage, before `USER nextjs`): `RUN node scripts/verify-prisma-artifact-runtime.mjs /app`.
  This is inside the final image, so it checks what would actually ship — not the builder's
  fully-populated `node_modules`, which can never reproduce a packaging defect. This is the
  step that would have stopped the R7C.1 image before it was published.
- **`.github/workflows/ci.yml`** (build job, after `npm run build`, where genuine
  `prisma generate` succeeds): copies `.next/standalone` out of the checkout and verifies it.

## Native acceptance commands (next pinned ARM64 run)

```bash
# 1. Build (genuine Prisma generation happens in this step; it is TLS-blocked here)
docker build --platform linux/arm64 -f Dockerfile -t dip-document-app:r7c3 .

# 2. The gate now runs during the build. Independently, from the image:
docker run --rm --platform linux/arm64 --entrypoint node dip-document-app:r7c3 \
  scripts/verify-prisma-artifact-runtime.mjs /app
# expect exit 0

# 3. The exact stop-gate that failed in R7C.2, from the image root
docker run --rm --platform linux/arm64 --entrypoint node dip-document-app:r7c3 -e '
  require("@prisma/client");
  const { PrismaPg } = require("@prisma/adapter-pg");
  new PrismaPg({ connectionString: "postgresql://check:check@127.0.0.1:5432/check" });
  console.log("adapter closure OK");
'

# 4. Build marker and PDF artifact, unchanged from R7C.1
docker run --rm --platform linux/arm64 --entrypoint node dip-document-app:r7c3 \
  -e 'console.log(require("fs").readFileSync("node_modules/.dip-pdf-worker-target.json","utf8"))'
docker run --rm --platform linux/arm64 --entrypoint node dip-document-app:r7c3 \
  scripts/verify-pdf-worker-artifact.mjs /app

# 5. The six PDF scenarios, then the production runner under the restricted env
docker run --rm --platform linux/arm64 --entrypoint node dip-document-app:r7c3 \
  scripts/smoke-pdf-worker-artifact.mjs /app
```

`PrismaClient` construction and server startup still need a real generated client, so they are
covered by steps 1–2 in an environment where generation works; they remain **BLOCKED** here.

## R7C.3.1 — verifier correction

CI run `45750694222` failed the Build job with 10/11 jobs passing. The failing step was the new
artifact gate, and its log showed every packaging check **PASS** with only two **FAIL**:

```
@prisma/client loads     PASS
generated client dir     PASS
@prisma/adapter-pg       PASS
driver-adapter-utils     PASS
pg                       PASS
nested dependency        PASS
PrismaClient construction  FAIL  Error: @prisma/client did not yield a constructor
disconnect                 FAIL
```

That signature — packaging all green, construction failing with "did not yield a constructor" —
is a **verifier bug**, not a packaging one. Confirmed at the committed source:

```js
const PrismaClientCtor = check("@prisma/client loads", () => {
  ...
  if (typeof mod?.PrismaClient !== "function") throw new Error("...");
  return { path };          // <- metadata
});
...
if (typeof PrismaClientCtor !== "function") throw new Error("@prisma/client did not yield a constructor");
```

`check()` returns its callback's **detail object**, not the constructor. So `PrismaClientCtor`
was `{ path }`, and the construction check failed on every artifact, including a perfect one.

### Three corrections

1. **Separated executable references from report metadata.** The constructor is held in a
   module-level binding; `check()` returns only serializable detail. One client is constructed
   and that same object is disconnected — the previous version built a second client solely for
   the disconnect check, which proved less than tearing down the object it had built.
2. **Removed the nested-dependency false positive.** The check returned success when both
   `postgres-array` copies resolved to the same directory ("acceptable only if the lockfile also
   collapsed them"). It never did: `pg-types` declares `~2.0.0`, the adapter declares `3.0.4`.
   A flattened tree now fails, and each copy's major is read from its own `package.json` and
   compared against the required major. The majors are literals because the script runs inside
   the image where no lockfile exists; a repository test asserts they still match.
3. **Natural exit instead of forced termination.** `process.exit()` was replaced with
   `process.exitCode`. A forced exit terminates the process even with the client's pool still
   open, so it cannot distinguish a clean disconnect from a torn-down one. With a natural exit a
   leaked handle holds the event loop and the process hangs — visible, not hidden. An **unref'd**
   5s watchdog reports the live handle types without ever *keeping* the process alive, and
   external bounds (test timeout, CI step, Docker build) still own termination.

### Regression coverage

`test/prisma.artifact-runtime.test.ts` now has **16** tests. The two that matter most were
verified non-vacuous by reintroducing each bug:

| reintroduced bug | tests that failed |
| --- | --- |
| return `{ path }` into the constructor path | 7, 11, 12 |
| accept one shared `postgres-array` copy | 5, 6 |

Tests 11 and 12 are a pair: 11 proves a clean artifact exits naturally inside the external
bound (measured 64 ms), 12 proves a synthetic leaked interval holds the process open until the
bound kills it (exit 124, watchdog naming `Timeout`). Natural exit is therefore *exercised*, not
merely declared.

### Limitation — genuine client generation

`prisma generate` is still TLS-blocked here: it fetches the schema engine from
`binaries.prisma.sh` before writing anything, and it does so even for a driver-adapter client
with `engineType = "client"`. So the client lives in the tests is a small synthetic module
exporting a class with `$disconnect`, used **only** to exercise the verifier's control flow.
It asserts nothing about Prisma itself and is never used by CI or the Dockerfile; the genuine
generated-client gate keeps running there unchanged. No mock or stub replaces the real
acceptance path.

## Status

- **B31-03 remains OPEN.** **B31-04 remains OPEN** — production packaging acceptance is not
  closed by this change, because it has not been executed on ARM64.
- **R7C acceptance is NOT claimed.** What is claimed is narrower and evidenced: the packaging
  mechanism is identified and reproduced, the correction is implemented and verified in a real
  standalone build on x64, and an artifact gate now fails the build when the closure is broken.
- **R7D remains pending and unimplemented.**
- PR #31 remains **NO-GO** for merge; deployment remains **NO-GO**.
- npm audit findings are unchanged and remain a separate release risk (no upgrades, no
  `npm audit fix`).
