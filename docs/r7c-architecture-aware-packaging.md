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
