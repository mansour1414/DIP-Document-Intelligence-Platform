# R7D.1 — Isolated PDF executor

The executor is a disposable container that parses exactly one document and exits. It is the
untrusted end of the execution topology: everything it receives is hostile input, and it is
never given a credential, a database connection or the Docker socket.

This directory holds the packaging only. The Supervisor, Watchdog, admission control and
reconciliation are a later increment and are not present here — deliberately, rather than as
stubs, because an unimplemented security control that looks implemented is worse than a missing
one.

## Artifact inventory

| Path | Role |
| --- | --- |
| `Dockerfile.executor` | Three-stage build on the Debian/glibc Node 22 family |
| `Dockerfile.executor.dockerignore` | Narrow build context |
| `src/lib/pdf/executor-child.ts` | Container entrypoint: v2 control frame on stdin, result on fd 3 |
| `scripts/esbuild-executor.mjs` | Precompiles the child to CommonJS |
| `scripts/verify-executor-artifact.mjs` | Build-time verification; executes the bundle, does not read it |
| `test/r7d.executor-bridge.test.ts` | Real subprocess, real fd 3, real documents |

## Runtime dependency closure

Five packages, all already locked. **No package was added and the lockfile is untouched.**

| Package | Version | License | Why it is in the image |
| --- | --- | --- | --- |
| `pdf-lib` | 1.17.1 | MIT | The PDF engine |
| `@napi-rs/canvas` | 1.0.9 | MIT | Raster appearance fallback for non-WinAnsi values |
| `@fontsource/noto-sans-arabic` | 5.3.0 | OFL-1.1 | Arabic and Latin glyphs |
| `pako` | 1.0.11 | MIT AND Zlib | Flate streams (pdf-lib dependency) |
| `tslib` | 2.8.1 | 0BSD | Import helpers (pdf-lib dependency) |

Excluded, and asserted absent by the artifact verifier: `@prisma/client`, `prisma`, `ioredis`,
`bullmq`, `@aws-sdk/*`, `openai`, `groq-sdk`. The executor parses documents; it has no business
holding a database client or a cloud credential, and a credential reaching this image is a much
worse defect than a slow build.

## The one non-obvious build flag

`--packages=external` is a correctness requirement, not an optimization. Bundling would inline a
`require()` of a platform-specific `.node` binary and a `require.resolve` of the font files into
the JavaScript, and the artifact would then work only on the architecture that built it —
silently, failing at first document rather than at build time. Keeping packages external means
Node's own resolver finds them on the target platform, which is the behavior that already works
in the application worker.

The verifier checks this by calling `require.resolve` on both font files and comparing byte
sizes exactly (79 084 and 13 620), and by rendering a pixel through the native canvas. A copied
font file passes an existence check and fails both.

## Synthetic profile

| Resource | Value |
| --- | --- |
| Executors | 1 |
| CPU | 0.75 (quota 75 000 µs / period 100 000 µs) |
| Memory | 384 MiB, swap 0 |
| PIDs | 48 |
| tmpfs | 48 MiB `/work`, 16 MiB `/tmp`, both `noexec,nosuid,nodev` |
| V8 old space | 256 MiB |
| Deadline | 20 s |
| Fixtures | ≤ 1 MiB |

The V8 cap is a heap cap, not an RSS limit. The container memory limit is what bounds RSS; the
heap cap only makes the process fail fast instead of thrashing inside it.

## What is verified, and what is not

**Verified in this environment** (`test/r7d.executor-bridge.test.ts`, executed):

- the built bundle answers `--self-check` with protocol version 2 and exit code 0;
- a real inspect request travels stdin → child → fd 3 and returns both fixture fields;
- a real fill returns the document on fd 3 with metadata whose `outBytes` equals the bytes that
  actually arrived, and the reopened PDF contains the written value;
- verify is confirmed by a **second, independent process** that has never seen the input;
- a non-PDF produces a refusal frame with exit code 0, not a crash, and the refusal does not echo
  the document;
- a truncated frame is refused before the engine sees it;
- an empty stdin exits rather than hanging;
- the bundle contains no TypeScript loader and no test framework.

**NOT TESTED — requires Docker, which is unavailable here:**

- the image builds, and layer contents match the inventory above;
- `verify-executor-artifact.mjs` passes. It is written and referenced by the Dockerfile but has
  never been executed, because it needs the built image;
- read-only rootfs, tmpfs flags, `cap-drop ALL`, `no-new-privileges`, seccomp and AppArmor are
  effective;
- private PID and cgroup namespaces are established;
- the cgroup memory, CPU and PID limits are enforced;
- `/dev/mqueue` is masked;
- log driver `none` suppresses output.

Source-level packaging can be argued from the files. OS-level enforcement cannot be argued at
all — it is either observed on a running daemon or it is an assumption, and this document does
not make assumptions into findings.

## Compatibility note

Verify's document bound is the same hard input ceiling as fill (512 MiB), and its result metadata
bound remains 4 MiB. Neither silently reduces previously supported behavior: the executor cannot
be asked to verify a document larger than fill could have produced.
