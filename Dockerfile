# Application image — Next.js standalone, Alpine (musl).
#
# ## Why Prisma generation is a build step, and not an afterthought
#
# `src/lib/db/index.ts` imports `PrismaClient` from `@prisma/client`, and the generated
# client is what gives that module its types. `@prisma/client` ships *without* a generated
# client: `prisma generate` produces it. Without that step `npm run build` fails with
#
#   TS2305: Module "@prisma/client" has no exported member "Prisma"
#   TS2305: Module "@prisma/client" has no exported member "PrismaClient"
#
# which is exactly what the ARM64 Alpine build reported. The worker image has always run
# generation explicitly (`Dockerfile.worker`); this image never did, and relied instead on
# an `npm ci || npm install` fallback that masked the missing step whenever the lockfile
# happened to resolve. Both are corrected here: the fallback is gone (an unlocked install
# in a production build is not reproducible) and generation runs before compilation.
#
# Generation needs the schema and `prisma.config.ts`, and no database: `prisma generate`
# reads the schema only. The datasource URL in `prisma.config.ts` resolves to `""` when
# neither variable is set, which is fine for generation — the CLI never connects. Real
# production credentials are therefore not required to build this image.
#
# ## What stays the same
#
# Non-root runtime (uid 1001), the standalone output model, port 3000, and the
# `node server.js` entrypoint are unchanged.

FROM node:22-alpine AS base

# Install dependencies only when needed
FROM base AS deps
WORKDIR /app
# R7C.1: the Prisma CLI reads `prisma.config.ts`, and the schema lives under `prisma/`.
# Both must be present for `prisma generate` to run at all, and both are small.
COPY package.json package-lock.json prisma.config.ts ./
COPY prisma ./prisma
# Deterministic, lockfile-only install. The `|| npm install` fallback that used to sit
# here could silently resolve a different dependency graph, so a broken lockfile produced
# an image that built but did not match the repository. A failure here is the correct
# outcome for a broken lockfile.
RUN npm ci

# Rebuild the source code only when needed
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# R7C.1: generate the Prisma client before anything type-checks or compiles. This is the
# step whose absence produced the TS2305 errors on ARM64 Alpine. It runs offline after
# `npm ci` (the engines are already in node_modules), needs no database connection, and
# produces the typed client that `src/lib/db/index.ts` imports.
#
# `DATABASE_URL` is deliberately not provided: `prisma generate` never connects, and
# passing a placeholder here would invite the belief that a real one is needed to build.
RUN npx prisma generate
RUN npm run build

# Production image, copy all the files and run next
FROM base AS runner
WORKDIR /app

ENV NODE_ENV production

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder /app/public ./public

# Set the correct permission for prisma output
RUN mkdir -p /app/prisma
COPY --from=builder /app/prisma ./prisma

# Automatically leverage output traces to reduce image size
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

# R7C.1: record which target this artifact was built for, so the PDF worker artifact can
# be verified against the *output* platform rather than the builder. TARGETARCH is
# BuildKit's value for the image being produced, and this image is Alpine throughout, so
# libc is always musl here.
ARG TARGETARCH
COPY --chown=nextjs:nodejs scripts/pdf-worker-platform.mjs ./scripts/pdf-worker-platform.mjs
COPY --chown=nextjs:nodejs scripts/write-pdf-worker-target.mjs ./scripts/write-pdf-worker-target.mjs
RUN node scripts/write-pdf-worker-target.mjs --root /app --libc musl

# R7C.3: prove the database runtime loads in *this* image before it is ever published.
#
# This runs inside the final image, so it checks the artifact that would actually ship —
# the traced `node_modules` tree, the generated client, and the real nesting — rather than
# the builder's tree, which has every package installed and can never reproduce a packaging
# defect. The R7C.1 image was built, published, and only then found to be unstartable at
# `require('@prisma/adapter-pg')`; this is the step that would have stopped it here.
#
# It runs as root, before `USER nextjs`. The check needs no privileges, but running it as
# the runtime user would require the files to be readable — which they must be anyway — and
# keeping it before the USER switch means a future permission mistake fails the build
# rather than the container.
#
# No DATABASE_URL is set and none is needed: Prisma constructs lazily, the script passes its
# own obviously-fake connection string, and no connection is opened.
COPY --chown=nextjs:nodejs scripts/verify-prisma-artifact-runtime.mjs ./scripts/verify-prisma-artifact-runtime.mjs
RUN node scripts/verify-prisma-artifact-runtime.mjs /app

USER nextjs

EXPOSE 3000

ENV PORT 3000
ENV HOSTNAME "0.0.0.0"

CMD ["node", "server.js"]
