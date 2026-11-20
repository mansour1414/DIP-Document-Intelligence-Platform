# Retention Dry-Run — Execution Location Alternatives

Status: **analysis only.** Supporting material for [CR-005](../cr-005-retention-dry-run-execution.md), which
is `PROPOSED — NOT APPROVED`. Neither option below is selected, provisioned or approved by this document.
No production system was contacted while preparing it.

Two locations are viable. They differ almost entirely in *where the credentials and the network path live*,
not in what the sweep does: the code path is identical (`npm run retention:dry-run`), and both are read-only.

---

## Option A — Private one-shot scheduler inside the existing worker boundary

A short-lived container, built from the existing worker image family, run once per day by the platform's own
scheduler.

**Shape**
1. `Dockerfile.worker` gains `scripts/cleanup-expired-jobs.ts` and `scripts/retention-dry-run.ts`
   (a copy line only; `tsx` is already a production dependency and `scripts/` is already partially copied).
2. Trigger: the existing cron / CronJob / systemd timer used by the platform — **to be verified**, because no
   scheduler manifest exists in this repository.
3. Credentials: `dip_retention` and a read-only Redis principal injected at container start from the existing
   secret manager. No credential is stored in GitHub.
4. Logs: the aggregate JSON report ships to the same private log store as worker logs.

**Security**
- Reuses the allowlisted egress path already granted to workers (DB, Redis, object storage). No new exposure.
- No public log surface; the report is aggregate-only by construction.
- `NODE_ENV=production` is already set in the worker image, so `readEnvironment()` requires `REDIS_URL` and
  `NEXT_PUBLIC_APP_URL` — both present in the worker environment, but confirm them for the scheduler container
  rather than assuming.

**Cost** — marginal: roughly one minute of existing CPU per day, plus log retention.

**Complexity** — image change (small), scheduler entry (needs verification), log shipping (usually already
solved for workers). No new secret store, no new network rule.

**Baseline compatibility** — the same Node 22 runtime, the same generated Prisma client and the same driver
adapter the workers already use. The one genuine blocker is the missing script copy.

**Verification required before use**
- [ ] A scheduler trigger exists and can run a one-shot container.
- [ ] The scheduler container's environment includes `REDIS_URL` and `NEXT_PUBLIC_APP_URL`.
- [ ] Redis read-only principal can read `bull:dip.document-processing.v1:*` and `bull:dip.ai-processing.v1:*`
      and is denied writes.
- [ ] The report lands in the private log store with a timestamp and operator identity.

---

## Option B — GitHub-hosted Actions runner (current scheduled workflow)

The workflow already in the repository, hardened for read-only operation.

**Shape**
1. `.github/workflows/retention.yml` runs on `ubuntu-latest` on a daily schedule and on dispatch.
2. It refuses any non-dry-run `RETENTION_APPLY` value, never passes the switch to the run step, runs
   `npm run retention:dry-run`, and uses `permissions: contents: read`.
3. Credentials: repository secrets `RETENTION_DATABASE_URL` and `RETENTION_STORAGE_BUCKET` (the storage key
   pair is not needed and is deliberately not passed to the run step).

**Security**
- The repository is **public**: job logs are public, and repository secrets are held by GitHub and reachable
  by any workflow in the repository. The dry-run's diagnostics are aggregate-only, which keeps this tolerable,
  but the posture must be accepted explicitly.
- GitHub-hosted egress addresses are dynamic and cannot be allowlisted, so production PostgreSQL **and** Redis
  must be reachable from the public internet over TLS. That is a standing attack surface, not a one-off cost.
- Action references are pinned by tag (`@v5`) today; pinning to commit SHAs is a prerequisite before
  production credentials are attached.
- `workflow_dispatch` executes the workflow file from the selected branch, so a dispatch from a feature branch
  runs that branch's code with production secrets. Restrict dispatch or require an environment gate.

**Cost** — zero: hosted minutes are free for a public repository.

**Complexity** — no new infrastructure, but the security work is larger: secrets in GitHub, an accepted public
log posture, network exposure for two stateful services, and SHA pinning.

**Baseline compatibility** — Node 22 on `ubuntu-latest` satisfies `engines >= 22.13.0`; `tsx`, Prisma
generation and the retention tests already run in this environment. Nothing in the sweep depends on the
worker image.

**Verification required before use**
- [ ] Both services are reachable from a hosted runner over TLS (or Option B is abandoned).
- [ ] Redis ACL user limited to reads on the two BullMQ key patterns.
- [ ] Actions pinned to SHAs; `permissions` confirmed minimal.
- [ ] Explicit acceptance of the public-log posture for a public repository.
- [ ] Report captured as an artifact or step summary for evidence retention.

---

## Side-by-side

| Dimension | A — Private scheduler | B — GitHub-hosted |
| --- | --- | --- |
| Credential location | Existing secret manager | GitHub repository secrets |
| Network | Existing allowlisted path | Public internet, dynamic egress |
| Log exposure | Private log store | **Public** (public repo) |
| New infrastructure | Image copy + scheduler entry | None |
| Security work | Redis ACL + topology check | Redis ACL + exposure sign-off + SHA pinning |
| Cost | Marginal, existing capacity | Zero |
| Code path | Identical (`npm run retention:dry-run`) | Identical |
| Principal blocker | Scheduler script missing from image; trigger unverified | Redis/PostgreSQL public reachability |

## Decision inputs the owner must supply

1. Is production Redis reachable from the public internet at all? *(If not, Option B cannot produce queue
   evidence and is not viable.)*
2. Does the private infrastructure have a usable one-shot scheduler?
3. Is the public-repository log posture acceptable for production run evidence?
4. Does the owner prefer the smaller infrastructure change (A) or the smaller infrastructure footprint (B)?

Whatever the answer, enabling `RETENTION_APPLY` is **not** part of this decision and requires its own approved
change request.
