# CR-005 Retention Dry-Run Execution Location

**Status: `PROPOSED — NOT APPROVED`**

This document **does not approve itself** and confers no authority to act. It records a decision that is
required before any production-connected retention run. Nothing here authorises provisioning credentials,
connecting to production PostgreSQL/Redis/object storage, enabling `RETENTION_APPLY`, changing the
scheduled workflow's execution location, or dispatching it. Approval must be recorded explicitly by the
owner in the decision register; until then the repository default remains the current scheduled
GitHub-hosted dry-run, which is read-only and applies nothing.

---

## 1. Identifier verification

| Check | Result |
| --- | --- |
| `CR-002` | `docs/cr-002-groq-evaluation.md` — Groq GPT-OSS evaluation |
| `CR-003` | `docs/cr-003-groq-production-routing.md` — Groq production routing |
| `CR-004` | **Already assigned** in the decision register to *Competitive Parity Adoption*; it is not a retention identifier and is not reused here. |
| `CR-005` | **Unused.** No document, comment, test or reference in this repository contains `CR-005` before this file (`grep -rn "CR-005" .` returns nothing outside this document and its cross-references). |

The earlier retention readiness audit (`docs/operations/retention-dry-run-readiness-2026-11-20.md`) used
“CR-004” informally for a proposed retention change; that reference was a collision and has been corrected
to `CR-005` in the same pull request that adds this document.

---

## 2. Decision requested

Where does the **first production-connected retention dry-run** execute?

Two options are documented in full in
[`docs/operations/retention-dry-run-execution-locations.md`](retention-dry-run-execution-locations.md):

| Option | Summary | Status here |
| --- | --- | --- |
| **A — Private one-shot scheduler** inside the existing worker boundary | One-shot container using the same network path, secret manager and image family as the document worker. Requires the scheduler script in the worker image and a scheduler trigger (cron/CronJob/systemd timer). | Not chosen. **Subject to topology verification** (§4). |
| **B — GitHub-hosted Actions runner** (current scheduled workflow) | The existing `Retention Dry-Run` workflow, hardened for read-only use. | Current default, read-only only. **Subject to network/security review** (§5). |

This CR does **not** select an option. Selecting one is the owner's decision, and the outcome determines
which of §4 or §5 must be satisfied first.

---

## 3. What is already true regardless of the decision (code readiness)

Established by the pull request that accompanies this CR, without touching production:

1. The dry-run path does not construct an S3 client and needs no S3 endpoint, access key or secret key.
   `STORAGE_BUCKET` is still required because storage-scope validation compares the `provider`/`bucket`
   recorded in PostgreSQL metadata against the configured scope — no object-store call is made.
2. Dry-run performs zero PostgreSQL mutations and zero object-storage operations; a regression fails both
   the hermetic tests and the runtime self-check (`RETENTION_DRY_RUN_MUTATED`).
3. Apply is unchanged and still fail-closed: storage-scope blocking, storage-first ordering, per-object
   scope proof, failure counting and the "leave the document ACTIVE for retry" rule all remain.
4. Missing or unreachable Redis produces `unknown` queue evidence, which can never authorise expiry, and is
   reported as such (`redis_configured`, `queues_expected`, `queues_read`, `failed_reads`, `queue_unknown`).
5. A dedicated dry-run-only entrypoint exists (`npm run retention:dry-run`). It rejects `RETENTION_APPLY=1`
   and every apply-shaped argument, and has no destructive mode.
6. The scheduled workflow cannot enter apply mode: it refuses any non-dry-run `RETENTION_APPLY` value,
   never passes the switch to the run step, and runs with `permissions: contents: read`.

Operational readiness is **not** established by any of the above. See §6.

---

## 4. Conditions attached to Option A (private one-shot scheduler)

Before this option may be used for a production-connected dry-run:

- **Topology verification**: confirm that a scheduler trigger exists (cron/CronJob/systemd timer) and that
  its execution context can reach PostgreSQL and Redis on the same allowlisted path as the workers.
- **Image change**: `Dockerfile.worker` must include `scripts/cleanup-expired-jobs.ts` (and the new
  `scripts/retention-dry-run.ts`) before any container can run the sweep.
- **Credential delivery**: `dip_retention` and a read-only Redis principal are injected from the existing
  secret manager at container start; no credential enters GitHub.
- **Log capture**: aggregate diagnostics are shipped to the private log store so evidence is retained.
- **Note**: the worker image sets `NODE_ENV=production`, which makes `readEnvironment()` require
  `REDIS_URL` and `NEXT_PUBLIC_APP_URL`. Both are already present in the worker environment; verify this
  explicitly for the scheduler container rather than assuming it.

## 5. Conditions attached to Option B (GitHub-hosted Actions runner)

Before this option may be used for a production-connected dry-run:

- **Network review**: production PostgreSQL and Redis must be reachable over TLS from GitHub-hosted
  runners, whose egress addresses are dynamic and cannot be allowlisted. If Redis has no public endpoint,
  this option cannot produce queue evidence at all and must be abandoned in favour of Option A.
- **Security review**: the repository is public, so job logs are public and repository secrets are held by
  GitHub. Approval must explicitly accept that posture for the two credentials this option needs.
- **Supply chain**: action references should be pinned to commit SHAs before production credentials are
  attached (currently `@v5` tags); `permissions: contents: read` is already in place.
- **Evidence retention**: the aggregate report must be captured as an artifact or step summary.

---

## 6. Explicitly out of scope / not approved by this CR

- Provisioning any secret, role, environment or repository setting.
- Enabling `RETENTION_APPLY` in any location.
- Any change to retention periods (`2026-09-provisional-v2`: FREE 7 days, PRO 30 days) or job-lifecycle
  rules.
- Any change to RLS architecture or `dip_retention` grants.
- Any production cleanup, deletion or data migration.
- **Operational readiness in general.** Code readiness and operational readiness are separate gates; this CR
  covers one decision inside the latter.

## 7. Approval record

| Field | Value |
| --- | --- |
| Approved by | *(blank — not approved)* |
| Date | *(blank)* |
| Selected option | *(blank — A or B)* |
| Conditions accepted | *(blank)* |
| Follow-up change request for apply | *(not opened; apply remains disabled)* |
