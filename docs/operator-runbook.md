# Production operator runbook

This runbook covers the existing modular monolith. It does not authorize deployment.

## Release prerequisites

- Build the web image with `Dockerfile` and the separate document-worker image with `Dockerfile.worker` from the same commit. The worker contains the existing BullMQ entrypoint, LibreOffice, qpdf, Tesseract `eng`/`ara`, OCRmyPDF 17.10.0 and pypdfium2 5.13.0, and must pass `python scripts/verify-ocr-runtime.py` with Ghostscript absent.
- Run both as non-root with bounded CPU, RAM, PIDs, and temporary disk. The document worker requires a read-only root filesystem plus two bounded tmpfs mounts: `/tmp` as `rw,nosuid,nodev,noexec,size=64m,mode=1777` for LibreOffice pipe semantics, and the nested private workspace `/tmp/dip` as `rw,nosuid,nodev,noexec,size=256m,uid=10001,gid=10001,mode=0700`. Do not replace these with a writable root filesystem or writable `/var/tmp`.
- Allow deterministic workers to reach only PostgreSQL, Redis, and object storage. AI workers may additionally reach the configured AI Gateway/provider endpoint.
- Run the pinned ClamAV scanner image as a separate private service. Do not expose port 3310 publicly. Permit signature-update egress only to approved mirrors and verify the database freshness before accepting traffic.
- Configure the monitoring sink/Sentry project and route thresholds from `src/lib/observability/alerts.ts` to on-call alerts.

## Production environment checklist

Keep secrets in the deployment secret manager, never Git or images.

- Database: `DATABASE_URL` is the pooled, least-privilege `dip_app` URL. `DATABASE_URL_UNPOOLED` is the separately protected direct owner URL for provisioning, migrations, dumps, and restore drills only. Require certificate verification with `sslmode=verify-full`.
- Redis: `REDIS_URL` uses TLS/authentication and a private, durable endpoint.
- Storage: configure `STORAGE_ENDPOINT`, `STORAGE_BUCKET`, `STORAGE_ACCESS_KEY`, `STORAGE_SECRET_KEY`, and `STORAGE_REGION`, or the supported `AWS_*` equivalents. Keep the bucket private and scope credentials to the required bucket/prefix.
- Malware scanning: configure private `CLAMD_HOST`/`CLAMD_PORT`, `MALWARE_SCAN_TIMEOUT_MS`, and `MALWARE_SCAN_MAX_BYTES`. Set clamd `StreamMaxLength` to at least the application scan maximum (100 MiB baseline). Readiness policy must keep public job intake closed until the scanner and signatures are healthy.
- Auth: configure high-entropy `AUTH_SECRET`, `API_KEY_PEPPER`, and `RATE_LIMIT_KEY_SECRET`. Register exact OAuth callbacks and configure a provider only when enabled.
- AI: the production default is stable `gemini-3.8-flash`, with `GEMINI_MODEL` and `GEMINI_MODEL_<ROUTE_CLASS>` remaining explicit overrides. Configure the provider credential, timeouts, hard token budget, concurrency, and rate limits. DIP's default Standard pricing schedule is date-aware: $0.75/$3.75 per million input/output tokens through 2026-12-31 and $1.50/$7.50 from 2027-01-01, based on [Google's published Gemini 3.8 pricing](https://ai.google.dev/gemini-api/docs/pricing) audited on 2026-09-21. Leave `GEMINI_*_USD_PER_MILLION` blank to use that schedule. A model override must set both prices from its approved provider contract; missing or partial override pricing fails closed. Audit configured prices at contract renewal. `AI_ENABLED` and `GEMINI_ENABLED` are kill switches.
- CR-002 permits `groq/openai/gpt-oss-120b` only in the isolated evaluation path. It requires `GROQ_EVALUATION_ENABLED=1` and `GROQ_API_KEY`. The approved price schedule effective 2026-09-21 is $0.15/$0.60 per million input/output tokens from `https://console.groq.com/docs/model/openai/gpt-oss-120b`. `GROQ_INPUT_USD_PER_MILLION` and `GROQ_OUTPUT_USD_PER_MILLION` are optional paired contract overrides; a partial override fails closed. `GROQ_ENABLED=false` is its provider kill switch. Never pass these evaluation variables to the production worker until a later CR approves production routing.
- App: set the canonical HTTPS `NEXT_PUBLIC_APP_URL` at build and runtime.
- Limits: review all `API_RATE_LIMIT_*`, `MAX_*`, worker concurrency/timeouts, BullMQ stalled settings, retention/apply flag, and cost-rate settings against measured capacity.
- Monitoring: configure `SENTRY_DSN`, sampling, and every `ALERT_*` threshold. Verify logs and metrics reach the selected backend without content or credentials.
- Scheduler: review a dry run, then run `npm run jobs:cleanup` daily with `RETENTION_APPLY=1`.

## Migration and rollback

1. Back up the database and record the object-store version/checkpoint. Test migrations on an isolated production-like branch.
2. Using the direct owner URL, run `prisma/bootstrap/roles.sql`, `npm run db:migrate:prod`, then `prisma/bootstrap/dip_app.sql`. Never migrate through the pooled runtime URL.
3. Verify `dip_app` is `NOSUPERUSER NOBYPASSRLS`, run the RLS/security suite, then start web and workers from the same commit.
4. For application rollback, stop intake, let compatible workers drain, and restore the prior immutable image. Migrations are forward-only: use a reviewed compensating migration, never `migrate reset` or destructive ad-hoc DDL.
5. If schema compatibility cannot be preserved, restore matching PostgreSQL and object-store versions into isolation, reconcile checksums/file lineage, then perform a controlled cutover.

## Backup and restore drill

- Configure point-in-time database recovery and object-store versioning/lifecycle to approved RPO/RTO values. Encrypt backups and restrict restore credentials.
- At least quarterly, restore both into isolation, verify object checksums and DB keys, run migrations/readiness/RLS tests, and process a representative job end to end.
- Record recovery time, missing objects, checksum failures, and corrective actions. A database-only restore is incomplete because binaries live in object storage.

## Secret rotation

- Rotate DB, Redis, storage, OAuth, provider, and Sentry credentials with overlap where supported; update workloads, verify readiness/E2E, then revoke old credentials.
- Rotating `AUTH_SECRET` invalidates sessions unless a reviewed multi-key verifier is introduced.
- `API_KEY_PEPPER` has no multi-pepper verifier. Issue replacement API keys under the new pepper, communicate the cutover, switch the secret, then revoke old keys. Never change it in place without this plan.
- Rotating `RATE_LIMIT_KEY_SECRET` resets limiter buckets; schedule and monitor it.

## Incident response and kill switches

1. Declare severity, preserve correlation/request/job IDs and audit/security events, and restrict log access. Never copy content or credentials into incident channels.
2. Contain by disabling `AI_ENABLED`/`GEMINI_ENABLED`, or `GROQ_ENABLED`/`GROQ_EVALUATION_ENABLED` for CR-002 evaluation, disabling a registry tool, deactivating the affected client/key/organization, stopping public intake, or scaling workers to zero. Never bypass the Tool Registry.
3. For credential exposure, rotate and revoke; for suspected tenant isolation failure, stop affected routes and preserve DB/audit evidence.
4. Recover through the normal migration/restore path. Validate readiness, RLS/cross-tenant tests, and processing E2E before gradual reopening.
5. Record timeline, scope, impact, root cause, prevention, and required legal/privacy notifications.

## Monitoring minimums

Alert on readiness, queue depth and oldest age, stuck jobs, latency and terminal outcomes, retries/stalls, worker CPU/RAM/temp disk, storage latency/failures/capacity, cleanup failures, AI usage/cost/provider failures, API latency/status/rate-limit outcomes, auth failures, and privilege/key lifecycle events. Investigate using `correlation_id`, `request_id`, and `job_id`; never trust user-supplied headers for tenant or limiter identity.

## AI retry and diagnostics policy

- AI jobs use five BullMQ attempts with 2-second exponential backoff and 50% jitter. The four nominal retry delays are 2, 4, 8, and 16 seconds; BullMQ jitter randomizes each delay between 50% and 100% of that value. HTTP 408, 429, 5xx, network errors, and provider timeouts are retryable; permanent client/provider errors use BullMQ's unrecoverable-error path and stop after the current attempt. Deterministic PDF, Office, and OCR queue policy is unchanged.
- Internal failure diagnostics retain only provider, resolved model, HTTP/provider status codes, retryability, attempt number, latency, job/correlation identifiers, and the stable DIP error code. Prompts, document content, credentials, and complete provider payloads must never be logged or persisted.
