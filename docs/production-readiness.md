# Production readiness gates

All numbers below are **engineering provisional**, not SLAs or marketing promises. Revalidate them from production-class P50/P95 telemetry before changing concurrency.

## Initial sizing

| Level | Web/API | Document worker | Concurrency | AI | Redis/Postgres | Temp disk |
| --- | --- | --- | --- | --- | --- | --- |
| Development | 1 vCPU / 1 GiB | 2 vCPU / 2 GiB | document 1 | AI 1 | single Redis; pooled app DB, direct migration URL | 2 GiB bounded |
| MVP Production | 1–2 vCPU / 2 GiB | 2–4 vCPU / 4 GiB | document 2 | AI 2, 10/min | durable Redis; pooled app DB, direct migrations; 10–20 app connections/instance initially | 10 GiB bounded |
| Growth threshold | scale after sustained queue depth >100 or P95 queue wait >60s | add worker replicas before raising per-process concurrency; 4 vCPU / 8 GiB class | validate 2–4 per worker | validate 2–4 and provider quota | HA/durable Redis; review pool budget across replicas | 20 GiB bounded/worker |

Storage is private S3-compatible object storage. No Kubernetes or vendor-specific compute assumption is introduced.

## Initial engineering SLOs

- API liveness target: 99.9% monthly; this is not an SLA.
- Job success target: ≥99% for valid deterministic inputs; provider and invalid-input failures are classified separately.
- Queue wait P95 <60s at MVP load. Low-resource deterministic P95 <30s; medium <120s; OCR/Office <300s.
- No job remains non-terminal past its timeout class plus 2 minutes.
- Eligible expired objects are processed within 24 hours; failed deletions retry on the next daily run.

## Alerts

`src/lib/observability/alerts.ts` defines configurable initial triggers: failure rate >5%/10m, queue depth >100/10m, stuck job >10m, Redis/worker/DB readiness failure >2m, ≥5 storage failures/5m, AI provider failure >10%/10m, any cleanup failure, temp disk >80%, and an AI hourly-cost threshold only after Finance/Product supplies a value (`0` disables it).

## Security and network controls

- Non-root web/workers with CPU, RAM and PID limits.
- Read-only root filesystem where possible; isolated bounded temp mount and no tenant-shared writable directory.
- Secret manager for DB, Redis, storage, Sentry and Gemini credentials; encrypted backups and restore drills.
- Deterministic workers may reach only DB, Redis and object storage. AI workers additionally reach approved Gemini endpoints. Enforce using container/firewall policy.
- Add malware scanning after validation and before durable storage/job creation before anonymous/public Office uploads. Macro-capable containers and native parsers make the risk material. Scanner selection is a Product/Security gate.

## Backup and restore

- Configure Neon restore window/snapshots for the selected plan and verify restoration into an isolated branch at least quarterly.
- Keep direct migration/restore and pooled runtime connections separate.
- Document object-storage durability/versioning; DB recovery alone cannot recreate missing file objects.
- Restore drill: isolated Postgres restore, representative object restore, checksum reconciliation, then job/file-lineage validation.

## Cost model

`src/lib/cost/model.ts` estimates CPU-ms, memory MB-ms, storage bytes/operations, AI tokens, OCR pages and Office duration from configurable rates. It returns cost per successful job without inventing cloud prices.

