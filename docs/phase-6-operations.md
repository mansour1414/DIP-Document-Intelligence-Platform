# Phase 6 operations and security

## Implemented in the application

- Per-tool upload MIME/magic-byte validation and page/file limits before storage.
- Bounded, sequential PDF page rendering with a per-page pixel ceiling and released PDF.js page/task resources.
- Bounded document/AI worker concurrency, retry attempts/backoff, stalled-job policy, lock duration and Redis command/connect timeouts.
- Separate PDF, LibreOffice, OCR, storage and AI timeout budgets.
- Non-shell LibreOffice/OCR process execution, controlled arguments, sanitized names, unique per-job temporary directory, dedicated LibreOffice profile, timeout termination and `finally` cleanup.
- Output signature/container/parseability, count, size and selected page-preservation validation before a job succeeds.
- Deterministic output keys, SHA-256 metadata, transactional output registration, idempotent job/credit/usage guards.
- Vendor-neutral structured metric events and redacted structured logging with job/tool/engine/version context.
- Lightweight liveness at `/api/health` and Redis+PostgreSQL readiness at `/api/readiness`.
- Retention/orphan selection policy that excludes active jobs and already-deleted objects. Final deletion periods remain provisional.

## Required at deployment/container layer

- Hard memory, CPU, process-count, temporary-volume and disk-quota limits.
- Deny arbitrary network egress for deterministic workers; allow only the approved AI provider path for AI workers.
- Read-only root filesystem where practical, patched LibreOffice/OCR system packages and a writable bounded temp mount.
- Production Redis sizing, worker/container replicas and concurrency validation against observed queue depth and memory.
- Monitoring backend, dashboards/alerts and Sentry project/DSN. The app must remain healthy without Sentry in development.

## Alert expectations

Alert on sustained failure-rate increase, oldest queued/running job age above its timeout class, queue depth exceeding validated capacity, retry spikes, provider errors/cost threshold, and cleanup failures. Vendor selection and final thresholds are Decision Gates.

## Turbopack / LibreOffice tracing

LibreOffice is discovered at runtime by spawning the fixed `soffice` executable. The warning was caused by Turbopack treating the dynamic `join(directory, name)` used for the unique `os.tmpdir()` workspace as potentially project-wide. The filename is sanitized and the directory is created by `mkdtemp`, so the documented `turbopackIgnore` marker is scoped only to that safe runtime join. The deployment-safe requirement is still to install `soffice` on the worker image PATH; the host binary is not bundled or traced into the Next.js artifact.

## Licensing gate

LibreOffice, OCRmyPDF, Ghostscript and all transitive/subprocess dependencies require deployment-distribution and commercial-use review. Installing an executable does not approve it. No new OCR engine or open model was adopted in Phase 6.

## Open-model evaluation gate

An open/open-weight candidate must demonstrate English and Arabic quality, structured extraction, citation grounding, prompt-injection resistance, acceptable latency/hardware/hosting cost, and commercially acceptable licensing. Current evidence does not justify adding a second provider, so Gemini remains the initial adapter behind Task → Policy → Routing → Provider → Validation → Usage Accounting.
