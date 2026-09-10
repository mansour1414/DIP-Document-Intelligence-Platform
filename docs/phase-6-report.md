# Phase 6 — Optimization report

Date: 2026-09-10

1. **Phase 6 status — Partially Completed.** Application-level optimization/hardening is implemented and local quality gates pass. Production-provider and host-engine gates remain.
2. **Performance baseline.** Methodology and adjustable budgets are in `phase-6-performance-baseline.md`. On the final local synthetic two-page run, PDF rendering was 204.9/56.1 ms for PDF→JPG and 52.2/49.2 ms for compression; full related tests were 2.61 s and 153.6 ms respectively. These are host observations, not SLOs.
3. **Queue optimization.** Both BullMQ queues retain bounded attempts/backoff/history; document and AI concurrency, limiter, stalled interval/count and lock duration are centralized environment settings. Queue depth helper and queue-wait metrics are available.
4. **Job reliability.** Terminal failure classification, worker timeout, retry state, cancelled/expired checks and idempotent succeeded-job skips remain in place. Full cooperative cancellation inside PDF.js is still limited.
5. **Resource limits.** Central limits cover input bytes, pages, rendered pixels/page, output count/bytes, extracted text, AI output tokens and concurrency.
6. **Timeouts.** Separate PDF/job, LibreOffice, OCR, storage and AI limits are configurable. Storage uses abort signals; subprocesses receive TERM then KILL escalation.
7. **Temp filesystem/cleanup.** Unique `mkdtemp` directory, sanitized basename, dedicated LibreOffice profile and unconditional recursive cleanup are implemented. Failure cleanup regression coverage exists at the policy/unit boundary.
8. **Output validation.** PDF signature/parseability/page semantics, JPEG signature, Office ZIP signature, output count and total bytes are checked before success; failures use `OUTPUT_VALIDATION_FAILED`.
9. **PDF rendering.** Sequential rendering, page/pixel bounds, per-page cleanup/task destruction and render timing are implemented. One PDF.js transfer copy remains intentional to preserve retry-safe input.
10. **LibreOffice.** Non-shell controlled spawn, private profile, timeout and expected-output checks are implemented. Turbopack warning was a false-positive trace on the unique temp-path join; a narrowly scoped documented ignore fixes it. Final build emits no warning.
11. **OCR.** Language selection, distinct timeout and duration instrumentation exist. Host corpus execution is blocked locally because OCRmyPDF/Tesseract are absent; commercial licensing is not approved.
12. **Corpora.** Generated PDF/security cases and AI fake-provider cases are automated. The repository contains corpus rules; real Arabic/English Office and OCR smoke execution awaits approved host engines. No personal documents are stored.
13. **Storage/retention.** Deterministic output keys, checksum/content type, abortable timed operations, cleanup selection and orphan idempotency policy exist. Final retention deletion periods and production scheduler remain Decision Gates.
14. **Database performance.** The hot idempotency lookup is timed and already uses the `(toolId,idempotencyKey)` unique index. Existing status/requester/time indexes match observed polling/dashboard/accounting patterns; no speculative index was added. No production `EXPLAIN ANALYZE` was run.
15. **Idempotency/retry.** Job uniqueness, deterministic object keys, transactional output registration, credit ledger uniqueness and AI usage advisory locking remain. Redis retry test verifies one logical output.
16. **Logging.** Structured JSON logging redacts content/prompt/credential/secret/token/signed-URL fields and records safe job/tool/engine/version/duration/status/error context.
17. **Metrics/observability.** Vendor-neutral metric events cover job totals/success/failure/duration, queue wait/depth, render/Office/OCR/storage latency, sizes, compression ratio and existing AI tokens/latency/cost. Dashboard vendor is not selected.
18. **Cost accounting.** AI estimated cost and tokens, storage bytes, duration and resource class foundations exist. Infrastructure cost per successful job awaits approved unit-cost inputs.
19. **AI cost routing.** Pipeline order remains Task → Policy → Routing → Adapter → Validation → Accounting. Internal `high_accuracy`, `balanced`, and `economy` route classes can select environment-configured Gemini models without exposing a new user feature.
20. **Open models.** No open model adopted: current evidence does not justify quality/cost/license risk. Evaluation criteria are documented.
21. **Security regression.** Existing document-scope, forced-RLS, least-privilege bootstrap, billing idempotency, upload validation and no-direct-Gemini tests pass or remain CI integration checks.
22. **License review.** Registry added for direct/native/subprocess components. Ghostscript remains a blocking commercial licensing gate if selected in the production OCR chain.
23. **Dependency security.** `npm audit`: 0 critical/high/moderate/low across 805 dependencies; no forced upgrade applied.
24. **Real Redis queue E2E.** Added success/retry/failure/idempotent-output integration using real BullMQ/Redis. It runs in GitHub CI; local execution was skipped because Redis/Docker is unavailable.
25. **Tests.** 61 total; 57 passed; 0 failed; 4 skipped (visual artifact opt-in, external Object Storage, Redis CI integration, pooled-RLS integration).
26. **Lint/typecheck/build.** ESLint passed; TypeScript passed; Next.js 16.3.4 Turbopack production build passed and generated 59 pages.
27. **CI status.** Workflow retains Node 22, PostgreSQL 16, Redis 7, roles bootstrap, `prisma migrate deploy`, grants reconciliation, lint/typecheck/build/test. Remote run status was not available from this workspace.
28. **Official MVP scope.** Registry and SEO tests confirm 18 official tools and 36 localized SEO pages, including Excel→PDF and PowerPoint→PDF.
29. **Decision Gates.** Production Redis/worker sizing, monitoring vendor and alert thresholds, Sentry SDK/project/DSN, open-model adoption, OCR/Ghostscript licensing, final retention periods/scheduler, production SLOs and concurrency sizing.
30. **Remaining Phase 6 work.** Run Office/OCR corpora on the approved image; run PostgreSQL/Redis/Object Storage integrations in CI/production-like infrastructure; implement approved retention scheduler/deletion transaction; attach approved Sentry/metrics backend; measure P50/P95 and cost with production-class fixtures.
31. **Baseline conflicts.** None found. CR-002 and the 18-tool product scope are preserved; no Phase 7–9 features, provider, payment system, Kubernetes or microservices were added.

