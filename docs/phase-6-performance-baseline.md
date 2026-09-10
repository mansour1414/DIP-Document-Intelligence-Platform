# Phase 6 performance baseline

Date: 2026-09-10. Scope: the 18 approved MVP tools. This is an initial engineering baseline, not a production SLO or commercial promise.

## Method

- Use generated, non-sensitive fixtures: one-page and multi-page PDFs plus small synthetic Office/OCR samples when host engines are available.
- Run the Node test runner serially on memory-constrained Windows hosts (`--test-concurrency=1`).
- Capture `api_job_creation_latency`, DB idempotency query latency, `queue_wait_time`, `job_duration`, PDF page render time, LibreOffice/OCR duration, AI/provider latency, storage read/write latency, bytes in/out, and compression ratio through structured metric events.
- CI uses PostgreSQL 16 and Redis 7. Real Gemini and external Object Storage remain conditional because they require credentials and can incur cost.
- Compare repeated runs on the same host; do not compare absolute local timings with CI or production.

## Baseline result

The deterministic unit corpus is recorded by the test command output and metric JSON lines. Production P50/P95 values are intentionally not claimed until representative production-class infrastructure and a monitoring backend are approved. Queue → worker → terminal-state integration is exercised in CI when PostgreSQL/Redis are present.

## Initial adjustable budgets

| Budget | Default |
| --- | ---: |
| Input bytes | 100 MiB |
| PDF pages | 500 |
| Rendered pixels/page | 40,000,000 |
| Output files/job | 500 |
| Output bytes/job | 250 MiB |
| Document worker concurrency | 2 |
| AI worker concurrency | 2 |
| PDF/job timeout | 180 s |
| LibreOffice timeout | 120 s |
| OCR timeout | 300 s |
| AI provider timeout | 60 s |

