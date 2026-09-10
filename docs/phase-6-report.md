# Phase 6 Completion — Production Readiness Gates

Date: 2026-09-10

1. **PHASE 6 FINAL STATUS — BLOCKED.** All repository-level technical foundations are implemented and local gates pass. Completion cannot be claimed until the new required CI integration job passes and the Product Owner approves one OCR launch/licensing option.
2. **Remaining gates before this run.** Office/OCR execution, real Redis/Postgres/S3 integration, full/failure E2E, executable retention, Sentry, complete metrics, sizing/SLOs/alerts/cost/security/backup documentation, and final license analysis.
3. **Office corpus results.** Safe generator covers English, Arabic RTL, mixed Word with tables/images; multi-sheet/print-area/Arabic/chart Excel; English/Arabic/images/common-layout PowerPoint. Real LibreOffice validation is mandatory in `Integration / Processing`; it records duration, pages, validity and non-pixel-perfect smoke status. This Windows host has no LibreOffice, so no local execution result is claimed.
4. **OCR corpus results.** Safe generated English, Arabic, mixed, clean/blurred and multi-page scans are processed by real OCRmyPDF/Tesseract in the heavy CI job. Tests require searchable text, preserved page count and valid PDF. No 100% accuracy claim. This host lacks OCR binaries, so execution evidence must come from CI.
5. **OCR/Ghostscript licensing.** Command is fixed to standard PDF and optimization 0; CI installs pypdfium2 and fails if `gs` exists. **LICENSING GATE: Blocked pending Product Owner decision.** Recommendation: approve the defined Ghostscript-free Option B after CI and legal/image-manifest review.
6. **Redis/BullMQ.** Real Redis 7 tests cover enqueue, pickup, terminal success/failure, retry and idempotent output; application-worker E2E uses the same Redis service. Priority/stalled policy remains bounded and instrumented.
7. **PostgreSQL.** CI uses PostgreSQL 16, roles bootstrap → `prisma migrate deploy` → grants reconciliation. Runtime URLs now activate RLS integration, including no BYPASSRLS/no DDL/fail-closed/cross-tenant checks.
8. **Object Storage.** Heavy CI starts isolated MinIO, creates a bucket, and runs real Put/Head/Get/Delete/checksum/content-type plus worker multi-output storage tests. No production secrets.
9. **Full worker E2E.** Upload/orchestrator → DB → Redis → document worker → PDF/LibreOffice → S3 → DB output/ToolExecution → terminal result for Merge PDF, PDF→JPG and Word→PDF.
10. **Failure/retry E2E.** Redis integration covers real retry/failure terminal behavior; validation/timeout/storage/engine tests cover classified failures. Successful retries use deterministic keys and one logical side effect.
11. **Retention policy.** `2026-09-provisional-v2`: Free inputs/outputs 7 days, Pro 30 days, failed jobs 7/30 days, temp 1 hour, audit 365 days, billing 2555 days. Values are existing/provisional rather than new commercial promises.
12. **Deletion scheduler.** Daily GitHub scheduler and manual dispatch call the existing monolith script. It defaults to dry-run unless `RETENTION_APPLY=1`, deletes storage first, marks metadata, retries partial failures and protects all active-job file IDs including params.
13. **Cleanup.** Integration verifies expired deletion, storage call, metadata status, active/running protection and idempotent retry. Failures remain eligible and increment `cleanup_failure_total`.
14. **Sentry.** Official `@sentry/nextjs` 10.74.0 is wired through Next instrumentation and workers. It is disabled without DSN, excludes PII/request bodies/cookies/query strings/error messages, recursively redacts sensitive keys and attaches only safe job/tool/correlation context.
15. **Metrics.** Vendor-neutral sink/log events cover required job, queue, retry/stall, tool duration, storage bytes/failures, OCR, AI tokens/latency/cost, credits, cleanup and cost-model dimensions. User IDs are removed from metric labels.
16. **Health/readiness.** Liveness is process-only. Readiness performs lightweight Redis PING + DB SELECT 1, returns 503 on failure and exposes no endpoints/credentials. The same check is reusable by workers.
17. **Production sizing.** Development, MVP Production and Growth Threshold profiles are documented in `production-readiness.md`; no Kubernetes or provider-specific compute was introduced.
18. **Engineering SLOs.** Provisional availability/success, queue P95, processing-class P95, stuck threshold and 24-hour cleanup targets are documented and explicitly not an SLA.
19. **Alerts.** Low-cardinality, environment-configurable thresholds cover job/AI/storage failures, queue depth, stuck jobs, readiness, cleanup, temp disk and optional cost.
20. **Cost model.** Configurable CPU-ms, memory MB-ms, storage bytes/operations, AI tokens, OCR pages and Office duration produce components, total and cost per successful job without invented cloud prices.
21. **Production security controls.** Non-root, CPU/RAM/PID/disk quotas, read-only root, isolated temp, secret manager, encryption and restore testing are deployment requirements—not claimed Node controls.
22. **Network egress.** Deterministic workers only DB/Redis/S3; AI additionally approved Gemini. Container/firewall enforcement is required.
23. **Malware scanning.** Recommended before anonymous/public Office uploads, positioned validation → scan → storage/job. Scanner choice is a Product/Security gate; scanning is not claimed active.
24. **Backup/restore.** Neon restore window/snapshot plus quarterly isolated restore drill and object/checksum reconciliation are documented; exact plan capability must be confirmed before launch.
25. **License registry.** Final registry includes version, relationship, source, SaaS obligations and gate for direct/native/subprocess/provider components.
26. **Security regression.** Local unit/security suite passes; RLS and infrastructure-backed cases are mandatory in CI. Path sanitization, magic/MIME, pixels, timeouts, output validation, AI isolation and credit idempotency remain covered.
27. **Dependency security.** `npm audit`: 0 findings across 940 dependencies. No force fix or major upgrade.
28. **Test results.** Local: 69 total, 60 passed, 0 failed, 9 skipped because this host lacks Redis/Postgres/S3/Office/OCR. Heavy tests are required—not optional—in CI.
29. **CI results.** Workflow definition now contains required `Integration / Processing`; it has not run for these uncommitted changes because this environment has no Docker or GitHub CLI and no push was authorized. Therefore CI green is not claimed.
30. **Official MVP scope.** Confirmed: 18 tools, including Excel→PDF and PowerPoint→PDF.
31. **SEO status.** Confirmed: 36 localized tool pages; regression passes locally.
32. **BLOCKERS.** (1) CI integration evidence is not yet available. (2) OCR production launch requires Product Owner selection among A commercial Ghostscript, B frozen Ghostscript-free path, C replacement engine, or D temporary launch disablement.
33. **Decision gates.** Approve OCR Option B (recommended) or another option; configure Sentry account/DSN and monitoring sink; set `RETENTION_APPLY=1` only after reviewing dry-run; choose malware scanner before public Office uploads; confirm backup plan/restore window.
34. **Remaining Phase 6 work.** Run the committed CI workflow and resolve its findings; record Product Owner OCR decision. These are the only gates to Completion.
35. **Baseline conflicts.** None. No Phase 7 workflow, Agent, Public API, new tool, microservice or Kubernetes work was added.

