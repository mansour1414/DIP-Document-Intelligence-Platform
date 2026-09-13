# Phase 8 — Document Agent

Phase 8A established deterministic control contracts. The Phase 8 runtime adds a durable first-party Agent that plans through the AI Gateway and executes only through Phase 7 workflows.

## Canonical pipeline

Natural-language request → non-executable structured plan → Tool Registry validation → explicit authorized File scope → permission and entitlement checks → budget preview/check → server-policy approval → frozen plan → Workflow Engine → ordinary Jobs and Workers → verified artifacts → audit evidence → final result.

Only the contracts through frozen plan, verification/evidence shapes, and Agent audit events are implemented in Phase 8A. Workflow execution remains a later Phase 8 slice.

## Trust boundary

Natural-language request text, document text, and future planner output are untrusted data. They cannot establish identity, tenant, roles, entitlements, credits, budgets, approval, tools, storage locations, or execution capability. Trusted server context supplies the authenticated user ID, correlation ID, default-deny tool allowlist, server-derived entitlements, budget, and policy versions.

`AgentRequest` contains request text, `ar | en` locale, and named inputs containing explicit File UUIDs. Scope resolution queries those IDs through the existing tenant transaction boundary and verifies the `File → Document.userId` ownership relationship. Object keys are never authorization inputs. A plan can bind only to a declared request input or an explicitly declared dependency step output.

## Plan contracts

- `AgentPlanDraft` is a strict, non-executable proposal. Unknown fields and authority/execution-shaped fields are rejected.
- `ValidatedAgentPlan` has passed schema, graph, Tool Registry, scope, default-deny permission, entitlement, hard-limit, MIME-transition, and budget checks. It records the server-policy approval decision.
- `FrozenAgentPlan` can be created only from a validated plan that is within budget and either needs no approval or has trusted approval. Its semantic contents are deeply frozen and protected by a deterministic SHA-256 hash of canonical JSON.

A frozen plan is never changed in place. Any change to steps, tools, bindings, options, scope, or user instruction requires a new plan version and a complete repeat of validation, authorization, budget, approval, and freezing.

## Tool, budget, and approval policy

The existing Tool Registry is the only tool source of truth. Registration and exact version, trusted allowlist membership, server-derived entitlements, supported locale, applicable size/page/file limits, output indexes, and known MIME transitions are checked deterministically. Registered AI tools remain ordinary governed tools; the Agent receives no provider capability.

`AgentBudget` is trusted server policy and has no production defaults in this phase. It carries maximum steps, input tokens, output tokens, credits, and execution time. Phase 8A enforces maximum steps and existing deterministic credit costs. Execution duration and provider cost are reported as unknown rather than zero because the repository has no authoritative pre-execution estimator for them.

Approval states are `NOT_REQUIRED`, `REQUIRED`, `APPROVED`, and `REJECTED`. A trusted policy chooses whole-plan or step approval requirements. Only a trusted decision can approve or reject; required or rejected plans cannot freeze.

## Verification, evidence, and audit

Verification contracts distinguish expected and actual outputs, artifact/schema/MIME status, structured failures, and failed step/file references. Execution evidence reuses future WorkflowRun, Job, JobStep, ToolExecution, output File, correlation, plan/version, and frozen-hash identifiers; it has no storage-key or credential fields.

Agent audit events use the existing structured logger and carry only decision metadata such as user, correlation, plan/version, step/tool, result code, approval state, budget result, and frozen hash. Request/document contents and secrets are not part of the Agent audit contract.

## Phase 8 runtime

`AgentRun` owns the authenticated request, explicit scope, trusted budget and allowlist snapshots, lifecycle, WorkflowRun link, verification, and final evidence. Immutable `AgentPlanVersion` rows retain the draft, resolved scope, preview, approval, frozen plan/hash, and internal WorkflowVersion link. Both tables have forced, fail-closed tenant RLS.

Planning uses the existing AI Gateway. The planner sees only safe file metadata and the allowed intersection of Tool Registry, entitlements, worker availability, and locale. Its JSON passes strict Phase 8A parsing and deterministic validation before freezing.

Planner accounting uses `AiUsage.agentRunId`; ordinary Job AI accounting continues to use `jobId`. Both paths retain advisory-lock idempotency.

The compiler maps a verified `FrozenAgentPlan` to a Phase 7 `WorkflowDefinition`. `AGENT_INTERNAL` workflows are excluded from Saved Workflows. `startWorkflowRun` remains the only execution handoff, so ordinary authorization, credits, Jobs, BullMQ, Workers, storage, output validation, retry, and cancellation apply.

Authenticated routes create, read, approve/reject, and cancel Agent runs under `/api/agent-runs`. The localized `/{locale}/agent` page supports explicit files, English and Arabic RTL requests, safe plan display, approval, progress, cancellation, verification, and artifact downloads.

Phase 8 excludes autonomous memory or open-ended replanning, arbitrary code/shell/network tools, direct provider/Worker/processor calls, external connectors, a second execution engine, public developer APIs, and Phase 9 functionality. Real-provider staging validation and final production policy values remain Production Readiness work.

## Validation

`test/agent.phase8a.test.ts` covers the deterministic security boundary. `test/agent.phase8.test.ts` covers planner restriction, compilation, migration/RLS, authenticated routes, RTL UI, and the execution boundary. The environment-gated lower-stack test in `test/workflow.execution.e2e.test.ts` uses the Fake planner plus real Postgres/RLS, object storage, Workflow/Jobs, BullMQ, and Workers for Agent success, idempotency, cancellation, failure, evidence, and cross-tenant behavior.

Production Readiness still requires applying the reviewed migration through the established deployment process, setting the final approval-policy configuration, and running the gated lower-stack suite plus a real-provider planner smoke test in an isolated staging branch. Production is not an implementation or test target.
