# Phase 8 — Document Agent

Phase 8 is current and is not closed. Phase 8A establishes deterministic control contracts only; it does not make the Agent executable.

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

## Deliberately not implemented in Phase 8A

No LLM or provider call, AI planner, API/UI, persistence or migration, WorkflowRun or Job creation, queue/Worker/processor call, execution, autonomous retry/replanning loop, shell/code/network capability, storage access, or public developer API is added.
